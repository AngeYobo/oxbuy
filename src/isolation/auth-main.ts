// SPDX-License-Identifier: MIT
/**
 * Authorization service: PDP + controlled signer, as its own OS identity.
 *
 * Holds the Ed25519 authorization signing key and the durable policy state.
 * Holds no payment credential and cannot reach the executor.
 *
 * It exposes exactly one operation to the gateway, and no generic signing endpoint:
 *   POST /v1/authorize   body: a PurchaseRequest (exact key set), nothing else
 *
 * The service validates the request itself, loads policy state from its own
 * protected store, runs the published PolicyEngine (fail-closed allowlists,
 * per-action cap, budget, velocity, nonce replay, ...), commits the next
 * state together with a reservation for the authorization, and only then
 * builds and signs the AuthorizationV1 itself. Nothing the caller sends ends
 * up in the authorization except through the validated request, which is
 * bound into the intent hash. Identity fields (agent_id, nonce, intent_id,
 * timestamp, issuer, audience, expiry) come from this service, never from the
 * caller.
 *
 * Phase 2C/2D: a second socket serves only the executor (settle channel,
 * src/isolation/settle-channel.ts); every request carries a peer-identity proof
 * and a message signed with the executor's key:
 *   POST /v1/claim    execution claim, committed before it is acknowledged (Phase 2D)
 *   POST /v1/void     synchronous VOID of a rejected authorization or abandoned claim (Phase 2D)
 *   POST /v1/settle   outcome report for a claim
 * Expired, unclaimed reservations are released by this service on its own
 * clock, every `expiryReleaseIntervalMs`.
 *
 * Policy state is persistent and operator-initialized
 * (src/isolation/policy-state-admin.ts). At startup the service computes its
 * own policy binding (issuer, policy_id, policy_version, agent_id) from its
 * own engine configuration, takes the exclusive writer lock itself on its own
 * descriptor (exit 75 if another process holds it, 66 if it cannot be
 * opened), and opens the existing state for exactly that binding. Missing,
 * unreadable, corrupt, foreign, old-format, or rolled-back state, or an
 * anchor that is missing or not append-only, makes it refuse to start
 * (exit 78): it never recreates a budget.
 *
 *   node auth-main.ts <auth-config.json>
 */
import { closeSync, fchmodSync, fsyncSync, openSync, writeSync } from "node:fs";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore, type PolicyStateStore } from "../authorization/policy-state.ts";
import { openFilePolicyStateStore, type PolicyBinding } from "../authorization/policy-state-file.ts";
import { acquireExclusiveLock, LockError, type ExclusiveLock } from "../durable/exclusive-lock.ts";
import { domainId } from "../executor/execution-domain.ts";
import { emit, readConfig, type AuthConfig } from "./config.ts";
import { serveJson } from "./ipc.ts";
import { verifyPeerProof } from "./settle-channel.ts";

const config = readConfig<AuthConfig>(process.argv[2]);
process.umask(0o077);
const { pdp } = config;

const serviceOptions = {
  policyVersion: pdp.policyVersion,
  issuer: pdp.issuer,
  audience: pdp.audience,
  agentId: pdp.agentId,
  ttlSeconds: pdp.ttlSeconds,
  now: () => Math.floor(Date.now() / 1000),
  signingKey: { privateKeyPem: pdp.privateKeyPem, kid: pdp.kid },
  executorReportKey: config.executorReportKey,
  executionDomain: config.executionDomain,
  minRemainingSeconds: config.minRemainingSeconds,
};
// The binding comes from this service's own engine, not from any input.
const authority = createAuthorizationService({ ...serviceOptions, stateStore: createInMemoryPolicyStateStore(undefined) }).trustMaterial.authority;
const binding: PolicyBinding = { issuer: authority.issuer, policyId: authority.policyId, policyVersion: pdp.policyVersion, agentId: pdp.agentId };
// CX2: the authorization audience must name the configured execution domain.
if (!pdp.audience.endsWith(`#exec-domain=${domainId(config.executionDomain)}`)) {
  process.stderr.write(`${JSON.stringify({ event: "refused", role: "auth", reason: "EXECUTION_DOMAIN_MISMATCH:audience" })}\n`);
  process.exit(78);
}

function refuse(code: number, reason: string): never {
  process.stderr.write(`${JSON.stringify({ event: "refused", role: "auth", reason })}\n`);
  process.exit(code);
}

let lock: ExclusiveLock;
try {
  lock = acquireExclusiveLock(config.lockPath, { create: true });
} catch (err) {
  if (err instanceof LockError && err.code === "LOCK_HELD") refuse(75, `POLICY_STATE_LOCKED:${err.message}`);
  refuse(66, `POLICY_STATE_LOCK_UNAVAILABLE:${(err as Error).message}`);
}

let store: PolicyStateStore;
try {
  store = openFilePolicyStateStore(config.stateDir, {
    binding,
    lock,
    anchorPath: config.anchorPath,
    faults: {
      crashAfterPrepare: config.faults?.crashAfterPrepare,
      crashAfterRename: config.faults?.crashAfterRename,
      crashAfterDirSync: config.faults?.crashAfterDirSync,
      failDoneAppend: config.faults?.failDoneAppend,
      failPrepare: config.faults?.failPrepare,
    },
  });
} catch (err) {
  refuse(78, (err as Error).message);
}

const stateStore = config.faults?.crashBeforeIssue
  ? {
      load: () => store.load(),
      async commit(...args: Parameters<typeof store.commit>) {
        const ok = await store.commit(...args);
        if (ok) process.kill(process.pid, "SIGKILL"); // decision committed, authorization never issued
        return ok;
      },
    }
  : store;

const service = createAuthorizationService({ ...serviceOptions, stateStore });

/** Audit record: decision metadata only, never key material. */
function audit(entry: Record<string, unknown>): void {
  const fd = openSync(config.decisionLogPath, "a", 0o600);
  try {
    fchmodSync(fd, 0o600);
    writeSync(fd, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

const server = await serveJson(config.socketPath, 0o660, {
  "/v1/authorize": async (body) => {
    const decision = await service.authorize(body);
    const req = (typeof body === "object" && body !== null ? body : {}) as Partial<PurchaseRequest>;
    audit({
      decision: decision.decision,
      ...(decision.decision === "ALLOW"
        ? { auth_id: decision.authorization.auth_id, intent_hash: decision.authorization.intent_hash, expiry: decision.authorization.expiry }
        : { reasons: decision.reasons }),
      request: { service_id: req.service_id, url: req.url, recipient: req.recipient, network: req.network, asset: req.asset, max_amount: req.max_amount },
    });
    return { status: 200, body: decision };
  },
});

/** Settle-channel envelope: {body, proof}; refused unless the kernel attests the executor sent it. */
function peerChecked(envelope: unknown): { ok: true; body: Record<string, unknown> } | { ok: false; reason: string } {
  const e = (typeof envelope === "object" && envelope !== null ? envelope : {}) as { body?: unknown; proof?: unknown };
  try {
    verifyPeerProof(config.proofDir, config.executorUid, e.proof, e.body);
  } catch (err) {
    return { ok: false, reason: (err as Error).message };
  }
  return typeof e.body === "object" && e.body !== null ? { ok: true, body: e.body as Record<string, unknown> } : { ok: false, reason: "SETTLE_INVALID_BODY" };
}

const settleServer = await serveJson(config.settleSocketPath, 0o660, {
  "/v1/settle": async (envelope) => {
    const c = peerChecked(envelope);
    if (!c.ok) {
      audit({ event: "settle_refused", reason: c.reason });
      return { status: 403, body: { status: "REJECTED", reason: c.reason } };
    }
    const result = await service.settle(c.body.report);
    audit({
      event: "settle",
      status: result.status,
      ...(result.status === "REJECTED"
        ? { reason: result.reason }
        : { auth_id: result.reservation.auth_id, state: result.reservation.state, released: result.released }),
    });
    if (result.status === "APPLIED" && config.faults?.crashAfterSettleCommit) process.kill(process.pid, "SIGKILL");
    return { status: 200, body: result };
  },
  "/v1/claim": async (envelope) => {
    const c = peerChecked(envelope);
    if (!c.ok) {
      audit({ event: "claim_refused", reason: c.reason });
      return { status: 403, body: { status: "REJECTED", reason: c.reason } };
    }
    const result = await service.claim(c.body.claim);
    audit({ event: "claim", ...result });
    if (result.status === "CLAIMED" && config.faults?.crashAfterClaimCommit) process.kill(process.pid, "SIGKILL");
    return { status: 200, body: result };
  },
  "/v1/void": async (envelope) => {
    const c = peerChecked(envelope);
    if (!c.ok) {
      audit({ event: "void_refused", reason: c.reason });
      return { status: 403, body: { status: "REJECTED", reason: c.reason } };
    }
    const result = await service.voidAuthorization(c.body.void);
    audit({ event: "void", ...result });
    if (result.status === "APPLIED" && config.faults?.crashAfterVoidCommit) process.kill(process.pid, "SIGKILL");
    return { status: 200, body: result };
  },
});

// Expired, unclaimed reservations: released on this service's own clock (no claim can be granted for them).
let releasing = false;
const expiryTimer = setInterval(() => {
  if (releasing) return;
  releasing = true;
  service
    .releaseExpired()
    .then((n) => {
      if (n > 0) audit({ event: "expired_released", count: n });
    })
    .catch((err) => audit({ event: "expired_release_error", error: (err as Error).message }))
    .finally(() => (releasing = false));
}, config.expiryReleaseIntervalMs);

emit({ event: "ready", role: "auth", pid: process.pid });

function shutdown() {
  // The writer lock is released by the kernel when this process exits.
  clearInterval(expiryTimer);
  settleServer.close();
  server.close(() => process.exit(0));
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

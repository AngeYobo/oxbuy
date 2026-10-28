// SPDX-License-Identifier: MIT
/**
 * Authorization service: PDP + controlled signer, as its own OS identity.
 *
 * Holds the Ed25519 authorization signing key and the durable policy state.
 * Holds no payment credential and cannot reach the executor.
 *
 * It exposes exactly one operation, and no generic signing endpoint:
 *   POST /v1/authorize   body: a PurchaseRequest (exact key set), nothing else
 *
 * The service validates the request itself, loads policy state from its own
 * protected store, runs the published PolicyEngine (fail-closed allowlists,
 * per-action cap, budget, velocity, nonce replay, ...), commits the next
 * state, and only then builds and signs the AuthorizationV1 itself. Nothing
 * the caller sends ends up in the authorization except through the
 * validated request, which is bound into the intent hash. Identity fields
 * (agent_id, nonce, intent_id, timestamp, issuer, audience, expiry) come
 * from this service, never from the caller.
 *
 * Policy state is persistent and operator-initialized
 * (src/isolation/policy-state-admin.ts). At startup the service computes its
 * own policy binding (issuer, policy_id, policy_version, agent_id) from its
 * own engine configuration and opens the existing state for exactly that
 * binding, under a kernel writer lock it must already hold (it is started
 * as `flock --nonblock <lockPath> node auth-main.ts ...`). Missing, unreadable,
 * corrupt, or foreign state, or a missing lock, makes it refuse to start
 * (exit 78): it never recreates a budget. The lock self-check does not prove
 * that this process owns the lock (see `assertWriterLockHeld`, N1): a single
 * writer is guaranteed only when started through the launcher's flock.
 *
 *   node auth-main.ts <auth-config.json>
 */
import { closeSync, fchmodSync, fsyncSync, openSync, writeSync } from "node:fs";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore, type PolicyStateStore } from "../authorization/policy-state.ts";
import { openFilePolicyStateStore, type PolicyBinding } from "../authorization/policy-state-file.ts";
import { emit, readConfig, type AuthConfig } from "./config.ts";
import { serveJson } from "./ipc.ts";

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
};
// The binding comes from this service's own engine, not from any input.
const authority = createAuthorizationService({ ...serviceOptions, stateStore: createInMemoryPolicyStateStore(undefined) }).trustMaterial.authority;
const binding: PolicyBinding = { issuer: authority.issuer, policyId: authority.policyId, policyVersion: pdp.policyVersion, agentId: pdp.agentId };

let store: PolicyStateStore;
try {
  store = openFilePolicyStateStore(config.stateDir, { binding, lockPath: config.lockPath });
} catch (err) {
  process.stderr.write(`${JSON.stringify({ event: "refused", role: "auth", reason: (err as Error).message })}\n`);
  process.exit(78);
}

const stateStore = config.faults?.crashBeforeIssue
  ? {
      load: () => store.load(),
      async commit(next: Parameters<typeof store.commit>[0], v: number) {
        const ok = await store.commit(next, v);
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

emit({ event: "ready", role: "auth", pid: process.pid });

function shutdown() {
  // The writer lock is released by the kernel when this process exits.
  server.close(() => process.exit(0));
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

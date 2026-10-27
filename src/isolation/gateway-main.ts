// SPDX-License-Identifier: MIT
/**
 * Process B: OxDeAI authorization gateway (PDP + PEP).
 *
 * Runs as the gateway's OS identity. Serves the agent on a public
 * Unix-domain socket and is the only client of the executor's private
 * socket. Holds the PDP signing key and the internal executor token.
 *
 *   node gateway-main.ts <gateway-config.json>
 *
 * Public routes (all POST, JSON):
 *   /v1/quote      read-only 402 quote (forwarded to the executor)
 *   /v1/authorize  PDP decision
 *   /v1/purchase   PEP: verify, consume, forward to the executor
 */
import { createInMemoryReplayStore, INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import type { PurchaseResult } from "../agent/agent.ts";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../authorization/policy-state.ts";
import { createPaymentGateway } from "../gateway/gateway.ts";
import { initialPolicyState } from "../system.ts";
import { emit, readConfig, type GatewayConfig } from "./config.ts";
import { postJson, serveJson } from "./ipc.ts";

const config = readConfig<GatewayConfig>(process.argv[2]);
process.umask(0o077);
const now = () => Math.floor(Date.now() / 1000);
const { pdp } = config;

const state = initialPolicyState();
if (pdp.budget !== undefined) state.budget.budget_limit[pdp.agentId] = BigInt(pdp.budget);

const authService = createAuthorizationService({
  policyVersion: pdp.policyVersion,
  issuer: pdp.issuer,
  audience: pdp.audience,
  agentId: pdp.agentId,
  ttlSeconds: pdp.ttlSeconds,
  stateStore: createInMemoryPolicyStateStore(state),
  now,
  signingKey: { privateKeyPem: pdp.privateKeyPem, kid: pdp.kid },
});

const gateway = createPaymentGateway({
  expectedAudience: pdp.audience,
  trustedKeySets: [authService.trustMaterial.keySet],
  trustedAuthorizationAuthorities: [authService.trustMaterial.authority],
  internalToken: config.internalToken,
  // The IPC client's own timeout is a backstop; the guard's timeoutMs decides.
  executor: { handle: (body, headers) => postJson(config.executorSocketPath, "/v1/execute", body, headers, config.timeoutMs + 5_000) },
  replayStore: createInMemoryReplayStore(),
  now,
  timeoutMs: config.timeoutMs,
});

const server = await serveJson(config.publicSocketPath, 0o666, {
  "/v1/quote": async (body) => {
    try {
      const res = await postJson(config.executorSocketPath, "/v1/quote", body, {
        [INTERNAL_EXECUTOR_TOKEN_HEADER]: config.internalToken,
      });
      return res.status === 200 ? res : { status: 400, body: { error: "QUOTE_FAILED" } };
    } catch {
      return { status: 502, body: { error: "QUOTE_UNAVAILABLE" } };
    }
  },
  "/v1/authorize": async (body) => ({ status: 200, body: await authService.authorize(body) }),
  "/v1/purchase": async (body) => {
    // Same envelope as the in-process client: { request, intent_ref, authorization }.
    const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
    const r = await gateway.submit({ action: { request: b.request, intent_ref: b.intent_ref }, authorization: b.authorization });
    const result: PurchaseResult = {
      decision: r.body.decision,
      executed: r.body.executed,
      status: r.status,
      reason: r.body.reason,
      detail: r.body.detail,
      receipt: r.body.receipt,
      auth_id: r.body.auth_id,
      intent_hash: r.body.intent_hash,
    };
    return { status: r.status, body: result };
  },
});

emit({ event: "ready", role: "gateway", pid: process.pid });

function shutdown() {
  server.close(() => process.exit(0));
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

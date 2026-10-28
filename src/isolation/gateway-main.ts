// SPDX-License-Identifier: MIT
/**
 * Gateway (PEP), as its own OS identity.
 *
 * Serves the agent on the public socket. Holds no authorization signing key,
 * no policy state, and no payment credential: only the PDP's public
 * verification material and the executor token (defence in depth; the
 * executor verifies every authorization itself).
 *
 *   node gateway-main.ts <gateway-config.json>
 *
 * Public routes (all POST, JSON):
 *   /v1/quote      read-only 402 quote, forwarded to the executor
 *   /v1/authorize  schema-checked, forwarded to the authorization service;
 *                  fails closed (DENY) if it is unavailable. There is no
 *                  local fallback that could construct an authorization.
 *   /v1/purchase   PEP: verify, consume, forward to the executor
 */
import { createInMemoryReplayStore, INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import type { AuthorizeResult, PurchaseResult } from "../agent/agent.ts";
import { validatePurchaseRequest } from "../authorization/intent.ts";
import { createPaymentGateway } from "../gateway/gateway.ts";
import { emit, readConfig, type GatewayConfig } from "./config.ts";
import { postJson, serveJson } from "./ipc.ts";

const config = readConfig<GatewayConfig>(process.argv[2]);
process.umask(0o077);
const now = () => Math.floor(Date.now() / 1000);

const gateway = createPaymentGateway({
  expectedAudience: config.trust.audience,
  trustedKeySets: [config.trust.keySet],
  trustedAuthorizationAuthorities: [config.trust.authority],
  internalToken: config.internalToken,
  // The IPC client's own timeout is a backstop; the guard's timeoutMs decides.
  executor: { handle: (body, headers) => postJson(config.executorSocketPath, "/v1/execute", body, headers, config.timeoutMs + 5_000) },
  replayStore: createInMemoryReplayStore(),
  now,
  timeoutMs: config.timeoutMs,
});

const deny = (reason: string): { status: number; body: AuthorizeResult } => ({ status: 200, body: { decision: "DENY", reasons: [reason] } });

const server = await serveJson(config.publicSocketPath, 0o660, {
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
  "/v1/authorize": async (body) => {
    try {
      validatePurchaseRequest(body);
    } catch (err) {
      return deny(`REQUEST_INVALID:${(err as Error).message}`);
    }
    try {
      const res = await postJson(config.authSocketPath, "/v1/authorize", body, {}, config.timeoutMs);
      const d = res.body as AuthorizeResult | undefined;
      if (res.status !== 200 || (d?.decision !== "ALLOW" && d?.decision !== "DENY")) return deny("PDP_UNAVAILABLE");
      return { status: 200, body: d };
    } catch {
      return deny("PDP_UNAVAILABLE");
    }
  },
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

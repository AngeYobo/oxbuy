// SPDX-License-Identifier: MIT
/**
 * Payment gateway (PEP).
 *
 * Thin wrapper over the published `createPepGatewayExecutor` from
 * @oxdeai/guard, which performs, in order and fail-closed:
 *   1. strict `verifyAuthorization` (Ed25519 signature against trusted
 *      KeySets, audience, expiry, issued_at plausibility, and the
 *      (issuer, policy_id) authority pair),
 *   2. `intent_hash` binding against `hashAction(action)`,
 *   3. atomic replay consumption of `auth_id`,
 *   4. the upstream (executor) call with the internal executor token.
 *
 * This file adds only what the published gateway leaves to the integrator:
 *   - `hashAction`: recompute the OxDeAI intent hash from the exact payment
 *     request (src/authorization/intent.ts);
 *   - a JSON round-trip + deep freeze of the input, so the object that is
 *     hashed is the object that is executed, and the caller cannot mutate it
 *     while the gateway awaits the replay store;
 *   - an outcome boundary on the guard's result (`classify`).
 *
 * Outcome boundary: the guard reports every upstream error or timeout as
 * `decision: "DENY", executed: false`, even after the executor may have
 * invoked `pay`. `classify` keeps the guard's result unchanged when the
 * upstream was not called, and otherwise reports:
 *   ALLOW          executor attests EXECUTED (verified settled receipt);
 *   DENY           executor attests NOT_EXECUTED (nothing signed);
 *   INDETERMINATE  anything else: timeout, lost connection, executor error,
 *                  ambiguous or mismatched receipt. Never retried here.
 */
import { createPepGatewayExecutor, type PepGatewayResult, type ReplayStore } from "@oxdeai/guard";
import type { AuthorizationAuthority, KeySet } from "@oxdeai/core";
import { hashGatewayAction } from "../authorization/intent.ts";
import type { PaymentExecutor } from "../executor/executor.ts";

export type GatewayOptions = {
  readonly expectedAudience: string;
  readonly trustedKeySets: readonly KeySet[];
  readonly trustedAuthorizationAuthorities: readonly AuthorizationAuthority[];
  readonly internalToken: string;
  readonly executor: Pick<PaymentExecutor, "handle">;
  readonly replayStore: ReplayStore;
  /** Trusted clock, unix seconds. */
  readonly now: () => number;
  /** Upstream timeout. Expiry yields INDETERMINATE, not DENY. */
  readonly timeoutMs: number;
};

export type GatewayDecision = "ALLOW" | "DENY" | "INDETERMINATE";

export type GatewayResult = {
  readonly status: number;
  readonly upstreamCalled: boolean;
  readonly body: {
    readonly ok: boolean;
    readonly decision: GatewayDecision;
    /** "unknown" only with INDETERMINATE. */
    readonly executed: boolean | "unknown";
    readonly reason?: string;
    readonly detail?: string;
    readonly auth_id?: string;
    readonly intent_hash?: string;
    readonly receipt?: unknown;
  };
};

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Detached, immutable, JSON-only copy. Throws on non-JSON input. */
function snapshot(input: unknown): unknown {
  return deepFreeze(JSON.parse(JSON.stringify(input)));
}

type ExecutorBody = { outcome?: unknown; error?: unknown; receipt?: unknown };

function classify(r: PepGatewayResult, detached: unknown): GatewayResult {
  if (!r.upstreamCalled) {
    return { status: r.status, upstreamCalled: false, body: { ok: false, decision: "DENY", executed: false, reason: r.body.reason } };
  }
  // The upstream was called, so hashing and verification already succeeded.
  const { action, authorization } = detached as { action: unknown; authorization: { auth_id: string } };
  const ids = { auth_id: authorization.auth_id, intent_hash: hashGatewayAction(action) };
  const upstream = (r.status === 200 ? r.body.upstream_result : r.body.upstream_error) as ExecutorBody | undefined;
  const outcome = typeof upstream === "object" && upstream !== null ? upstream.outcome : undefined;
  const error = typeof upstream === "object" && upstream !== null ? upstream.error : upstream;

  if (r.status === 200 && outcome === "EXECUTED") {
    return {
      status: 200,
      upstreamCalled: true,
      body: { ok: true, decision: "ALLOW", executed: true, ...ids, receipt: upstream?.receipt },
    };
  }
  if (r.status !== 200 && outcome === "NOT_EXECUTED") {
    return {
      status: r.status,
      upstreamCalled: true,
      body: { ok: false, decision: "DENY", executed: false, reason: r.body.reason, detail: String(error), ...ids },
    };
  }
  return {
    status: r.status === 200 ? 502 : r.status,
    upstreamCalled: true,
    body: {
      ok: false,
      decision: "INDETERMINATE",
      executed: "unknown",
      reason: "PAYMENT_UNKNOWN",
      detail: error === undefined ? r.body.reason : String(error),
      ...ids,
      ...(upstream?.receipt !== undefined ? { receipt: upstream.receipt } : {}),
    },
  };
}

export function createPaymentGateway(options: GatewayOptions) {
  const pep = createPepGatewayExecutor({
    expectedAudience: options.expectedAudience,
    trustedKeySets: options.trustedKeySets,
    trustedAuthorizationAuthorities: options.trustedAuthorizationAuthorities,
    internalExecutorToken: options.internalToken,
    replayStore: options.replayStore,
    now: options.now,
    timeoutMs: options.timeoutMs,
    hashAction: hashGatewayAction,
    executeUpstream: async (action, headers) => {
      const res = await options.executor.handle(action, headers);
      return { status: res.status, body: res.body };
    },
  });

  return {
    async submit(input: unknown): Promise<GatewayResult> {
      let detached: unknown;
      try {
        detached = snapshot(input);
      } catch {
        return {
          status: 403,
          upstreamCalled: false,
          body: { ok: false, decision: "DENY", executed: false, reason: "INVALID_REQUEST" },
        };
      }
      return classify(await pep(detached), detached);
    },
  };
}

export type PaymentGateway = ReturnType<typeof createPaymentGateway>;

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
 *     while the gateway awaits the replay store.
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
  readonly executor: PaymentExecutor;
  readonly replayStore: ReplayStore;
  /** Trusted clock, unix seconds. */
  readonly now: () => number;
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

export function createPaymentGateway(options: GatewayOptions) {
  const pep = createPepGatewayExecutor({
    expectedAudience: options.expectedAudience,
    trustedKeySets: options.trustedKeySets,
    trustedAuthorizationAuthorities: options.trustedAuthorizationAuthorities,
    internalExecutorToken: options.internalToken,
    replayStore: options.replayStore,
    now: options.now,
    hashAction: hashGatewayAction,
    executeUpstream: async (action, headers) => {
      const res = await options.executor.handle(action, headers);
      return { status: res.status, body: res.body };
    },
  });

  return {
    async submit(input: unknown): Promise<PepGatewayResult> {
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
      return pep(detached);
    },
  };
}

export type PaymentGateway = ReturnType<typeof createPaymentGateway>;

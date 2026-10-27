// SPDX-License-Identifier: MIT
/**
 * Authorization service (PDP side).
 *
 * Wraps the published `@oxdeai/core` PolicyEngine. Holds the Ed25519
 * authorization signing key; neither the agent nor the gateway ever sees it.
 * The gateway receives only the public KeySet (see `trustMaterial`).
 *
 * Fail-closed: invalid request, unavailable/missing policy state, policy
 * state with a missing or empty required allowlist, an engine error, or a
 * state CAS conflict all return DENY and issue no authorization.
 */
import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import {
  PolicyEngine,
  RECOMMENDED_TRUSTED_TIME_PROFILE,
  toPublicAuthorizationV1,
  type AuthorizationAuthority,
  type AuthorizationV1,
  type KeySet,
} from "@oxdeai/core";
import type { IntentRef, PurchaseRequest } from "../agent/purchase-request.ts";
import { buildPaymentIntent, validatePurchaseRequest } from "./intent.ts";
import { assertRequiredAllowlists, type PolicyStateStore } from "./policy-state.ts";

export type AuthorizationDecision =
  | { readonly decision: "ALLOW"; readonly authorization: AuthorizationV1; readonly intent_ref: IntentRef }
  | { readonly decision: "DENY"; readonly reasons: readonly string[] };

export type AuthorizationServiceOptions = {
  readonly policyVersion: string;
  readonly issuer: string;
  /** Must equal the gateway's expectedAudience. */
  readonly audience: string;
  /**
   * Agent identity, fixed by the deployment. Not taken from the request: in
   * Phase 1 there is one agent and it is not authenticated (see ARCHITECTURE.md).
   */
  readonly agentId: string;
  readonly ttlSeconds: number;
  readonly stateStore: PolicyStateStore;
  /** Trusted clock, unix seconds. */
  readonly now: () => number;
};

export function createAuthorizationService(options: AuthorizationServiceOptions) {
  // Ephemeral per-process key. This is an authorization-signing key, not a
  // wallet: it cannot move funds.
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const kid = `pdp-${randomBytes(4).toString("hex")}`;

  const engine = new PolicyEngine({
    policy_version: options.policyVersion,
    engine_secret: randomBytes(32).toString("hex"),
    authorization_ttl_seconds: options.ttlSeconds,
    authorization_signing_alg: "Ed25519",
    authorization_private_key_pem: privateKeyPem,
    authorization_issuer: options.issuer,
    authorization_audience: options.audience,
    authorization_signing_kid: kid,
    strictDeterminism: true,
    ...RECOMMENDED_TRUSTED_TIME_PROFILE,
  });

  const keySet: KeySet = {
    issuer: options.issuer,
    version: "1",
    keys: [
      {
        kid,
        alg: "Ed25519",
        public_key: createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString(),
      },
    ],
  };
  const authority: AuthorizationAuthority = { issuer: options.issuer, policyId: engine.computePolicyId() };

  async function authorize(input: unknown): Promise<AuthorizationDecision> {
    let request: PurchaseRequest;
    try {
      request = validatePurchaseRequest(input);
    } catch (err) {
      return { decision: "DENY", reasons: [`REQUEST_INVALID:${(err as Error).message}`] };
    }

    let loaded;
    try {
      loaded = await options.stateStore.load();
    } catch (err) {
      return { decision: "DENY", reasons: [`POLICY_STATE_UNAVAILABLE:${(err as Error).message}`] };
    }
    try {
      assertRequiredAllowlists(loaded.state);
    } catch (err) {
      return { decision: "DENY", reasons: [`POLICY_STATE_INVALID:${(err as Error).message}`] };
    }

    const evaluationTime = options.now();
    const intent_ref: IntentRef = {
      intent_id: `intent-${randomBytes(12).toString("hex")}`,
      agent_id: options.agentId,
      nonce: BigInt(`0x${randomBytes(8).toString("hex")}`).toString(),
      timestamp: evaluationTime,
    };

    let result;
    try {
      result = engine.evaluatePure(buildPaymentIntent(request, intent_ref), loaded.state, evaluationTime);
    } catch (err) {
      return { decision: "DENY", reasons: [`ENGINE_ERROR:${(err as Error).message}`] };
    }
    if (result.decision !== "ALLOW") return { decision: "DENY", reasons: result.reasons };

    // Commit budget/velocity/nonce state before releasing the authorization,
    // so a concurrent request cannot spend the same budget.
    let committed: boolean;
    try {
      committed = await options.stateStore.commit(result.nextState, loaded.version);
    } catch (err) {
      return { decision: "DENY", reasons: [`POLICY_STATE_UNAVAILABLE:${(err as Error).message}`] };
    }
    if (!committed) return { decision: "DENY", reasons: ["POLICY_STATE_CONFLICT"] };

    return { decision: "ALLOW", authorization: toPublicAuthorizationV1(result.authorization), intent_ref };
  }

  return {
    authorize,
    /** Public verification material for the gateway. Contains no secrets. */
    trustMaterial: Object.freeze({ keySet, authority, audience: options.audience }),
  };
}

export type AuthorizationService = ReturnType<typeof createAuthorizationService>;

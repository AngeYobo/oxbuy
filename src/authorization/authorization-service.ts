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
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
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
import { sameDomain, type ExecutionDomain } from "../executor/execution-domain.ts";
import { verifyReport } from "../executor/outcome-report.ts";
import { assertRequiredAllowlists, type PolicyStateStore } from "./policy-state.ts";
import { applyOutcome, newReservation, ReportRejected, type ReservationRecord } from "./reservations.ts";

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
  /**
   * Operator-provisioned Ed25519 signing key. Omitted: an ephemeral key is
   * generated (in-process harness).
   */
  readonly signingKey?: { readonly privateKeyPem: string; readonly kid: string };
  /** Executor outcome-report key (Phase 2C). Without it, `settle` refuses every report. */
  readonly executorReportKey?: { readonly publicKeyPem: string; readonly kid: string };
  /**
   * The execution domain this deployment's executor runs in (Phase 2C; CX2).
   * Every reservation is bound to it; `audience` must already name it
   * (src/executor/execution-domain.ts). Without it, reservations are unbound
   * and never released (in-process harness).
   */
  readonly executionDomain?: ExecutionDomain;
};

export type SettleResult =
  | { readonly status: "APPLIED" | "ALREADY_APPLIED" | "STALE"; readonly reservation: ReservationRecord; readonly released: string }
  | { readonly status: "REJECTED"; readonly reason: string };

export function createAuthorizationService(options: AuthorizationServiceOptions) {
  // An authorization-signing key, not a wallet: it cannot move funds.
  const privateKey = options.signingKey
    ? createPrivateKey(options.signingKey.privateKeyPem)
    : generateKeyPairSync("ed25519").privateKey;
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const kid = options.signingKey?.kid ?? `pdp-${randomBytes(4).toString("hex")}`;

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

    // Commit budget/velocity/nonce state, and the reservation for this
    // authorization, in one atomic write before releasing the authorization,
    // so a concurrent request cannot spend the same budget.
    const auth = result.authorization;
    if (loaded.reservations[auth.auth_id] !== undefined) return { decision: "DENY", reasons: ["RESERVATION_EXISTS"] };
    const reservation = newReservation({
      auth_id: auth.auth_id,
      intent_hash: auth.intent_hash,
      agent_id: options.agentId,
      domain: options.executionDomain ? { journal_id: options.executionDomain.journal_id, executor_uid: options.executionDomain.executor_uid } : null,
      amount: request.max_amount,
      expiry: auth.expiry,
      at: evaluationTime,
    });
    let committed: boolean;
    try {
      committed = await options.stateStore.commit(result.nextState, loaded.version, { ...loaded.reservations, [auth.auth_id]: reservation });
    } catch (err) {
      return { decision: "DENY", reasons: [`POLICY_STATE_UNAVAILABLE:${(err as Error).message}`] };
    }
    if (!committed) return { decision: "DENY", reasons: ["POLICY_STATE_CONFLICT"] };

    return { decision: "ALLOW", authorization: toPublicAuthorizationV1(result.authorization), intent_ref };
  }

  /**
   * Apply one executor outcome report (Phase 2C; F3). The report must carry a
   * valid executor signature; the transition must be allowed by the
   * reservation state machine. A release subtracts the released amount from
   * the agent's budget charge in the same atomic write. Never throws.
   */
  async function settle(signed: unknown): Promise<SettleResult> {
    if (!options.executorReportKey) return { status: "REJECTED", reason: "REPORT_INVALID:no trusted executor key" };
    let facts;
    try {
      facts = verifyReport(signed, options.executorReportKey);
    } catch (err) {
      return { status: "REJECTED", reason: (err as Error).message };
    }
    for (let attempt = 0; attempt < 5; attempt++) {
      let loaded;
      try {
        loaded = await options.stateStore.load();
      } catch (err) {
        return { status: "REJECTED", reason: `POLICY_STATE_UNAVAILABLE:${(err as Error).message}` };
      }
      const rec = loaded.reservations[facts.auth_id];
      if (rec === undefined) return { status: "REJECTED", reason: "REPORT_REJECTED:UNKNOWN_RESERVATION" };
      // CX2: only the reservation's own execution domain may move it, and only
      // while that domain is the one this service currently trusts.
      const reporting: ExecutionDomain | undefined = options.executionDomain && { journal_id: facts.journal_id, executor_uid: options.executionDomain.executor_uid };
      if (!sameDomain(reporting, options.executionDomain)) return { status: "REJECTED", reason: "REPORT_REJECTED:DOMAIN_NOT_CURRENT" };
      if (!sameDomain(rec.domain, options.executionDomain)) return { status: "REJECTED", reason: "REPORT_REJECTED:DOMAIN_MISMATCH" };
      let applied;
      try {
        applied = applyOutcome(rec, facts, options.now());
      } catch (err) {
        return { status: "REJECTED", reason: err instanceof ReportRejected ? err.message : `REPORT_REJECTED:${(err as Error).message}` };
      }
      if (applied.kind !== "APPLIED") return { status: applied.kind, reservation: rec, released: "0" };
      const spent = loaded.state.budget.spent_in_period[rec.agent_id] ?? 0n;
      if (applied.release > spent) return { status: "REJECTED", reason: "RESERVATION_ACCOUNTING_INCONSISTENT" };
      const nextState = {
        ...loaded.state,
        budget: { ...loaded.state.budget, spent_in_period: { ...loaded.state.budget.spent_in_period, [rec.agent_id]: spent - applied.release } },
      };
      let committed: boolean;
      try {
        committed = await options.stateStore.commit(nextState, loaded.version, { ...loaded.reservations, [facts.auth_id]: applied.next });
      } catch (err) {
        return { status: "REJECTED", reason: `POLICY_STATE_UNAVAILABLE:${(err as Error).message}` };
      }
      if (committed) return { status: "APPLIED", reservation: applied.next, released: applied.release.toString() };
    }
    return { status: "REJECTED", reason: "POLICY_STATE_CONFLICT" };
  }

  /**
   * RESERVED reservations of the current execution domain whose authorization
   * expired more than `graceSeconds` ago (cancellation candidates). Other
   * domains' reservations are never offered (CX2).
   */
  async function expiredReservations(graceSeconds: number): Promise<Array<Pick<ReservationRecord, "auth_id" | "intent_hash" | "expiry">>> {
    const loaded = await options.stateStore.load();
    const cutoff = options.now() - graceSeconds;
    return Object.values(loaded.reservations)
      .filter((r) => r.state === "RESERVED" && r.expiry < cutoff && sameDomain(r.domain, options.executionDomain))
      .map((r) => ({ auth_id: r.auth_id, intent_hash: r.intent_hash, expiry: r.expiry }));
  }

  return {
    authorize,
    settle,
    expiredReservations,
    /** Public verification material for the gateway. Contains no secrets. */
    trustMaterial: Object.freeze({ keySet, authority, audience: options.audience }),
  };
}

export type AuthorizationService = ReturnType<typeof createAuthorizationService>;

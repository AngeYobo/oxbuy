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
import type { ClaimResult, VoidResult } from "../executor/execution-authority.ts";
import { verifyClaim, verifyReport, verifyVoid } from "../executor/outcome-report.ts";
import { assertRequiredAllowlists, type PolicyStateStore } from "./policy-state.ts";
import {
  applyClaim,
  applyOutcome,
  applyVoid,
  ClaimRefused,
  newReservation,
  releaseIfExpired,
  ReportRejected,
  type ApplyResult,
  type ReservationRecord,
} from "./reservations.ts";

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
  /** Executor message key (Phase 2C reports; Phase 2D claims and voids). Without it, every claim, void, and report is refused. */
  readonly executorReportKey?: { readonly publicKeyPem: string; readonly kid: string };
  /**
   * The execution domain this deployment's executor runs in (Phase 2C; CX2).
   * Every reservation is bound to it; `audience` must already name it
   * (src/executor/execution-domain.ts). Without it, reservations are unbound
   * and only unbound claims, voids, and reports are accepted (in-process
   * harness only; the auth service process always configures a domain).
   */
  readonly executionDomain?: ExecutionDomain;
  /** A claim needs `now < expiry - minRemainingSeconds` on this service's clock (Phase 2D; D4). Default 0. */
  readonly minRemainingSeconds?: number;
};

export type SettleResult =
  | { readonly status: "APPLIED" | "ALREADY_APPLIED" | "STALE" | "NOT_CLAIMED"; readonly reservation: ReservationRecord; readonly released: string }
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
    // Legacy restore (Phase 2D): windowed limits restored from a backup are not trusted until every
    // window and lease that existed before the restore has run out.
    if (loaded.quarantine_until !== undefined && evaluationTime < loaded.quarantine_until) {
      return { decision: "DENY", reasons: ["POLICY_STATE_QUARANTINED"] };
    }
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
   * The execution domain check for a claim, void, or report naming
   * `journalId` (CX2): only the reservation's own domain, and only while that
   * is the domain this service trusts. Without a configured domain (in-process
   * harness) only unbound reservations are accepted.
   */
  function domainRefusal(journalId: string, rec: ReservationRecord): string | null {
    if (!options.executionDomain) return rec.domain === null ? null : "DOMAIN_MISMATCH";
    if (journalId !== options.executionDomain.journal_id) return "DOMAIN_NOT_CURRENT";
    if (!sameDomain(rec.domain, options.executionDomain)) return "DOMAIN_MISMATCH";
    return null;
  }

  /**
   * One reservation transition, committed atomically with its budget effect
   * (compare-and-set, retried on a concurrent commit). `step` throws to refuse;
   * nothing is written then. A release subtracts exactly what the reservation
   * stops being charged.
   */
  async function transition(
    authId: string,
    journalId: string,
    step: (rec: ReservationRecord, now: number) => ApplyResult,
  ): Promise<{ ok: true; result: ApplyResult } | { ok: false; reason: string }> {
    for (let attempt = 0; attempt < 5; attempt++) {
      let loaded;
      try {
        loaded = await options.stateStore.load();
      } catch (err) {
        return { ok: false, reason: `POLICY_STATE_UNAVAILABLE:${(err as Error).message}` };
      }
      const rec = loaded.reservations[authId];
      if (rec === undefined) return { ok: false, reason: "REPORT_REJECTED:UNKNOWN_RESERVATION" };
      const refusal = domainRefusal(journalId, rec);
      if (refusal) return { ok: false, reason: `REPORT_REJECTED:${refusal}` };
      let result: ApplyResult;
      try {
        result = step(rec, options.now());
      } catch (err) {
        return { ok: false, reason: err instanceof ReportRejected || err instanceof ClaimRefused ? err.message : `REPORT_REJECTED:${(err as Error).message}` };
      }
      if (!result.changed) return { ok: true, result };
      const spent = loaded.state.budget.spent_in_period[rec.agent_id] ?? 0n;
      if (result.release > spent || result.release < 0n) return { ok: false, reason: "RESERVATION_ACCOUNTING_INCONSISTENT" };
      const nextState = {
        ...loaded.state,
        budget: { ...loaded.state.budget, spent_in_period: { ...loaded.state.budget.spent_in_period, [rec.agent_id]: spent - result.release } },
      };
      let committed: boolean;
      try {
        committed = await options.stateStore.commit(nextState, loaded.version, { ...loaded.reservations, [authId]: result.next });
      } catch (err) {
        return { ok: false, reason: `POLICY_STATE_UNAVAILABLE:${(err as Error).message}` };
      }
      // Only after the commit (DONE durable) is anything acknowledged.
      if (committed) return { ok: true, result };
    }
    return { ok: false, reason: "POLICY_STATE_CONFLICT" };
  }

  function executorKey() {
    if (!options.executorReportKey) throw new Error("REPORT_INVALID:no trusted executor key");
    return options.executorReportKey;
  }

  /**
   * Execution claim (Phase 2D): RESERVED -> EXECUTING(claim_id), durably
   * committed before it is acknowledged, only while the authorization is valid
   * on this service's clock (`now < expiry - minRemainingSeconds`). At most
   * one claim per authorization is ever granted. Never throws.
   *
   * REJECTED is definitive: nothing was committed for this claim. A policy-state
   * failure (load, commit, or an unconfirmed commit whose new state may already
   * be in place and is completed by the next start) is UNCONFIRMED instead, so
   * the executor abandons the attempt (positive record + VOID) rather than
   * treating the claim as never committed (audit finding AUD-01).
   */
  async function claim(signed: unknown): Promise<ClaimResult> {
    let c;
    try {
      c = verifyClaim(signed, executorKey());
    } catch (err) {
      return { status: "REJECTED", reason: (err as Error).message };
    }
    const t = await transition(c.auth_id, c.journal_id, (rec, now) => applyClaim(rec, c, now, options.minRemainingSeconds ?? 0));
    if (!t.ok) return t.reason.startsWith("POLICY_STATE_") ? { status: "UNCONFIRMED", reason: t.reason } : { status: "REJECTED", reason: t.reason };
    return { status: "CLAIMED", auth_id: c.auth_id, intent_hash: c.intent_hash, claim_id: c.claim_id };
  }

  /** Synchronous VOID of a pre-execution rejection or an abandoned claim (Phase 2D). Never throws. */
  async function voidAuthorization(signed: unknown): Promise<VoidResult> {
    let v;
    try {
      v = verifyVoid(signed, executorKey());
    } catch (err) {
      return { status: "REJECTED", reason: (err as Error).message };
    }
    const t = await transition(v.auth_id, v.journal_id, (rec, now) => applyVoid(rec, v, now));
    if (!t.ok) return { status: "REJECTED", reason: t.reason };
    return { status: t.result.kind === "ALREADY_APPLIED" ? "ALREADY_APPLIED" : "APPLIED", released: t.result.release.toString() };
  }

  /**
   * Apply one executor outcome report for a claim (Phase 2C; F3, Phase 2D).
   * The report must carry a valid executor signature; the transition must be
   * allowed by the reservation state machine. Never throws.
   */
  async function settle(signed: unknown): Promise<SettleResult> {
    let facts;
    try {
      facts = verifyReport(signed, executorKey());
    } catch (err) {
      return { status: "REJECTED", reason: (err as Error).message };
    }
    const t = await transition(facts.auth_id, facts.journal_id, (rec, now) => applyOutcome(rec, facts, now));
    if (!t.ok) return { status: "REJECTED", reason: t.reason };
    const kind = t.result.kind === "CLAIMED" ? "APPLIED" : t.result.kind;
    return { status: kind, reservation: t.result.next, released: t.result.release.toString() };
  }

  /**
   * Release every unclaimed Phase 2D reservation whose authorization has
   * expired on this service's clock (no claim can be granted for it any more),
   * in one commit. Returns how many were released.
   */
  async function releaseExpired(): Promise<number> {
    for (let attempt = 0; attempt < 5; attempt++) {
      const loaded = await options.stateStore.load();
      const now = options.now();
      const next: Record<string, ReservationRecord> = { ...loaded.reservations };
      const spent = { ...loaded.state.budget.spent_in_period };
      let count = 0;
      for (const rec of Object.values(loaded.reservations)) {
        const r = releaseIfExpired(rec, now);
        if (r === null) continue;
        const s = spent[rec.agent_id] ?? 0n;
        if (r.release > s) throw new Error("RESERVATION_ACCOUNTING_INCONSISTENT");
        spent[rec.agent_id] = s - r.release;
        next[rec.auth_id] = r.next;
        count += 1;
      }
      if (count === 0) return 0;
      const nextState = { ...loaded.state, budget: { ...loaded.state.budget, spent_in_period: spent } };
      if (await options.stateStore.commit(nextState, loaded.version, next)) return count;
    }
    throw new Error("POLICY_STATE_CONFLICT");
  }

  return {
    authorize,
    claim,
    voidAuthorization,
    settle,
    releaseExpired,
    /** Public verification material for the gateway. Contains no secrets. */
    trustMaterial: Object.freeze({ keySet, authority, audience: options.audience }),
  };
}

export type AuthorizationService = ReturnType<typeof createAuthorizationService>;

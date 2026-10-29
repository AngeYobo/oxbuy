// SPDX-License-Identifier: MIT
/**
 * The executor's view of the authorization service as the execution
 * authority (Phase 2D; architecture C).
 *
 *   claim  RESERVED -> EXECUTING(claim_id) at the authorization service,
 *          durably committed before it answers. `pay` may be called only
 *          after `{ ok: true }` for exactly this attempt's claim id, in this
 *          process.
 *   void   synchronous, acknowledged release of an authorization the
 *          executor rejected before execution, or of a claim it abandoned.
 *
 * A claim answer is `definitive` when the authorization service itself
 * answered (claim refused: nothing committed). Anything else (timeout, lost
 * connection, unexpected answer) is not definitive: the claim may or may not
 * have committed, so the attempt is abandoned and never paid.
 *
 * `createLocalExecutionAuthority` is the in-process test harness transport: it
 * signs the same messages with the executor report key and calls the service
 * directly. The executor process uses the settle channel (executor-main.ts).
 */
import type { VoidReason } from "../authorization/reservations.ts";
import { CLAIM_TYPE, signClaim, signVoid, VOID_TYPE } from "./outcome-report.ts";

export type ClaimRequest = { readonly auth_id: string; readonly intent_hash: string; readonly claim_id: string };
export type ClaimAnswer = { readonly ok: true } | { readonly ok: false; readonly definitive: boolean; readonly reason: string };
export type VoidRequest = { readonly auth_id: string; readonly intent_hash: string; readonly reason: VoidReason; readonly claim_id?: string };
/**
 * `acknowledged`: the service committed this VOID (or already held it).
 * `final`: the service has durably confirmed that the authorization can no longer be claimed: the VOID was
 * acknowledged, or it was refused because the reservation already left RESERVED (VOID_NOT_ELIGIBLE:<state>),
 * which is never re-entered. Only a final answer lets the executor present a rejection as definitive (F-SIBLING).
 */
export type VoidAnswer = { readonly acknowledged: boolean; readonly final: boolean; readonly reason?: string };

export interface ExecutionAuthority {
  claim(c: ClaimRequest): Promise<ClaimAnswer>;
  void(v: VoidRequest): Promise<VoidAnswer>;
}

/** What the authorization service answers (authorization-service.ts `claim` / `voidAuthorization`). */
export type ClaimResult =
  | { readonly status: "CLAIMED"; readonly auth_id: string; readonly intent_hash: string; readonly claim_id: string }
  | { readonly status: "REJECTED"; readonly reason: string }
  /** The service could not confirm whether the claim committed (policy-state failure): never definitive. */
  | { readonly status: "UNCONFIRMED"; readonly reason: string };
export type VoidResult = { readonly status: "APPLIED" | "ALREADY_APPLIED"; readonly released: string } | { readonly status: "REJECTED"; readonly reason: string };

/** Accept a claim answer only if it acknowledges exactly this attempt's claim. */
export function interpretClaim(c: ClaimRequest, httpStatus: number, body: unknown): ClaimAnswer {
  const b = (typeof body === "object" && body !== null ? body : {}) as Partial<ClaimResult & { reason: string }>;
  if (httpStatus === 200 && b.status === "CLAIMED") {
    if (b.claim_id === c.claim_id && b.auth_id === c.auth_id && b.intent_hash === c.intent_hash) return { ok: true };
    return { ok: false, definitive: false, reason: "CLAIM_ACK_MISMATCH" };
  }
  // The service answered and refused: nothing was committed for this claim.
  if ((httpStatus === 200 || httpStatus === 403) && b.status === "REJECTED") return { ok: false, definitive: true, reason: String(b.reason) };
  // The service answered but cannot confirm the commit's outcome: the claim may be in place.
  if (httpStatus === 200 && b.status === "UNCONFIRMED") return { ok: false, definitive: false, reason: `CLAIM_UNCONFIRMED:${String(b.reason)}` };
  return { ok: false, definitive: false, reason: `CLAIM_UNAVAILABLE:http ${httpStatus}` };
}

export function interpretVoid(httpStatus: number, body: unknown): VoidAnswer {
  const b = (typeof body === "object" && body !== null ? body : {}) as Partial<VoidResult & { reason: string }>;
  if (httpStatus === 200 && (b.status === "APPLIED" || b.status === "ALREADY_APPLIED")) return { acknowledged: true, final: true };
  const reason = b.reason ?? `http ${httpStatus}`;
  // The service answered that the reservation is no longer RESERVED (or is a legacy one that can never be claimed).
  // (reservations.ts applyVoid -> ReportRejected("VOID_NOT_ELIGIBLE:<state>"), message "REPORT_REJECTED:VOID_NOT_ELIGIBLE:<state>")
  const final = httpStatus === 200 && b.status === "REJECTED" && typeof b.reason === "string" && /^REPORT_REJECTED:VOID_NOT_ELIGIBLE:[A-Z_]+$/.test(b.reason);
  return { acknowledged: false, final, reason };
}

/**
 * A definitive claim refusal that also proves the authorization can never be claimed again: the reservation
 * left RESERVED, is a legacy one, or its authorization expired on the service's clock. Other definitive
 * refusals (binding, domain, unknown reservation, a dead claim id) say nothing about later claims.
 */
export function claimRefusalIsFinal(reason: string): boolean {
  // reservations.ts applyClaim -> ClaimRefused(code), message "CLAIM_REFUSED:<code>"
  if (reason === "CLAIM_REFUSED:AUTH_EXPIRED_AT_CLAIM") return true;
  return /^CLAIM_REFUSED:NOT_ELIGIBLE:[A-Z_]+$/.test(reason) && reason !== "CLAIM_REFUSED:NOT_ELIGIBLE:DEAD_CLAIM";
}

/** In-process harness transport (src/system.ts and unit tests). */
export function createLocalExecutionAuthority(
  service: { claim(signed: unknown): Promise<ClaimResult>; voidAuthorization(signed: unknown): Promise<VoidResult> },
  key: { readonly privateKeyPem: string; readonly kid: string },
  journalId: string,
): ExecutionAuthority {
  return {
    async claim(c) {
      const signed = signClaim({ type: CLAIM_TYPE, ...c, journal_id: journalId, executor_kid: key.kid }, key.privateKeyPem);
      return interpretClaim(c, 200, await service.claim(signed));
    },
    async void(v) {
      const signed = signVoid({ type: VOID_TYPE, ...v, journal_id: journalId, executor_kid: key.kid }, key.privateKeyPem);
      return interpretVoid(200, await service.voidAuthorization(signed));
    },
  };
}

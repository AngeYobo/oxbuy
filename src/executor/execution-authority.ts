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
export type VoidAnswer = { readonly acknowledged: boolean; readonly reason?: string };

export interface ExecutionAuthority {
  claim(c: ClaimRequest): Promise<ClaimAnswer>;
  void(v: VoidRequest): Promise<VoidAnswer>;
}

/** What the authorization service answers (authorization-service.ts `claim` / `voidAuthorization`). */
export type ClaimResult = { readonly status: "CLAIMED"; readonly auth_id: string; readonly intent_hash: string; readonly claim_id: string } | { readonly status: "REJECTED"; readonly reason: string };
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
  return { ok: false, definitive: false, reason: `CLAIM_UNAVAILABLE:http ${httpStatus}` };
}

export function interpretVoid(httpStatus: number, body: unknown): VoidAnswer {
  const b = (typeof body === "object" && body !== null ? body : {}) as Partial<VoidResult & { reason: string }>;
  if (httpStatus === 200 && (b.status === "APPLIED" || b.status === "ALREADY_APPLIED")) return { acknowledged: true };
  return { acknowledged: false, reason: b.reason ?? `http ${httpStatus}` };
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

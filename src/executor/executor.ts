// SPDX-License-Identifier: MIT
/**
 * Trusted payment executor.
 *
 * The only component holding the PaymentAdapter (in Phase 2: the only
 * component able to reach the wallet-bearing buy process). It accepts work
 * only when the caller presents the internal executor token, checked by the
 * published `protectUpstreamExecution` from @oxdeai/guard. The token is
 * shared only with the gateway, and it is not sufficient: every request must
 * also carry the signed AuthorizationV1, which the executor verifies itself
 * with the published `verifyAuthorization` (strict: Ed25519 signature
 * against trusted KeySets, audience, expiry, issued_at plausibility, and the
 * (issuer, policy_id) authority pair), and whose `intent_hash` must equal the
 * hash the executor recomputes from the action.
 *
 * Before `pay`, it re-quotes and requires the live 402 requirements to match
 * the authorized network, asset, recipient, and resource, and the live price
 * to be <= the authorized max_amount. `pay` itself receives the full
 * authorized binding and must re-check it before signing (see
 * payment-adapter.ts).
 *
 * Replay: the gateway consumes `auth_id` in its replay store before calling
 * the executor; the executor then consumes it again, durably, in the payment
 * journal together with the intent reservation. A first-time request passes
 * both; a resubmission is stopped by whichever sees it second. Neither is the
 * authority (Phase 2D): before `pay` the executor must obtain a durably
 * committed execution claim from the authorization service for this attempt
 * (src/executor/execution-authority.ts). The service grants at most one claim
 * per authorization, ever, on its own clock (`now < expiry`), so a restarted
 * gateway or a rolled-back journal cannot make an authorization payable again.
 * A pre-execution rejection of an authentic authorization is VOIDed at the
 * service synchronously; if the VOID is not acknowledged, the reservation
 * stays charged until it expires there.
 *
 * Final rejections (F-SIBLING, patch 0008): every NOT_EXECUTED answer carries
 * `final`. It is true only when the authorization service itself has durably
 * confirmed, for this request, that the authorization can never be claimed
 * again (acknowledged VOID, a claim refused because the reservation already
 * left RESERVED or expired, or a claim that committed and was then refused
 * before signing). Such a rejection survives any rollback of the executor's
 * state, checkpoint included, because the service never re-enters RESERVED.
 * When the service could not confirm it (outage, timeout, journal failure, a
 * replay answer, an unauthentic request), `final` is false: nothing was paid,
 * but the rejection is protected only by the executor's journal and
 * checkpoint, and the caller must not treat the authorization as dead until it
 * expires.
 *
 * Every response states one of three outcomes:
 *   NOT_EXECUTED     nothing was signed or submitted;
 *   EXECUTED         `pay` returned a settled receipt matching the binding;
 *   PAYMENT_UNKNOWN  `pay` was (or may have been) invoked and its result is
 *                    not a verified settlement.
 * A journal reservation (STARTED) is written before `pay` is invoked, and the
 * same intent is never handed to `pay` twice.
 */
import { randomBytes } from "node:crypto";
import { verifyAuthorization, type AuthorizationAuthority, type AuthorizationV1, type KeySet } from "@oxdeai/core";
import { protectUpstreamExecution } from "@oxdeai/guard";
import { hashGatewayAction, validatePurchaseRequest } from "../authorization/intent.ts";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { claimRefusalIsFinal, type ExecutionAuthority } from "./execution-authority.ts";
import { PaymentRefusedError, type PaymentAdapter, type PaymentReceipt, type QuoteRequest } from "./payment-adapter.ts";
import type { PaymentJournal } from "./payment-journal.ts";

export type ExecutorOutcome =
  | { readonly outcome: "NOT_EXECUTED"; readonly error: string; readonly final: boolean; readonly prior_state?: string }
  | { readonly outcome: "EXECUTED"; readonly receipt: PaymentReceipt }
  | { readonly outcome: "PAYMENT_UNKNOWN"; readonly error: string; readonly receipt?: unknown; readonly prior_state?: string };

export type ExecutorResponse = { status: number; body: unknown; executed: boolean | "unknown" };

/** Trust material the executor verifies authorizations against. */
export type ExecutorVerification = {
  readonly expectedAudience: string;
  readonly trustedKeySets: readonly KeySet[];
  readonly trustedAuthorizationAuthorities: readonly AuthorizationAuthority[];
  /** Trusted clock, unix seconds. */
  readonly now: () => number;
};

export type ExecutorOptions = {
  readonly internalToken: string;
  readonly adapter: PaymentAdapter;
  readonly verification: ExecutorVerification;
  readonly journal: PaymentJournal;
  /** The authorization service as the execution authority (claim before `pay`, VOID on rejection). */
  readonly authority: ExecutionAuthority;
};

const ATOMIC_AMOUNT = /^(0|[1-9][0-9]{0,30})$/;

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Exactly `{ action, authorization }`. */
function parseEnvelope(body: unknown): { action: unknown; authorization: AuthorizationV1 } {
  if (typeof body !== "object" || body === null || Array.isArray(body)) throw new Error("EXECUTOR_INVALID_REQUEST");
  const keys = Object.keys(body).sort();
  if (keys.length !== 2 || keys[0] !== "action" || keys[1] !== "authorization") throw new Error("EXECUTOR_INVALID_REQUEST");
  const { action, authorization } = body as { action: unknown; authorization: unknown };
  if (typeof authorization !== "object" || authorization === null || Array.isArray(authorization)) {
    throw new Error("EXECUTOR_AUTHORIZATION_MISSING");
  }
  return { action, authorization: authorization as AuthorizationV1 };
}

/** Null when the receipt is a settled payment within the binding. */
function receiptViolation(receipt: unknown, request: PurchaseRequest): string | null {
  if (typeof receipt !== "object" || receipt === null) return "EXECUTOR_RECEIPT_AMBIGUOUS";
  const r = receipt as Record<string, unknown>;
  if (r.settled !== true) return "EXECUTOR_RECEIPT_NOT_SETTLED";
  if (
    typeof r.reference !== "string" ||
    r.reference === "" ||
    typeof r.pay_to !== "string" ||
    typeof r.amount !== "string" ||
    !ATOMIC_AMOUNT.test(r.amount)
  ) {
    return "EXECUTOR_RECEIPT_AMBIGUOUS";
  }
  if (r.network !== request.network) return "EXECUTOR_RECEIPT_NETWORK_MISMATCH";
  if (r.asset !== request.asset) return "EXECUTOR_RECEIPT_ASSET_MISMATCH";
  if (r.pay_to.toLowerCase() !== request.recipient) return "EXECUTOR_RECEIPT_RECIPIENT_MISMATCH";
  if (BigInt(r.amount) > BigInt(request.max_amount)) return "EXECUTOR_RECEIPT_EXCEEDS_AUTHORIZED_MAX";
  return null;
}

export function createPaymentExecutor(options: ExecutorOptions) {
  const { journal, verification: v } = options;

  /** Intents whose `pay` is running in this process right now (outcome reports: EXECUTING, not UNCERTAIN). */
  const inFlight = new Set<string>();

  async function execute(body: unknown): Promise<ExecutorOutcome> {
    // Pre-payment checks: any failure here means nothing was signed.
    let intentHash: string;
    let authId: string;
    let request: PurchaseRequest;
    // Set once the authorization is proven authentic, unexpired, and bound to
    // this action. From then on a refusal consumes the auth_id durably
    // (REJECTED_BEFORE_EXECUTION) so its budget reservation can be released
    // safely: a consumed auth_id can never be used to pay (Phase 2C; F3).
    let authentic = false;
    try {
      const { action, authorization } = parseEnvelope(body);
      intentHash = hashGatewayAction(action);
      const verdict = verifyAuthorization(authorization, {
        now: v.now(),
        mode: "strict",
        trustedKeySets: v.trustedKeySets,
        requireSignatureVerification: true,
        expectedAudience: v.expectedAudience,
        trustedAuthorizationAuthorities: v.trustedAuthorizationAuthorities,
      });
      if (verdict.status !== "ok") {
        throw new Error(`EXECUTOR_AUTHORIZATION_INVALID:${verdict.violations.map((x) => x.code).join(",") || "UNKNOWN"}`);
      }
      if (authorization.intent_hash !== intentHash) throw new Error("EXECUTOR_INTENT_HASH_MISMATCH");
      authId = authorization.auth_id;
      request = validatePurchaseRequest((action as Record<string, unknown>).request);
      authentic = true;
      const quote = await options.adapter.quote(request);
      const u = new URL(request.url);
      if (quote.network !== request.network) throw new Error("EXECUTOR_QUOTE_NETWORK_MISMATCH");
      if (quote.asset !== request.asset) throw new Error("EXECUTOR_QUOTE_ASSET_MISMATCH");
      if (quote.pay_to.toLowerCase() !== request.recipient) throw new Error("EXECUTOR_QUOTE_RECIPIENT_MISMATCH");
      if (quote.resource !== `${u.origin}${u.pathname}`) throw new Error("EXECUTOR_QUOTE_RESOURCE_MISMATCH");
      if (BigInt(quote.amount) > BigInt(request.max_amount)) throw new Error("EXECUTOR_QUOTE_EXCEEDS_AUTHORIZED_MAX");
    } catch (err) {
      if (!authentic) return { outcome: "NOT_EXECUTED", error: message(err), final: false };
      try {
        const rec = journal.consume({ auth_id: authId!, intent_hash: intentHash!, disposition: "REJECTED_BEFORE_EXECUTION", detail: message(err) });
        // Already consumed earlier (a replay): report what the journal holds, never a new rejection.
        if (rec.disposition !== "REJECTED_BEFORE_EXECUTION") return { outcome: "NOT_EXECUTED", error: "EXECUTOR_AUTH_REPLAY", final: false };
      } catch (storageErr) {
        return { outcome: "NOT_EXECUTED", error: `${message(err)};EXECUTOR_JOURNAL_UNAVAILABLE:${message(storageErr)}`, final: false };
      }
      // Burn it at the authority, synchronously. Unacknowledged: it stays charged until it expires there,
      // and the rejection is not final (F-SIBLING): only the service's confirmation survives a rollback.
      const voided = await voidFinal({ auth_id: authId!, intent_hash: intentHash!, reason: "REJECTED_BEFORE_EXECUTION" });
      return { outcome: "NOT_EXECUTED", error: message(err), final: voided };
    }

    let reservation;
    inFlight.add(intentHash);
    try {
      return await reserveAndPay();
    } finally {
      inFlight.delete(intentHash);
    }

    async function reserveAndPay(): Promise<ExecutorOutcome> {
      // One claim id per attempt, journaled before the claim is requested.
      const claimId = randomBytes(16).toString("hex");
      try {
        reservation = journal.reserve({ intent_hash: intentHash, auth_id: authId, request, claim_id: claimId });
      } catch (err) {
        return { outcome: "NOT_EXECUTED", error: `EXECUTOR_JOURNAL_UNAVAILABLE:${message(err)}`, final: false };
      }
      if (!reservation.ok) {
        if (reservation.reason === "AUTH_REPLAY") return { outcome: "NOT_EXECUTED", error: "EXECUTOR_AUTH_REPLAY", final: false };
        // This request is never paid. If the earlier attempt's outcome is not
        // definitive, the intent's payment status is unknown, not "not executed".
        const prior = reservation.prior;
        if (prior === "STARTED" || prior === "UNKNOWN") {
          return { outcome: "PAYMENT_UNKNOWN", error: "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT", prior_state: prior };
        }
        return { outcome: "NOT_EXECUTED", error: "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT", final: false, prior_state: prior };
      }

      // The irreversible boundary: `pay` only with this attempt's acknowledged, durably committed claim.
      let claim;
      try {
        claim = await options.authority.claim({ auth_id: authId, intent_hash: intentHash, claim_id: claimId });
      } catch (err) {
        claim = { ok: false as const, definitive: false, reason: message(err) };
      }
      if (!claim.ok) {
        if (claim.definitive) return refuse(intentHash, "CLAIM_REFUSED", `EXECUTOR_CLAIM_REFUSED:${claim.reason}`, claimRefusalIsFinal(claim.reason));
        // The claim may have committed. Never pay it: record that first, then try to void it.
        const out = refuse(intentHash, "CLAIM_ABANDONED", `EXECUTOR_CLAIM_UNAVAILABLE:${claim.reason}`, false);
        // This process will never pay this claim, so the VOID is true even if the record failed.
        const voided = await voidFinal({ auth_id: authId, intent_hash: intentHash, reason: "CLAIM_ABANDONED", claim_id: claimId });
        return out.outcome === "NOT_EXECUTED" ? { ...out, final: voided } : out;
      }

      let receipt: unknown;
      try {
        receipt = await options.adapter.pay({ intent_hash: intentHash, request, claim_id: claimId });
      } catch (err) {
        if (err instanceof PaymentRefusedError) {
          // The claim committed, so the service will never grant another one for this authorization.
          return finish(intentHash, { outcome: "NOT_EXECUTED", error: err.message, final: true }, "REFUSED_BEFORE_SIGNING", err.message);
        }
        return finish(
          intentHash,
          { outcome: "PAYMENT_UNKNOWN", error: `EXECUTOR_PAYMENT_OUTCOME_UNKNOWN:${message(err)}` },
          "UNKNOWN",
          message(err),
        );
      }

      // Detects a bad settlement after the fact; it cannot undo it.
      const violation = receiptViolation(receipt, request);
      if (violation !== null) {
        return finish(intentHash, { outcome: "PAYMENT_UNKNOWN", error: violation, receipt }, "UNKNOWN", violation, receipt);
      }
      return finish(intentHash, { outcome: "EXECUTED", receipt: receipt as PaymentReceipt }, "SETTLED", undefined, receipt);
    }
  }

  /**
   * Claim not granted: `pay` is never called for this attempt. If the record
   * cannot be written the journal still says STARTED (reported UNCERTAIN, held);
   * the response is still NOT_EXECUTED, which is true.
   */
  function refuse(intentHash: string, state: "CLAIM_REFUSED" | "CLAIM_ABANDONED", error: string, final: boolean): ExecutorOutcome {
    try {
      journal.record(intentHash, state, error);
      return { outcome: "NOT_EXECUTED", error, final };
    } catch (err) {
      return { outcome: "NOT_EXECUTED", error: `${error};EXECUTOR_JOURNAL_WRITE_FAILED:${message(err)}`, final };
    }
  }

  /** VOID at the authority; true only when the service confirmed the authorization can never be claimed again. */
  async function voidFinal(v: Parameters<ExecutionAuthority["void"]>[0]): Promise<boolean> {
    try {
      return (await options.authority.void(v)).final === true;
    } catch {
      return false;
    }
  }

  /**
   * Record the final journal state, then return `out`. If the record cannot
   * be written, the durable journal still says STARTED; report the outcome
   * as unknown rather than claim a result the journal does not hold.
   */
  function finish(
    intentHash: string,
    out: ExecutorOutcome,
    state: "SETTLED" | "REFUSED_BEFORE_SIGNING" | "UNKNOWN",
    detail?: string,
    receipt?: unknown,
  ): ExecutorOutcome {
    try {
      journal.record(intentHash, state, detail, receipt);
      return out;
    } catch (err) {
      return {
        outcome: "PAYMENT_UNKNOWN",
        error: `EXECUTOR_JOURNAL_WRITE_FAILED:${message(err)}`,
        ...("receipt" in out && out.receipt !== undefined ? { receipt: out.receipt } : {}),
      };
    }
  }

  async function quote(body: unknown): Promise<unknown> {
    const b = body as Partial<QuoteRequest> | null;
    if (typeof b !== "object" || b === null) throw new Error("EXECUTOR_INVALID_REQUEST");
    const q = await options.adapter.quote({ service_id: b.service_id!, method: b.method!, url: b.url!, body: b.body ?? null });
    return { network: q.network, asset: q.asset, pay_to: q.pay_to, amount: q.amount };
  }

  return {
    /** Entry point. Shape matches an HTTP handler: body + headers. */
    async handle(body: unknown, headers: Record<string, string | string[] | undefined>): Promise<ExecutorResponse> {
      const res = await protectUpstreamExecution(body, headers, { expectedToken: options.internalToken, execute });
      // 403: token rejected, `execute` never ran.
      if (res.status === 403) return res;
      // `execute` does not throw by construction; if it did, whether `pay`
      // ran is unknown.
      if (res.status !== 200) {
        return {
          status: 502,
          executed: "unknown",
          body: { outcome: "PAYMENT_UNKNOWN", error: `EXECUTOR_INTERNAL_ERROR:${(res.body as { error?: string }).error}` },
        };
      }
      const out = res.body as ExecutorOutcome;
      if (out.outcome === "EXECUTED") return { status: 200, executed: true, body: out };
      if (out.outcome === "NOT_EXECUTED") return { status: 409, executed: false, body: out };
      return { status: 502, executed: "unknown", body: out };
    },
    /** Read-only 402 quote, token-protected. Never signs or pays. */
    async handleQuote(body: unknown, headers: Record<string, string | string[] | undefined>): Promise<ExecutorResponse> {
      const res = await protectUpstreamExecution(body, headers, { expectedToken: options.internalToken, execute: quote });
      if (res.status === 200) return { status: 200, executed: false, body: res.body };
      return { status: res.status === 403 ? 403 : 400, executed: false, body: res.body };
    },
    /** Operator/test inspection of the payment journal. Never handed to the agent. */
    journal: { get: journal.get, inspect: journal.inspect },
    /** Intents being paid right now (for outcome reports). */
    inFlight: (): ReadonlySet<string> => inFlight,
  };
}

export type PaymentExecutor = ReturnType<typeof createPaymentExecutor>;

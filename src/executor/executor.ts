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
 * both; a resubmission is stopped by whichever sees it second.
 *
 * Every response states one of three outcomes:
 *   NOT_EXECUTED     nothing was signed or submitted;
 *   EXECUTED         `pay` returned a settled receipt matching the binding;
 *   PAYMENT_UNKNOWN  `pay` was (or may have been) invoked and its result is
 *                    not a verified settlement.
 * A journal reservation (STARTED) is written before `pay` is invoked, and the
 * same intent is never handed to `pay` twice.
 */
import { verifyAuthorization, type AuthorizationAuthority, type AuthorizationV1, type KeySet } from "@oxdeai/core";
import { protectUpstreamExecution } from "@oxdeai/guard";
import { hashGatewayAction, validatePurchaseRequest } from "../authorization/intent.ts";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { PaymentRefusedError, type PaymentAdapter, type PaymentReceipt, type QuoteRequest } from "./payment-adapter.ts";
import type { PaymentJournal } from "./payment-journal.ts";

export type ExecutorOutcome =
  | { readonly outcome: "NOT_EXECUTED"; readonly error: string; readonly prior_state?: string }
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

  async function execute(body: unknown): Promise<ExecutorOutcome> {
    // Pre-payment checks: any failure here means nothing was signed.
    let intentHash: string;
    let authId: string;
    let request: PurchaseRequest;
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
      const quote = await options.adapter.quote(request);
      const u = new URL(request.url);
      if (quote.network !== request.network) throw new Error("EXECUTOR_QUOTE_NETWORK_MISMATCH");
      if (quote.asset !== request.asset) throw new Error("EXECUTOR_QUOTE_ASSET_MISMATCH");
      if (quote.pay_to.toLowerCase() !== request.recipient) throw new Error("EXECUTOR_QUOTE_RECIPIENT_MISMATCH");
      if (quote.resource !== `${u.origin}${u.pathname}`) throw new Error("EXECUTOR_QUOTE_RESOURCE_MISMATCH");
      if (BigInt(quote.amount) > BigInt(request.max_amount)) throw new Error("EXECUTOR_QUOTE_EXCEEDS_AUTHORIZED_MAX");
    } catch (err) {
      return { outcome: "NOT_EXECUTED", error: message(err) };
    }

    let reservation;
    try {
      reservation = journal.reserve({ intent_hash: intentHash, auth_id: authId, request });
    } catch (err) {
      return { outcome: "NOT_EXECUTED", error: `EXECUTOR_JOURNAL_UNAVAILABLE:${message(err)}` };
    }
    if (!reservation.ok) {
      if (reservation.reason === "AUTH_REPLAY") return { outcome: "NOT_EXECUTED", error: "EXECUTOR_AUTH_REPLAY" };
      // This request is never paid. If the earlier attempt's outcome is not
      // definitive, the intent's payment status is unknown, not "not executed".
      const prior = reservation.prior;
      if (prior === "STARTED" || prior === "UNKNOWN") {
        return { outcome: "PAYMENT_UNKNOWN", error: "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT", prior_state: prior };
      }
      return { outcome: "NOT_EXECUTED", error: "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT", prior_state: prior };
    }

    let receipt: unknown;
    try {
      receipt = await options.adapter.pay({ intent_hash: intentHash, request });
    } catch (err) {
      if (err instanceof PaymentRefusedError) {
        return finish(intentHash, { outcome: "NOT_EXECUTED", error: err.message }, "REFUSED_BEFORE_SIGNING", err.message);
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
  };
}

export type PaymentExecutor = ReturnType<typeof createPaymentExecutor>;

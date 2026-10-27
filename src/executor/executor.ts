// SPDX-License-Identifier: MIT
/**
 * Trusted payment executor.
 *
 * The only component holding the PaymentAdapter (in Phase 2: the only
 * component able to reach the wallet-bearing buy process). It accepts work
 * only when the caller presents the internal executor token, checked by the
 * published `protectUpstreamExecution` from @oxdeai/guard. The token is
 * shared only with the gateway.
 *
 * Before `pay`, it re-quotes and requires the live 402 requirements to match
 * the authorized network, asset, recipient, and resource, and the live price
 * to be <= the authorized max_amount. `pay` itself receives the full
 * authorized binding and must re-check it before signing (see
 * payment-adapter.ts).
 *
 * Every response states one of three outcomes:
 *   NOT_EXECUTED     nothing was signed or submitted;
 *   EXECUTED         `pay` returned a settled receipt matching the binding;
 *   PAYMENT_UNKNOWN  `pay` was invoked and its result is not a verified
 *                    settlement (error, ambiguous or mismatched receipt).
 * A payment journal entry is written before `pay` is invoked, and the same
 * intent is never handed to `pay` twice.
 */
import { protectUpstreamExecution } from "@oxdeai/guard";
import { hashGatewayAction, validatePurchaseRequest } from "../authorization/intent.ts";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { PaymentRefusedError, type PaymentAdapter, type PaymentReceipt } from "./payment-adapter.ts";

export type ExecutorOutcome =
  | { readonly outcome: "NOT_EXECUTED"; readonly error: string }
  | { readonly outcome: "EXECUTED"; readonly receipt: PaymentReceipt }
  | { readonly outcome: "PAYMENT_UNKNOWN"; readonly error: string; readonly receipt?: unknown };

export type ExecutorResponse = { status: number; body: unknown; executed: boolean | "unknown" };

export type PaymentJournalState = "STARTED" | "SETTLED" | "REFUSED_BEFORE_SIGNING" | "UNKNOWN";
export type PaymentJournalEntry = { readonly state: PaymentJournalState; readonly detail?: string };

const ATOMIC_AMOUNT = /^(0|[1-9][0-9]{0,30})$/;

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** In-memory journal keyed by intent hash. Phase 2 needs durable storage. */
function createPaymentJournal() {
  const entries = new Map<string, PaymentJournalEntry>();
  return {
    /** Records STARTED. False if this intent was already handed to `pay`. */
    begin(intentHash: string): boolean {
      if (entries.has(intentHash)) return false;
      entries.set(intentHash, { state: "STARTED" });
      return true;
    },
    record(intentHash: string, state: Exclude<PaymentJournalState, "STARTED">, detail?: string) {
      entries.set(intentHash, detail === undefined ? { state } : { state, detail });
    },
    get(intentHash: string): PaymentJournalEntry | undefined {
      return entries.get(intentHash);
    },
  };
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

export function createPaymentExecutor(options: { readonly internalToken: string; readonly adapter: PaymentAdapter }) {
  const journal = createPaymentJournal();

  async function execute(action: unknown): Promise<ExecutorOutcome> {
    // Pre-payment checks: any failure here means nothing was signed.
    let intentHash: string;
    let request: PurchaseRequest;
    try {
      intentHash = hashGatewayAction(action);
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

    if (!journal.begin(intentHash)) return { outcome: "NOT_EXECUTED", error: "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT" };

    let receipt: unknown;
    try {
      receipt = await options.adapter.pay({ intent_hash: intentHash, request });
    } catch (err) {
      if (err instanceof PaymentRefusedError) {
        journal.record(intentHash, "REFUSED_BEFORE_SIGNING", err.message);
        return { outcome: "NOT_EXECUTED", error: err.message };
      }
      journal.record(intentHash, "UNKNOWN", message(err));
      return { outcome: "PAYMENT_UNKNOWN", error: `EXECUTOR_PAYMENT_OUTCOME_UNKNOWN:${message(err)}` };
    }

    // Detects a bad settlement after the fact; it cannot undo it.
    const violation = receiptViolation(receipt, request);
    if (violation !== null) {
      journal.record(intentHash, "UNKNOWN", violation);
      return { outcome: "PAYMENT_UNKNOWN", error: violation, receipt };
    }
    journal.record(intentHash, "SETTLED");
    return { outcome: "EXECUTED", receipt: receipt as PaymentReceipt };
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
    /** Operator/test inspection of the payment journal. Never handed to the agent. */
    journal: { get: journal.get },
  };
}

export type PaymentExecutor = ReturnType<typeof createPaymentExecutor>;

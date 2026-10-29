// SPDX-License-Identifier: MIT
/**
 * Payment adapter contract used by the trusted executor.
 *
 * Modeled on the two documented `@celo/buy` operations (see
 * docs/FEASIBILITY.md): a read-only quote (`buy_pay_quote`) and a paid call
 * that signs and settles (`buy_curl` / `buy curl --max-amount`). Field names
 * here are this PoC's own; they are NOT a verified mirror of the @celo/buy
 * wire format, and nothing here is evidence that @celo/buy can honour the
 * payment-time checks required of `pay` below.
 */
import type { PurchaseRequest } from "../agent/purchase-request.ts";

/** Payment requirements read from an HTTP 402 challenge. */
export type PaymentQuote = {
  readonly network: string;
  readonly asset: string;
  readonly pay_to: string;
  /** Atomic units, decimal string. */
  readonly amount: string;
  readonly resource: string;
};

export type PaymentReceipt = {
  readonly settled: boolean;
  /** Settlement reference. Mock adapters MUST prefix it with "mock-". */
  readonly reference: string;
  readonly network: string;
  readonly asset: string;
  readonly amount: string;
  readonly pay_to: string;
  readonly response_status: number;
  readonly response_body: string;
};

export type QuoteRequest = Pick<PurchaseRequest, "service_id" | "method" | "url" | "body">;

/**
 * The full authorized payment binding handed to `pay`.
 *
 * `request` carries the exact method, URL, body, service id, and the
 * authorized network, asset, recipient, and max_amount. `intent_hash` is the
 * OxDeAI intent hash the gateway verified the authorization against: the
 * exact request identity.
 */
export type AuthorizedPayment = {
  readonly intent_hash: string;
  readonly request: PurchaseRequest;
  /** The execution claim the authorization service committed for this attempt (Phase 2D). */
  readonly claim_id: string;
};

/**
 * Thrown by `pay` ONLY when it is certain that nothing was signed or
 * submitted. Any other error from `pay` is treated as an unknown payment
 * outcome.
 */
export class PaymentRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PaymentRefusedError";
  }
}

export interface PaymentAdapter {
  /** Read-only. Must not sign or pay. */
  quote(request: QuoteRequest): Promise<PaymentQuote>;
  /**
   * Sign and settle for exactly `payment.request`. This is the only
   * operation that can move funds.
   *
   * Immediately before signing, against the live 402 requirements, it must
   * throw `PaymentRefusedError` unless network, asset, payTo, and resource
   * equal the authorized values and the price is <= `max_amount`.
   */
  pay(payment: AuthorizedPayment): Promise<PaymentReceipt>;
}

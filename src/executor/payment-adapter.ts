// SPDX-License-Identifier: MIT
/**
 * Payment adapter contract used by the trusted executor.
 *
 * Modeled on the two documented `@celo/buy` operations (see
 * docs/FEASIBILITY.md): a read-only quote (`buy_pay_quote`) and a paid call
 * that signs and settles (`buy_curl` / `buy curl --max-amount`). Field names
 * here are this PoC's own; they are NOT a verified mirror of the @celo/buy
 * wire format.
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
  readonly amount: string;
  readonly pay_to: string;
  readonly response_status: number;
  readonly response_body: string;
};

export type QuoteRequest = Pick<PurchaseRequest, "service_id" | "method" | "url" | "body">;

export interface PaymentAdapter {
  /** Read-only. Must not sign or pay. */
  quote(request: QuoteRequest): Promise<PaymentQuote>;
  /**
   * Sign and settle for exactly `request`, refusing if the live price exceeds
   * `maxAmount`. This is the only operation that can move funds.
   */
  pay(request: PurchaseRequest, maxAmount: bigint): Promise<PaymentReceipt>;
}

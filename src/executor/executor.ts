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
 * to be <= the authorized max_amount. Any mismatch throws, so no payment.
 */
import { protectUpstreamExecution } from "@oxdeai/guard";
import { validateIntentRef, validatePurchaseRequest } from "../authorization/intent.ts";
import type { PaymentAdapter, PaymentReceipt } from "./payment-adapter.ts";

export type ExecutorResponse = { status: number; body: unknown; executed: boolean };

export function createPaymentExecutor(options: { readonly internalToken: string; readonly adapter: PaymentAdapter }) {
  async function execute(action: unknown): Promise<PaymentReceipt> {
    if (typeof action !== "object" || action === null) throw new Error("EXECUTOR_INVALID_ACTION");
    const { request: rawRequest, intent_ref } = action as Record<string, unknown>;
    const request = validatePurchaseRequest(rawRequest);
    validateIntentRef(intent_ref);

    const quote = await options.adapter.quote(request);
    const u = new URL(request.url);
    if (quote.network !== request.network) throw new Error("EXECUTOR_QUOTE_NETWORK_MISMATCH");
    if (quote.asset !== request.asset) throw new Error("EXECUTOR_QUOTE_ASSET_MISMATCH");
    if (quote.pay_to.toLowerCase() !== request.recipient) throw new Error("EXECUTOR_QUOTE_RECIPIENT_MISMATCH");
    if (quote.resource !== `${u.origin}${u.pathname}`) throw new Error("EXECUTOR_QUOTE_RESOURCE_MISMATCH");
    const maxAmount = BigInt(request.max_amount);
    if (BigInt(quote.amount) > maxAmount) throw new Error("EXECUTOR_QUOTE_EXCEEDS_AUTHORIZED_MAX");

    return options.adapter.pay(request, maxAmount);
  }

  return {
    /** Entry point. Shape matches an HTTP handler: body + headers. */
    async handle(body: unknown, headers: Record<string, string | string[] | undefined>): Promise<ExecutorResponse> {
      return protectUpstreamExecution(body, headers, { expectedToken: options.internalToken, execute });
    },
  };
}

export type PaymentExecutor = ReturnType<typeof createPaymentExecutor>;

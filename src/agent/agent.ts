// SPDX-License-Identifier: MIT
/**
 * Minimal agent-side interface.
 *
 * `AgentGatewayClient` is everything the agent is given. It has no executor,
 * no payment adapter, no internal executor token, and no signing key. The
 * agent cannot pay; it can only ask the gateway to execute a request that the
 * authorization service has signed.
 */
import type { AuthorizationV1 } from "@oxdeai/core";
import type { IntentRef, PurchaseRequest } from "./purchase-request.ts";

export type QuoteInput = Pick<PurchaseRequest, "service_id" | "method" | "url" | "body">;

export type QuoteView = { readonly network: string; readonly asset: string; readonly pay_to: string; readonly amount: string };

export type AuthorizeResult =
  | { readonly decision: "ALLOW"; readonly authorization: AuthorizationV1; readonly intent_ref: IntentRef }
  | { readonly decision: "DENY"; readonly reasons: readonly string[] };

/**
 * DENY: nothing was signed. ALLOW: verified settled payment.
 * INDETERMINATE: a payment may have occurred; `executed` is "unknown". Do not
 * retry; the operator reconciles it by `intent_hash`.
 */
export type PurchaseResult = {
  readonly decision: "ALLOW" | "DENY" | "INDETERMINATE";
  readonly executed: boolean | "unknown";
  readonly status: number;
  readonly reason?: string;
  /** Executor reason when reason is UPSTREAM_ERROR or PAYMENT_UNKNOWN. */
  readonly detail?: string;
  readonly receipt?: unknown;
  readonly auth_id?: string;
  readonly intent_hash?: string;
};

export interface AgentGatewayClient {
  /** Read-only 402 quote. Never signs or pays. */
  quote(request: QuoteInput): Promise<QuoteView>;
  /** Ask the authorization service (PDP) for a signed authorization. */
  authorize(request: PurchaseRequest): Promise<AuthorizeResult>;
  /** Present request + authorization to the gateway (PEP) for execution. */
  purchase(input: { request: PurchaseRequest; intent_ref: IntentRef; authorization: AuthorizationV1 }): Promise<PurchaseResult>;
}

export type PurchaseOutcome =
  | { readonly stage: "authorize"; readonly decision: "DENY"; readonly reasons: readonly string[] }
  | { readonly stage: "purchase"; readonly result: PurchaseResult };

/** Quote -> authorize exactly the quoted price -> purchase. */
export function createPurchaseAgent(client: AgentGatewayClient) {
  return {
    async buy(draft: QuoteInput): Promise<PurchaseOutcome> {
      const quote = await client.quote(draft);
      const request: PurchaseRequest = {
        ...draft,
        network: quote.network,
        asset: quote.asset,
        recipient: quote.pay_to.toLowerCase(),
        max_amount: quote.amount,
      };
      const auth = await client.authorize(request);
      if (auth.decision !== "ALLOW") return { stage: "authorize", decision: "DENY", reasons: auth.reasons };
      const result = await client.purchase({ request, intent_ref: auth.intent_ref, authorization: auth.authorization });
      return { stage: "purchase", result };
    },
  };
}

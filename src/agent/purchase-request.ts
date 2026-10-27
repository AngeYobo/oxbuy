// SPDX-License-Identifier: MIT
/**
 * Agent-facing purchase request.
 *
 * This is the only shape the untrusted agent produces. It is JSON-safe on
 * purpose (no bigint, no functions) so the same value can cross a process or
 * HTTP boundary in Phase 2 without a second encoding.
 *
 * Every field is bound into the OxDeAI intent (see
 * src/authorization/intent.ts). Changing any of them after authorization
 * changes the intent hash and the gateway denies.
 */
export type HttpMethod = "GET" | "POST";

export type PurchaseRequest = {
  /** Deployer-known service identifier (e.g. a gateway catalog entry). */
  readonly service_id: string;
  /** Exact HTTP method of the paid request. */
  readonly method: HttpMethod;
  /** Exact absolute https URL of the paid request, including query. */
  readonly url: string;
  /** Exact request body as sent on the wire, or null for no body. */
  readonly body: string | null;
  /** Settlement network identifier. */
  readonly network: string;
  /** Settlement asset identifier. */
  readonly asset: string;
  /** Payee address the x402 challenge must name. */
  readonly recipient: string;
  /** Maximum amount, atomic units, decimal string without sign or leading zeros. */
  readonly max_amount: string;
};

/**
 * Identity fields of a single authorization attempt. Issued by the
 * authorization service, echoed back to the gateway with the request so the
 * gateway can recompute the intent hash. They carry no authority on their own:
 * the signed AuthorizationV1 binds them.
 */
export type IntentRef = {
  readonly intent_id: string;
  readonly agent_id: string;
  /** Decimal string of the bigint intent nonce. */
  readonly nonce: string;
  /** Unix seconds. */
  readonly timestamp: number;
};

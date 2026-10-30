// SPDX-License-Identifier: MIT
/**
 * x402 protocol v2 wire format (HTTP transport), as specified in coinbase/x402
 * specs/x402-specification-v2.md, specs/transports-v2/http.md and specs/schemes/exact/scheme_exact_evm.md
 * (commit 0e6e8c55, 2026-10-15).
 *
 *   402 + PAYMENT-REQUIRED  : base64(JSON PaymentRequired)        server -> client
 *   PAYMENT-SIGNATURE       : base64(JSON PaymentPayload)         client -> server
 *   PAYMENT-RESPONSE        : base64(JSON SettleResponse)         server -> client
 *
 * Parsing is strict: anything malformed throws X402_MALFORMED:*. Parsed values carry no authority;
 * the executor checks every field against the OxDeAI authorization before signing.
 */

export const HEADER_PAYMENT_REQUIRED = "payment-required";
export const HEADER_PAYMENT_SIGNATURE = "payment-signature";
export const HEADER_PAYMENT_RESPONSE = "payment-response";

export type PaymentRequirements = {
  readonly scheme: string;
  readonly network: string;
  /** Atomic units, decimal string. */
  readonly amount: string;
  readonly asset: string;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
  readonly extra?: Readonly<Record<string, unknown>>;
};

export type ResourceInfo = { readonly url: string; readonly description?: string; readonly mimeType?: string };

export type PaymentRequired = {
  readonly x402Version: 2;
  readonly error?: string;
  readonly resource: ResourceInfo;
  readonly accepts: readonly PaymentRequirements[];
  readonly extensions?: Readonly<Record<string, unknown>>;
};

export type Eip3009Authorization = {
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
};

export type PaymentPayload = {
  readonly x402Version: 2;
  readonly resource?: ResourceInfo;
  readonly accepted: PaymentRequirements;
  readonly payload: { readonly signature: string; readonly authorization: Eip3009Authorization };
  readonly extensions?: Readonly<Record<string, unknown>>;
};

export type SettleResponse = {
  readonly success: boolean;
  readonly errorReason?: string;
  readonly payer?: string;
  /** Empty string when nothing was broadcast. */
  readonly transaction: string;
  readonly network: string;
  readonly amount?: string;
};

export type VerifyResponse = { readonly isValid: boolean; readonly invalidReason?: string; readonly payer?: string };

const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;

function fail(what: string): never {
  throw new Error(`X402_MALFORMED:${what}`);
}
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown, what: string): string => (typeof v === "string" ? v : fail(what));

export function encodeHeader(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

export function decodeHeader(value: string | null | undefined, what: string): unknown {
  if (typeof value !== "string" || value === "" || value.length > 64 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) fail(`${what}:encoding`);
  try {
    return JSON.parse(Buffer.from(value, "base64").toString("utf8"));
  } catch {
    return fail(`${what}:json`);
  }
}

export function parseRequirements(v: unknown, what = "requirements"): PaymentRequirements {
  if (!isObj(v)) fail(what);
  const amount = str(v.amount, `${what}.amount`);
  if (!DECIMAL.test(amount)) fail(`${what}.amount`);
  const mts = v.maxTimeoutSeconds;
  if (typeof mts !== "number" || !Number.isSafeInteger(mts) || mts <= 0) fail(`${what}.maxTimeoutSeconds`);
  if (v.extra !== undefined && !isObj(v.extra)) fail(`${what}.extra`);
  return {
    scheme: str(v.scheme, `${what}.scheme`),
    network: str(v.network, `${what}.network`),
    amount,
    asset: str(v.asset, `${what}.asset`),
    payTo: str(v.payTo, `${what}.payTo`),
    maxTimeoutSeconds: mts,
    ...(v.extra !== undefined ? { extra: v.extra as Record<string, unknown> } : {}),
  };
}

export function parsePaymentRequired(header: string | null | undefined): PaymentRequired {
  const v = decodeHeader(header, "PAYMENT-REQUIRED");
  if (!isObj(v) || v.x402Version !== 2) fail("PAYMENT-REQUIRED.x402Version");
  if (!isObj(v.resource)) fail("PAYMENT-REQUIRED.resource");
  if (!Array.isArray(v.accepts) || v.accepts.length === 0 || v.accepts.length > 32) fail("PAYMENT-REQUIRED.accepts");
  return {
    x402Version: 2,
    ...(typeof v.error === "string" ? { error: v.error } : {}),
    resource: { url: str(v.resource.url, "PAYMENT-REQUIRED.resource.url") },
    accepts: v.accepts.map((a, i) => parseRequirements(a, `accepts[${i}]`)),
    ...(isObj(v.extensions) ? { extensions: v.extensions } : {}),
  };
}

export function parsePaymentPayload(header: string | null | undefined): PaymentPayload {
  const v = decodeHeader(header, "PAYMENT-SIGNATURE");
  if (!isObj(v) || v.x402Version !== 2) fail("PAYMENT-SIGNATURE.x402Version");
  if (!isObj(v.payload) || !isObj(v.payload.authorization)) fail("PAYMENT-SIGNATURE.payload");
  const a = v.payload.authorization;
  const auth: Eip3009Authorization = {
    from: str(a.from, "authorization.from"),
    to: str(a.to, "authorization.to"),
    value: str(a.value, "authorization.value"),
    validAfter: str(a.validAfter, "authorization.validAfter"),
    validBefore: str(a.validBefore, "authorization.validBefore"),
    nonce: str(a.nonce, "authorization.nonce"),
  };
  for (const k of ["value", "validAfter", "validBefore"] as const) if (!DECIMAL.test(auth[k])) fail(`authorization.${k}`);
  return {
    x402Version: 2,
    ...(isObj(v.resource) ? { resource: { url: str(v.resource.url, "resource.url") } } : {}),
    accepted: parseRequirements(v.accepted, "accepted"),
    payload: { signature: str(v.payload.signature, "payload.signature"), authorization: auth },
  };
}

export function parseSettleResponse(v: unknown, what = "PAYMENT-RESPONSE"): SettleResponse {
  if (!isObj(v) || typeof v.success !== "boolean") fail(`${what}.success`);
  if (typeof v.transaction !== "string") fail(`${what}.transaction`);
  return {
    success: v.success,
    ...(typeof v.errorReason === "string" ? { errorReason: v.errorReason } : {}),
    ...(typeof v.payer === "string" ? { payer: v.payer } : {}),
    transaction: v.transaction,
    network: str(v.network, `${what}.network`),
    ...(typeof v.amount === "string" ? { amount: v.amount } : {}),
  };
}

export function parseVerifyResponse(v: unknown): VerifyResponse {
  if (!isObj(v) || typeof v.isValid !== "boolean") fail("verify.isValid");
  return {
    isValid: v.isValid,
    ...(typeof v.invalidReason === "string" ? { invalidReason: v.invalidReason } : {}),
    ...(typeof v.payer === "string" ? { payer: v.payer } : {}),
  };
}

// ── x402 v1 (coinbase/x402 specs/x402-specification-v1.md, transports-v1/http.md) ──────────────────────
// 402 body: { x402Version: 1, error, accepts: [{ scheme, network, maxAmountRequired, asset, payTo, resource,
// description, mimeType?, outputSchema?, maxTimeoutSeconds, extra? }] }; payment in X-PAYMENT (base64 JSON
// { x402Version: 1, scheme, network, payload }); settlement in X-PAYMENT-RESPONSE. Used by the Celo buy gateway.

export const HEADER_X_PAYMENT = "x-payment";
export const HEADER_X_PAYMENT_RESPONSE = "x-payment-response";

/** v1 network names -> CAIP-2 (only Celo; anything else stays unmatchable). */
export const V1_NETWORKS: Readonly<Record<string, string>> = Object.freeze({ celo: "eip155:42220", "celo-sepolia": "eip155:11142220" });
export const v1NetworkToCaip2 = (n: string): string => V1_NETWORKS[n] ?? `x402v1:${n}`;

export type V1Offer = { readonly requirements: PaymentRequirements; readonly resource: string; readonly wireNetwork: string };

export function parsePaymentRequiredV1(body: unknown): V1Offer[] {
  if (!isObj(body) || body.x402Version !== 1) fail("v1.x402Version");
  if (!Array.isArray(body.accepts) || body.accepts.length === 0 || body.accepts.length > 32) fail("v1.accepts");
  return body.accepts.map((a, i) => {
    if (!isObj(a)) fail(`v1.accepts[${i}]`);
    const wireNetwork = str(a.network, `v1.accepts[${i}].network`);
    const requirements = parseRequirements({ ...a, amount: a.maxAmountRequired, network: v1NetworkToCaip2(wireNetwork) }, `v1.accepts[${i}]`);
    return { requirements, resource: str(a.resource, `v1.accepts[${i}].resource`), wireNetwork };
  });
}

export type PaymentPayloadV1 = {
  readonly x402Version: 1;
  readonly scheme: string;
  readonly network: string;
  readonly payload: { readonly signature: string; readonly authorization: Eip3009Authorization };
};

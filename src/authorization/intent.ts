// SPDX-License-Identifier: MIT
/**
 * Deterministic mapping PurchaseRequest + IntentRef -> OxDeAI Intent.
 *
 * Used by BOTH the authorization service (to evaluate) and the gateway (to
 * recompute `intent_hash` from what is actually presented for execution).
 * Because the two sides share one function, any byte-level change to the
 * method, URL, body, network, asset, recipient, or max amount produces a
 * different `metadata_hash`, therefore a different `intentHash()`, and the
 * gateway rejects with INTENT_HASH_MISMATCH.
 *
 * Validation is strict and throws on anything unexpected; the gateway turns
 * a throw into DENY (ACTION_CANONICALIZATION_FAILED).
 */
import { createHash } from "node:crypto";
import { intentHash, sha256HexFromJson, type Intent } from "@oxdeai/core";
import type { IntentRef, PurchaseRequest } from "../agent/purchase-request.ts";

export class RequestValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestValidationError";
  }
}

const REQUEST_KEYS = ["asset", "body", "max_amount", "method", "network", "recipient", "service_id", "url"];
const INTENT_REF_KEYS = ["agent_id", "intent_id", "nonce", "timestamp"];
const ATOMIC_AMOUNT = /^[1-9][0-9]{0,30}$/;
const DECIMAL_NONCE = /^(0|[1-9][0-9]{0,38})$/;
const IDENTIFIER = /^[A-Za-z0-9._:\-]{1,128}$/;

function fail(message: string): never {
  throw new RequestValidationError(message);
}

function assertExactKeys(value: unknown, keys: readonly string[], name: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`${name} must be an object`);
  const actual = Object.keys(value).sort();
  if (actual.length !== keys.length || actual.some((k, i) => k !== keys[i])) {
    fail(`${name} must have exactly the keys ${keys.join(",")}`);
  }
}

function assertIdentifier(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) fail(`${name} is not a valid identifier`);
}

export function validatePurchaseRequest(value: unknown): PurchaseRequest {
  assertExactKeys(value, REQUEST_KEYS, "request");
  const { service_id, method, url, body, network, asset, recipient, max_amount } = value;
  assertIdentifier(service_id, "service_id");
  if (method !== "GET" && method !== "POST") fail("method must be GET or POST");
  if (typeof url !== "string") fail("url must be a string");
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    fail("url is not a valid absolute URL");
  }
  if (parsed.protocol !== "https:") fail("url must use https");
  if (parsed.username !== "" || parsed.password !== "") fail("url must not carry credentials");
  if (parsed.hash !== "") fail("url must not carry a fragment");
  // Require the canonical serialization so two spellings of one URL cannot
  // produce two different authorizations for the same resource.
  if (parsed.href !== url) fail("url must be in canonical form");
  if (body !== null && typeof body !== "string") fail("body must be a string or null");
  if (method === "GET" && body !== null) fail("GET requests must not carry a body");
  assertIdentifier(network, "network");
  assertIdentifier(asset, "asset");
  // Lower-case only, so checksum casing is not a second spelling of one payee.
  if (typeof recipient !== "string" || !/^0x[0-9a-f]{40}$/.test(recipient)) fail("recipient must be a lower-case 20-byte hex address");
  if (typeof max_amount !== "string" || !ATOMIC_AMOUNT.test(max_amount)) fail("max_amount must be a positive atomic-unit decimal string");
  return { service_id, method, url, body, network, asset, recipient, max_amount };
}

export function validateIntentRef(value: unknown): IntentRef {
  assertExactKeys(value, INTENT_REF_KEYS, "intent_ref");
  const { intent_id, agent_id, nonce, timestamp } = value;
  assertIdentifier(intent_id, "intent_id");
  assertIdentifier(agent_id, "agent_id");
  if (typeof nonce !== "string" || !DECIMAL_NONCE.test(nonce)) fail("nonce must be a decimal string");
  if (typeof timestamp !== "number" || !Number.isSafeInteger(timestamp) || timestamp < 0) fail("timestamp must be unix seconds");
  return { intent_id, agent_id, nonce, timestamp };
}

/** SHA-256 of the exact body bytes (UTF-8), or null when there is no body. */
export function bodySha256(body: string | null): string | null {
  return body === null ? null : createHash("sha256").update(body, "utf8").digest("hex");
}

/** Canonical payment binding committed into `Intent.metadata_hash`. */
export function paymentBinding(request: PurchaseRequest): Record<string, unknown> {
  return {
    schema: "oxdeai-celo-poc/x402-purchase/v1",
    service_id: request.service_id,
    method: request.method,
    url: request.url,
    body_sha256: bodySha256(request.body),
    network: request.network,
    asset: request.asset,
    recipient: request.recipient,
    max_amount: request.max_amount,
  };
}

/**
 * Policy target: one (network, recipient, service URL without query) tuple.
 * The allowlist is matched on the complete tuple, so an allowed recipient
 * cannot be paired with a different service, and vice versa.
 */
export function paymentTarget(request: PurchaseRequest): string {
  const u = new URL(request.url);
  return `x402:${request.network}:${request.recipient}@${u.origin}${u.pathname}`;
}

export function buildPaymentIntent(request: PurchaseRequest, ref: IntentRef): Intent {
  return {
    type: "EXECUTE",
    intent_id: ref.intent_id,
    agent_id: ref.agent_id,
    action_type: "PAYMENT",
    depth: 0,
    amount: BigInt(request.max_amount),
    asset: request.asset,
    target: paymentTarget(request),
    timestamp: ref.timestamp,
    metadata_hash: sha256HexFromJson(paymentBinding(request)),
    nonce: BigInt(ref.nonce),
    tool: "x402_purchase",
    tool_call: true,
    // Required by the Intent type; PolicyEngine does not verify it.
    signature: "unsigned",
  };
}

/** Gateway-side action envelope: what the agent presents for execution. */
export type GatewayAction = {
  readonly request: PurchaseRequest;
  readonly intent_ref: IntentRef;
};

/**
 * `hashAction` for createPepGatewayExecutor: validate the presented action
 * and recompute the OxDeAI intent hash from it. Throws on invalid input.
 */
export function hashGatewayAction(action: unknown): string {
  assertExactKeys(action, ["intent_ref", "request"], "action");
  const request = validatePurchaseRequest(action.request);
  const ref = validateIntentRef(action.intent_ref);
  return intentHash(buildPaymentIntent(request, ref));
}

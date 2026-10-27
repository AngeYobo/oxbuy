// SPDX-License-Identifier: MIT
/** T5 expiry, T6 replay, T7 invalid signature, plus missing authorization. */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { signAuthorizationEd25519, type AuthorizationV1 } from "@oxdeai/core";
import { POLICY } from "../../src/system.ts";
import { assertNoPayment, authorize, newSystem, requestFor, SERVICES } from "../helpers.ts";

// ── T5 expired authorization ────────────────────────────────────────────────

test("T5 expired authorization: AUTH_EXPIRED, no payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  sys.harness.clock.advance(POLICY.ttlSeconds + 1);
  const result = await sys.client.purchase(auth);
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /AUTH_EXPIRED/);
  assertNoPayment(sys);
});

test("T5 authorization at exact expiry second: DENY (exclusive bound)", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  sys.harness.clock.advance(POLICY.ttlSeconds);
  const result = await sys.client.purchase(auth);
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /AUTH_EXPIRED/);
  assertNoPayment(sys);
});

// ── T6 replay ───────────────────────────────────────────────────────────────

test("T6 replayed authorization: second use AUTH_REPLAY, exactly one payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const first = await sys.client.purchase(auth);
  assert.equal(first.decision, "ALLOW");
  const second = await sys.client.purchase(auth);
  assert.equal(second.decision, "DENY");
  assert.equal(second.reason, "AUTH_REPLAY");
  assert.equal(sys.harness.mockBuy.counters.payments, 1);
});

test("T6 concurrent replay: exactly one of two simultaneous submissions executes", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const results = await Promise.all([sys.client.purchase(auth), sys.client.purchase(auth)]);
  assert.deepEqual(results.map((r) => r.decision).sort(), ["ALLOW", "DENY"]);
  assert.equal(sys.harness.mockBuy.counters.payments, 1);
});

// ── T7 invalid signature ────────────────────────────────────────────────────

function withSignature(auth: AuthorizationV1, mutate: (sig: string) => string): AuthorizationV1 {
  if (typeof auth.signature === "string") return { ...auth, signature: mutate(auth.signature) };
  return { ...auth, signature: { ...auth.signature, sig: mutate(auth.signature.sig) } };
}

function flipFirstChar(s: string): string {
  return (s[0] === "A" ? "B" : "A") + s.slice(1);
}

test("T7a corrupted signature bytes: AUTH_SIGNATURE_INVALID, no payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const result = await sys.client.purchase({ ...auth, authorization: withSignature(auth.authorization, flipFirstChar) });
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /AUTH_SIGNATURE_INVALID/);
  assertNoPayment(sys);
});

test("T7b signed field changed without re-signing (expiry extended): AUTH_SIGNATURE_INVALID", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const forged = { ...auth.authorization, expiry: auth.authorization.expiry + 3600 };
  const result = await sys.client.purchase({ ...auth, authorization: forged });
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /AUTH_SIGNATURE_INVALID/);
  assertNoPayment(sys);
});

test("T7c authorization signed by an untrusted key claiming the trusted issuer and kid: DENY", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const { privateKey } = generateKeyPairSync("ed25519");
  const attackerPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const { signature: _drop, ...unsigned } = auth.authorization;
  const forged = signAuthorizationEd25519({ ...unsigned, alg: "Ed25519" }, attackerPem);
  const result = await sys.client.purchase({ ...auth, authorization: forged });
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /AUTH_SIGNATURE_INVALID/);
  assertNoPayment(sys);
});

test("T7d self-issued authorization for an arbitrary request (attacker key, own hash): DENY", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  // Attacker computes a correct intent_hash for a request the PDP never approved.
  const { hashGatewayAction } = await import("../../src/authorization/intent.ts");
  const evil = requestFor(SERVICES.unlisted);
  const { privateKey } = generateKeyPairSync("ed25519");
  const { signature: _drop, ...unsigned } = auth.authorization;
  const forged = signAuthorizationEd25519(
    { ...unsigned, alg: "Ed25519", auth_id: "forged-1", intent_hash: hashGatewayAction({ request: evil, intent_ref: auth.intent_ref }) },
    privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  );
  const result = await sys.client.purchase({ request: evil, intent_ref: auth.intent_ref, authorization: forged });
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /AUTH_SIGNATURE_INVALID/);
  assertNoPayment(sys);
});

test("T7e wrong audience (field rewritten): DENY", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const result = await sys.client.purchase({ ...auth, authorization: { ...auth.authorization, audience: "other-gateway" } });
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /AUTH_AUDIENCE_MISMATCH/);
  assertNoPayment(sys);
});

// ── missing authorization ───────────────────────────────────────────────────

test("missing authorization: INVALID_REQUEST, no payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const result = await sys.client.purchase({ ...auth, authorization: undefined as unknown as AuthorizationV1 });
  assert.equal(result.decision, "DENY");
  assert.equal(result.reason, "INVALID_REQUEST");
  assertNoPayment(sys);
});

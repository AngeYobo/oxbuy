// SPDX-License-Identifier: MIT
/** T9 direct executor bypass, T10 no payment after any DENY. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import { createLocalSystem, POLICY } from "../../src/system.ts";
import { assertNoPayment, authorize, newSystem, requestFor, SERVICES } from "../helpers.ts";

// ── T9 direct executor bypass ───────────────────────────────────────────────

test("T9a agent client exposes no executor, adapter, token, or signing material", () => {
  const sys = newSystem();
  assert.deepEqual(Object.keys(sys.client).sort(), ["authorize", "purchase", "quote"]);
  assert.ok(Object.isFrozen(sys.client));
  const serialized = JSON.stringify(sys.client, (_k, v) => (typeof v === "function" ? v.toString() : v));
  assert.doesNotMatch(serialized, /PRIVATE KEY/);
  // Public trust material handed to the gateway carries no private key.
  assert.doesNotMatch(JSON.stringify(sys.harness.authService.trustMaterial), /PRIVATE KEY/);
});

test("T9b direct executor call without internal token: 403, no payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const res = await sys.harness.executor.handle({ request: auth.request, intent_ref: auth.intent_ref }, {});
  assert.equal(res.status, 403);
  assert.equal(res.executed, false);
  assertNoPayment(sys);
});

test("T9c direct executor call with forged token: 403, no payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const res = await sys.harness.executor.handle(
    { request: auth.request, intent_ref: auth.intent_ref },
    { [INTERNAL_EXECUTOR_TOKEN_HEADER]: "0".repeat(64) },
  );
  assert.equal(res.status, 403);
  assertNoPayment(sys);
});

test("T9d direct executor call with a token header given twice: 403", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const res = await sys.harness.executor.handle(
    { request: auth.request, intent_ref: auth.intent_ref },
    { [INTERNAL_EXECUTOR_TOKEN_HEADER]: ["a", "b"] },
  );
  assert.equal(res.status, 403);
  assertNoPayment(sys);
});

test("T9e authorization from one system instance is rejected by another (different trust root)", async () => {
  const a = newSystem();
  const b = newSystem();
  const auth = await authorize(a, requestFor(SERVICES.weather));
  const result = await b.client.purchase(auth);
  assert.equal(result.decision, "DENY");
  assertNoPayment(b);
});

// ── T10 no mock payment after any DENY ──────────────────────────────────────

test("T10 across every DENY path, the mock buy adapter never signs or pays", async () => {
  const sys = createLocalSystem();
  const denies: string[] = [];
  const record = (label: string, r: { decision: string }) => {
    assert.equal(r.decision, "DENY", label);
    denies.push(label);
  };

  record("unlisted service", await sys.client.authorize(requestFor(SERVICES.unlisted)));
  record("over cap", await sys.client.authorize(requestFor(SERVICES.premium)));

  const tampered = await authorize(sys, requestFor(SERVICES.weather));
  record("tampered body", await sys.client.purchase({ ...tampered, request: { ...tampered.request, body: "{}" } }));

  const forged = await authorize(sys, requestFor(SERVICES.weather));
  record("forged expiry", await sys.client.purchase({ ...forged, authorization: { ...forged.authorization, expiry: 1 } }));

  const expired = await authorize(sys, requestFor(SERVICES.weather));
  sys.harness.clock.advance(POLICY.ttlSeconds + 1);
  record("expired", await sys.client.purchase(expired));

  const noRef = await authorize(sys, requestFor(SERVICES.weather));
  record("missing intent_ref", await sys.client.purchase({ ...noRef, intent_ref: undefined as never }));

  sys.harness.policyStore.setAvailable(false);
  record("state unavailable", await sys.client.authorize(requestFor(SERVICES.weather)));

  assert.equal(denies.length, 7);
  assertNoPayment(sys);
});

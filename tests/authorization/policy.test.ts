// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { test } from "node:test";
import { createLocalSystem } from "../../src/system.ts";
import { assertNoPayment, authorize, newSystem, requestFor, SERVICES } from "../helpers.ts";

function assertDeny(result: { decision: string; reasons?: readonly string[] }, reason: RegExp): void {
  assert.equal(result.decision, "DENY");
  const reasons = result.reasons ?? [];
  assert.ok(reasons.some((r) => reason.test(r)), `expected ${reason}, got ${JSON.stringify(reasons)}`);
}

// ── T2 unauthorized service or recipient ─────────────────────────────────────

test("T2a unauthorized service: PDP DENY (ALLOWLIST_TARGET), no payment", async () => {
  const sys = newSystem();
  assertDeny(await sys.client.authorize(requestFor(SERVICES.unlisted)), /^ALLOWLIST_TARGET$/);
  assertNoPayment(sys);
});

test("T2b allowed service with substituted recipient: PDP DENY, no payment", async () => {
  const sys = newSystem();
  const request = requestFor(SERVICES.weather, { recipient: SERVICES.unlisted.pay_to });
  assertDeny(await sys.client.authorize(request), /^ALLOWLIST_TARGET$/);
  assertNoPayment(sys);
});

test("T2c unauthorized asset: PDP DENY (ALLOWLIST_ASSET), no payment", async () => {
  const sys = newSystem();
  assertDeny(await sys.client.authorize(requestFor(SERVICES.weather, { asset: "other-token" })), /^ALLOWLIST_ASSET$/);
  assertNoPayment(sys);
});

test("T2d upstream 402 names a different payee after authorization: executor refuses, no payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  sys.harness.mockBuy.setPayTo(SERVICES.weather.service_id, SERVICES.unlisted.pay_to);
  const result = await sys.client.purchase(auth);
  assert.equal(result.decision, "DENY");
  assert.equal(result.executed, false);
  assert.equal(result.reason, "UPSTREAM_ERROR");
  assert.equal(result.detail, "EXECUTOR_QUOTE_RECIPIENT_MISMATCH");
  assertNoPayment(sys);
});

// ── T3 amount above approved maximum ────────────────────────────────────────

test("T3a amount above per-action policy cap: PDP DENY, no payment", async () => {
  const sys = newSystem();
  assertDeny(await sys.client.authorize(requestFor(SERVICES.premium)), /^PER_ACTION_CAP_EXCEEDED$/);
  assertNoPayment(sys);
});

test("T3b cumulative budget exhausted: PDP DENY after budget is spent", async () => {
  const sys = newSystem();
  // Budget 50_000, per-action 20_000: five 10_000 authorizations fit, the sixth does not.
  for (let i = 0; i < 5; i++) {
    await authorize(sys, requestFor(SERVICES.weather, { url: `${SERVICES.weather.resource}?i=${i}` }));
  }
  assertDeny(await sys.client.authorize(requestFor(SERVICES.weather)), /^BUDGET_EXCEEDED$/);
  assertNoPayment(sys);
});

test("T3c live price rises above authorized max_amount: executor refuses before signing", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  sys.harness.mockBuy.setPrice(SERVICES.weather.service_id, 10_001n);
  const result = await sys.client.purchase(auth);
  assert.equal(result.decision, "DENY");
  assert.equal(result.executed, false);
  assert.equal(result.detail, "EXECUTOR_QUOTE_EXCEEDS_AUTHORIZED_MAX");
  assertNoPayment(sys);
});

// ── T8 missing or unavailable authorization state ───────────────────────────

test("T8a missing policy state: PDP DENY, no authorization issued", async () => {
  const sys = createLocalSystem({ initialState: null });
  assertDeny(await sys.client.authorize(requestFor(SERVICES.weather)), /^POLICY_STATE_UNAVAILABLE:POLICY_STATE_MISSING$/);
  assertNoPayment(sys);
});

test("T8b unavailable policy state backend: PDP DENY", async () => {
  const sys = newSystem();
  sys.harness.policyStore.setAvailable(false);
  assertDeny(await sys.client.authorize(requestFor(SERVICES.weather)), /^POLICY_STATE_UNAVAILABLE/);
  assertNoPayment(sys);
});

test("T8c structurally invalid policy state: engine DENY (STATE_INVALID)", async () => {
  const sys = newSystem();
  const broken = structuredClone(await sys.harness.policyStore.load()).state as unknown as Record<string, unknown>;
  delete broken.budget;
  const store = sys.harness.policyStore;
  const v = (await store.load()).version;
  assert.equal(await store.commit(broken as never, v), true);
  assertDeny(await sys.client.authorize(requestFor(SERVICES.weather)), /STATE_INVALID/);
  assertNoPayment(sys);
});

test("T8d replay store unavailable at the gateway: DENY, no payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  sys.harness.replayStore.setAvailable(false);
  const result = await sys.client.purchase(auth);
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /^REPLAY_STORE_UNAVAILABLE/);
  assertNoPayment(sys);
});

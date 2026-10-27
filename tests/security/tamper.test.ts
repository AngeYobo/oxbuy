// SPDX-License-Identifier: MIT
/** T4: any change to the authorized request after authorization is DENY. */
import assert from "node:assert/strict";
import { test } from "node:test";
import type { PurchaseRequest } from "../../src/agent/purchase-request.ts";
import { assertNoPayment, authorize, newSystem, requestFor, SERVICES } from "../helpers.ts";

const MUTATIONS: Array<[string, Partial<PurchaseRequest>]> = [
  ["body", { body: JSON.stringify({ units: "metric", days: 30 }) }],
  ["body whitespace only", { body: JSON.stringify({ units: "metric", days: 3 }, null, 1) }],
  ["url query", { url: `${SERVICES.weather.resource}?city=paris` }],
  ["url path", { url: `${SERVICES.premium.resource}?city=lagos` }],
  ["method", { method: "GET", body: null }],
  ["recipient", { recipient: SERVICES.unlisted.pay_to }],
  ["max_amount raised", { max_amount: "19999" }],
  ["max_amount lowered", { max_amount: "9999" }],
  ["network", { network: "other-network" }],
  ["asset", { asset: "other-token" }],
  ["service_id", { service_id: SERVICES.premium.service_id }],
];

for (const [name, change] of MUTATIONS) {
  test(`T4 request modified after authorization (${name}): INTENT_HASH_MISMATCH, no payment`, async () => {
    const sys = newSystem();
    const auth = await authorize(sys, requestFor(SERVICES.weather));
    const result = await sys.client.purchase({ ...auth, request: { ...auth.request, ...change } });
    assert.equal(result.decision, "DENY");
    assert.equal(result.executed, false);
    assert.equal(result.reason, "INTENT_HASH_MISMATCH");
    assertNoPayment(sys);
  });
}

test("T4 intent_ref modified after authorization (nonce): INTENT_HASH_MISMATCH", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const result = await sys.client.purchase({ ...auth, intent_ref: { ...auth.intent_ref, nonce: "1" } });
  assert.equal(result.reason, "INTENT_HASH_MISMATCH");
  assertNoPayment(sys);
});

test("T4 non-canonical / malformed request at the gateway: DENY before hashing completes", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const extraField = { ...auth.request, extra: "x" } as unknown as PurchaseRequest;
  const result = await sys.client.purchase({ ...auth, request: extraField });
  assert.equal(result.decision, "DENY");
  assert.match(result.reason ?? "", /^ACTION_CANONICALIZATION_FAILED/);
  assertNoPayment(sys);
});

test("T4 caller mutates its request object after submit: executed request is the hashed one", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const mutable = { ...auth.request } as { -readonly [K in keyof PurchaseRequest]: PurchaseRequest[K] };
  const pending = sys.client.purchase({ ...auth, request: mutable });
  // Runs while the gateway awaits the replay store.
  mutable.recipient = SERVICES.unlisted.pay_to;
  mutable.max_amount = "19999";
  const result = await pending;
  assert.equal(result.decision, "ALLOW");
  const receipt = result.receipt as { pay_to: string; amount: string };
  assert.equal(receipt.pay_to, SERVICES.weather.pay_to);
  assert.equal(receipt.amount, "10000");
});

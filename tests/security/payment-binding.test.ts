// SPDX-License-Identifier: MIT
/** R-F1: the authorized binding is enforced at the point of payment, not only at quote. */
import assert from "node:assert/strict";
import { test } from "node:test";
import type { AuthorizedPayment, PaymentAdapter } from "../../src/executor/payment-adapter.ts";
import type { MockBuy } from "../../src/adapters/mock-buy/mock-buy.ts";
import { createLocalSystem } from "../../src/system.ts";
import { assertNoPayment, authorize, requestFor, SERVICES } from "../helpers.ts";

/** Executor adapter whose upstream 402 changes right after the executor's quote. */
function changeAfterQuote(change: (mock: MockBuy["inspect"]) => void) {
  return (inner: PaymentAdapter, mock: MockBuy["inspect"]): PaymentAdapter => ({
    async quote(request) {
      const quote = await inner.quote(request);
      change(mock);
      return quote;
    },
    pay: (payment) => inner.pay(payment),
  });
}

const QUOTE_THEN_PAY_CHANGES: Array<[string, (mock: MockBuy["inspect"]) => void, string]> = [
  ["recipient", (m) => m.setPayTo(SERVICES.weather.service_id, SERVICES.unlisted.pay_to), "MOCK_BUY_RECIPIENT_MISMATCH"],
  ["network", (m) => m.setNetwork(SERVICES.weather.service_id, "other-network"), "MOCK_BUY_NETWORK_MISMATCH"],
  ["asset", (m) => m.setAsset(SERVICES.weather.service_id, "other-token"), "MOCK_BUY_ASSET_MISMATCH"],
  ["price", (m) => m.setPrice(SERVICES.weather.service_id, 10_001n), "MOCK_BUY_PRICE_EXCEEDS_MAX_AMOUNT"],
];

for (const [name, change, detail] of QUOTE_THEN_PAY_CHANGES) {
  test(`R-F1a ${name} changes between executor quote and pay: refused before signing, DENY, no payment`, async () => {
    const sys = createLocalSystem({ faults: { wrapAdapter: changeAfterQuote(change) } });
    const auth = await authorize(sys, requestFor(SERVICES.weather));
    const result = await sys.client.purchase(auth);
    assert.equal(sys.harness.mockBuy.counters.quotes, 1, "executor quote passed with the original requirements");
    assert.equal(result.decision, "DENY");
    assert.equal(result.executed, false);
    assert.equal(result.detail, detail);
    assert.deepEqual(sys.harness.executor.journal.get(auth.authorization.intent_hash), {
      state: "REFUSED_BEFORE_SIGNING",
      detail,
    });
    assertNoPayment(sys);
  });
}

test("R-F1b pay receives the full authorized binding: exact request and the verified intent_hash", async () => {
  const seen: AuthorizedPayment[] = [];
  const sys = createLocalSystem({
    faults: {
      wrapAdapter: (inner) => ({
        quote: (r) => inner.quote(r),
        pay: (payment) => {
          seen.push(payment);
          return inner.pay(payment);
        },
      }),
    },
  });
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const result = await sys.client.purchase(auth);
  assert.equal(result.decision, "ALLOW");
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0], { intent_hash: auth.authorization.intent_hash, request: auth.request });
  assert.equal(result.intent_hash, auth.authorization.intent_hash);
  assert.deepEqual(sys.harness.executor.journal.get(auth.authorization.intent_hash), { state: "SETTLED" });
});

// A non-compliant adapter that pays and then reports a settlement outside the
// binding. Receipt verification DETECTS this after the fact; it does not
// prevent it (the mock ledger shows the payment happened).
const RECEIPT_VIOLATIONS: Array<[string, Record<string, unknown>, string]> = [
  ["recipient", { pay_to: SERVICES.unlisted.pay_to }, "EXECUTOR_RECEIPT_RECIPIENT_MISMATCH"],
  ["network", { network: "other-network" }, "EXECUTOR_RECEIPT_NETWORK_MISMATCH"],
  ["asset", { asset: "other-token" }, "EXECUTOR_RECEIPT_ASSET_MISMATCH"],
  ["amount", { amount: "10001" }, "EXECUTOR_RECEIPT_EXCEEDS_AUTHORIZED_MAX"],
];

for (const [name, override, detail] of RECEIPT_VIOLATIONS) {
  test(`R-F1c receipt ${name} outside the binding: INDETERMINATE (detected, not prevented), never ALLOW`, async () => {
    const sys = createLocalSystem({
      faults: {
        wrapAdapter: (inner) => ({
          quote: (r) => inner.quote(r),
          pay: async (payment) => ({ ...(await inner.pay(payment)), ...override }),
        }),
      },
    });
    const auth = await authorize(sys, requestFor(SERVICES.weather));
    const result = await sys.client.purchase(auth);
    assert.equal(result.decision, "INDETERMINATE");
    assert.equal(result.executed, "unknown");
    assert.equal(result.reason, "PAYMENT_UNKNOWN");
    assert.equal(result.detail, detail);
    assert.equal(sys.harness.mockBuy.counters.payments, 1, "the payment was not prevented");
    assert.deepEqual(sys.harness.executor.journal.get(auth.authorization.intent_hash), { state: "UNKNOWN", detail });
  });
}

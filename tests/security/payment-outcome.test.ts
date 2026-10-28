// SPDX-License-Identifier: MIT
/** R-F2: an execution that may have moved funds is never reported as DENY. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import { createMockBuyAdapter } from "../../src/adapters/mock-buy/mock-buy.ts";
import type { PaymentAdapter, PaymentReceipt } from "../../src/executor/payment-adapter.ts";
import { createPaymentExecutor } from "../../src/executor/executor.ts";
import { createInMemoryPaymentJournal } from "../../src/executor/payment-journal.ts";
import { createLocalSystem, type LocalSystemFaults } from "../../src/system.ts";
import { authorize, requestFor, SERVICES } from "../helpers.ts";

/** Executor adapter that settles through the mock, then fails in `fail`. */
function settleThen(fail: (receipt: PaymentReceipt) => Promise<unknown>): LocalSystemFaults["wrapAdapter"] {
  return (inner) => ({
    quote: (r) => inner.quote(r),
    pay: async (payment) => (await fail(await inner.pay(payment))) as PaymentReceipt,
  });
}

async function purchaseOnce(faults: LocalSystemFaults) {
  const sys = createLocalSystem({ faults });
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const result = await sys.client.purchase(auth);
  return { sys, auth, result, journal: sys.harness.executor.journal.get(auth.authorization.intent_hash) };
}

function assertIndeterminate(result: { decision: string; executed: unknown; reason?: string; status: number }) {
  assert.equal(result.decision, "INDETERMINATE");
  assert.equal(result.executed, "unknown");
  assert.equal(result.reason, "PAYMENT_UNKNOWN");
  assert.notEqual(result.status, 200);
}

test("R-F2a error after settlement (original F2 reproduction): INDETERMINATE, not DENY", async () => {
  const { sys, result, journal } = await purchaseOnce({
    wrapAdapter: settleThen(async () => {
      throw new Error("settle_uncertain");
    }),
  });
  assertIndeterminate(result);
  assert.equal(result.detail, "EXECUTOR_PAYMENT_OUTCOME_UNKNOWN:settle_uncertain");
  assert.equal(sys.harness.mockBuy.counters.payments, 1);
  assert.deepEqual(journal, { state: "UNKNOWN", detail: "settle_uncertain" });
});

test("R-F2b connection loss after submission to the payment rail: INDETERMINATE", async () => {
  const { sys, result, journal } = await purchaseOnce({
    wrapAdapter: settleThen(async () => {
      throw Object.assign(new Error("ECONNRESET"), { code: "ECONNRESET" });
    }),
  });
  assertIndeterminate(result);
  assert.equal(sys.harness.mockBuy.counters.payments, 1);
  assert.equal(journal?.state, "UNKNOWN");
});

test("R-F2c executor response lost between executor and gateway: INDETERMINATE although executor settled", async () => {
  const { sys, result, journal } = await purchaseOnce({
    wrapExecutorHandle: (inner) => async (body, headers) => {
      await inner(body, headers);
      throw new Error("socket hang up");
    },
  });
  assertIndeterminate(result);
  assert.equal(result.detail, "socket hang up");
  assert.equal(sys.harness.mockBuy.counters.payments, 1);
  assert.deepEqual(journal, { state: "SETTLED" });
});

test("R-F2d gateway timeout after pay was invoked: INDETERMINATE; journal shows STARTED, later SETTLED", async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const { sys, auth, result, journal } = await purchaseOnce({
    gatewayTimeoutMs: 20,
    wrapAdapter: (inner) => ({
      quote: (r) => inner.quote(r),
      pay: async (payment) => {
        await gate;
        return inner.pay(payment);
      },
    }),
  });
  assertIndeterminate(result);
  assert.equal(result.detail, "UPSTREAM_TIMEOUT");
  assert.equal(result.status, 504);
  assert.deepEqual(journal, { state: "STARTED" });

  release();
  await new Promise((r) => setImmediate(r));
  assert.equal(sys.harness.mockBuy.counters.payments, 1, "the payment completed after the gateway answered");
  assert.deepEqual(sys.harness.executor.journal.get(auth.authorization.intent_hash), { state: "SETTLED" });
});

test("R-F2e gateway timeout before pay was invoked: still INDETERMINATE (conservative); journal has no entry", async () => {
  const { sys, result, journal } = await purchaseOnce({
    gatewayTimeoutMs: 20,
    wrapAdapter: (inner) => ({
      quote: async (r) => {
        await new Promise((resolve) => setTimeout(resolve, 60));
        return inner.quote(r);
      },
      pay: (payment) => inner.pay(payment),
    }),
  });
  assertIndeterminate(result);
  assert.equal(journal, undefined);
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(sys.harness.mockBuy.counters.payments, 1, "late executor still pays exactly once");
});

const AMBIGUOUS: Array<[string, (r: PaymentReceipt) => unknown, string]> = [
  ["settled=false", (r) => ({ ...r, settled: false }), "EXECUTOR_RECEIPT_NOT_SETTLED"],
  ["null receipt", () => null, "EXECUTOR_RECEIPT_AMBIGUOUS"],
  ["missing reference", (r) => ({ ...r, reference: "" }), "EXECUTOR_RECEIPT_AMBIGUOUS"],
  ["non-numeric amount", (r) => ({ ...r, amount: "ten" }), "EXECUTOR_RECEIPT_AMBIGUOUS"],
];

for (const [name, mangle, detail] of AMBIGUOUS) {
  test(`R-F2f ambiguous settlement response (${name}): INDETERMINATE`, async () => {
    const { result, journal } = await purchaseOnce({ wrapAdapter: settleThen(async (r) => mangle(r)) });
    assertIndeterminate(result);
    assert.equal(result.detail, detail);
    assert.deepEqual(journal, { state: "UNKNOWN", detail });
  });
}

test("R-F2g no automatic retry: pay invoked once; resubmission after INDETERMINATE is AUTH_REPLAY", async () => {
  let payCalls = 0;
  const sys = createLocalSystem({
    faults: {
      wrapAdapter: (inner) => ({
        quote: (r) => inner.quote(r),
        pay: async (payment) => {
          payCalls += 1;
          await inner.pay(payment);
          throw new Error("settle_uncertain");
        },
      }),
    },
  });
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  assert.equal((await sys.client.purchase(auth)).decision, "INDETERMINATE");
  const again = await sys.client.purchase(auth);
  assert.equal(again.decision, "DENY");
  assert.equal(again.reason, "AUTH_REPLAY");
  assert.equal(payCalls, 1);
  assert.equal(sys.harness.mockBuy.counters.payments, 1);
});

test("R-F2h executor never hands the same intent to pay twice, even with a valid token", async () => {
  const mock = createMockBuyAdapter(Object.values(SERVICES));
  const token = "e".repeat(64);
  const sys = createLocalSystem();
  const { keySet, authority, audience } = sys.harness.authService.trustMaterial;
  const executor = createPaymentExecutor({
    internalToken: token,
    adapter: mock.adapter as PaymentAdapter,
    verification: { expectedAudience: audience, trustedKeySets: [keySet], trustedAuthorizationAuthorities: [authority], now: sys.harness.clock.now },
    journal: createInMemoryPaymentJournal(),
  });
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const body = { action: { request: auth.request, intent_ref: auth.intent_ref }, authorization: auth.authorization };
  const headers = { [INTERNAL_EXECUTOR_TOKEN_HEADER]: token };
  const first = await executor.handle(body, headers);
  const second = await executor.handle(body, headers);
  assert.equal(first.executed, true);
  assert.equal(second.executed, false);
  assert.deepEqual(second.body, { outcome: "NOT_EXECUTED", error: "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT", prior_state: "SETTLED" });
  assert.equal(mock.inspect.counters.payments, 1);
});

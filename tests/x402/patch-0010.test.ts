// SPDX-License-Identifier: MIT
/**
 * Patch 0010 regressions (security review of 0009 + R-01..R-04, 2026-10-30).
 *
 *   P10-XR01-a  EXECUTING --RESOLVED_SETTLED--> CONFIRMED: charge = settled amount, rest released; the claim and
 *               the amount bounds still apply
 *   P10-XR01-b  end to end (review ADV-1 inverted): an operator resolution recorded BEFORE any UNCERTAIN report is
 *               confirmed by the next report pass; a late UNCERTAIN afterwards changes nothing
 *   P10-XR03    the x402 adapter refuses before reading the key or signing when no durable binding store is given;
 *               nothing is transmitted, nothing is paid
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { applyClaim, applyOutcome, newReservation, type OutcomeFacts } from "../../src/authorization/reservations.ts";
import { createX402EvmAdapter } from "../../src/adapters/x402-evm/x402-evm.ts";
import { verifyOnchainSettlement } from "../../src/chain/eip3009-evidence.ts";
import { CELO_SEPOLIA } from "../../src/chain/networks.ts";
import { PaymentRefusedError } from "../../src/executor/payment-adapter.ts";
import type { PaymentPayload } from "../../src/x402/wire.ts";
import { PRICE, x402World } from "./harness.ts";

const H = "a".repeat(64);
const C = "c".repeat(32);
const D = { journal_id: "b".repeat(32), executor_uid: 1 };
const f = (outcome: OutcomeFacts["outcome"], extra: Partial<OutcomeFacts> = {}): OutcomeFacts => ({ auth_id: "A", intent_hash: H, claim_id: C, outcome, report_id: `r-${outcome}`, ...extra });

test("P10-XR01-a EXECUTING + RESOLVED_SETTLED confirms at the settled amount; claim and amount bounds still enforced", () => {
  const base = newReservation({ auth_id: "A", intent_hash: H, agent_id: "agent", domain: D, amount: "10000", expiry: 100, at: 1 });
  const claimed = applyClaim(base, { auth_id: "A", intent_hash: H, claim_id: C }, 50).next;
  assert.equal(claimed.state, "EXECUTING");
  const full = applyOutcome(claimed, f("RESOLVED_SETTLED", { amount: "10000" }), 2);
  assert.deepEqual([full.kind, full.next.state, full.release, full.next.charged], ["APPLIED", "CONFIRMED", 0n, "10000"]);
  const part = applyOutcome(claimed, f("RESOLVED_SETTLED", { amount: "6000" }), 2);
  assert.deepEqual([part.next.state, part.release, part.next.charged], ["CONFIRMED", 4000n, "6000"]);
  assert.throws(() => applyOutcome(claimed, f("RESOLVED_SETTLED", { amount: "10001" }), 2), /AMOUNT_EXCEEDS_RESERVATION/);
  assert.throws(() => applyOutcome(claimed, f("RESOLVED_SETTLED", { amount: "10", claim_id: "d".repeat(32) }), 2), /SETTLEMENT_WITHOUT_CLAIM/);
  assert.throws(() => applyOutcome(claimed, f("RESOLVED_SETTLED"), 2), /AMOUNT_INVALID/);
  // Still not a release path: a late UNCERTAIN after the confirmation moves nothing.
  assert.throws(() => applyOutcome(full.next, f("UNCERTAIN"), 3));
  assert.equal(applyOutcome(full.next, f("RESOLVED_SETTLED", { amount: "10000" }), 3).kind, "ALREADY_APPLIED");
});

test("P10-XR01-b resolution recorded before any UNCERTAIN report: confirmed by the next report pass (review ADV-1 inverted)", async () => {
  const w = await x402World({ sellerHooks: { afterSettle: () => "drop" } });
  try {
    const a = await w.authorize();
    assert.equal((await w.submit(a)).decision, "INDETERMINATE");
    assert.equal((await w.reservation(a.authorization.auth_id)).state, "EXECUTING", "no report has run (crash / stopped executor)");
    const b = w.journal.inspect(a.authorization.intent_hash)!.payment_binding!;
    const ev = await verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, {
      asset: CELO_SEPOLIA.assets[0]!.address, payer: w.payer, payTo: w.payee, nonce: w.nonceFor(a.authorization.intent_hash),
      maxAmount: PRICE, signedAmount: BigInt(b.amount), txHash: w.chain.transfers()[0]!.hash,
    });
    w.journal.resolve(a.authorization.intent_hash, ev, "operator resolves first");
    await w.report();
    const r = await w.reservation(a.authorization.auth_id);
    assert.deepEqual([r.state, r.charged], ["CONFIRMED", PRICE.toString()]);
    assert.equal(await w.spent(), PRICE);
    assert.equal(w.journal.acked(a.authorization.auth_id, "RESOLVED_SETTLED"), true);
    assert.equal(w.chain.transfers().length, 1);
    assert.equal(w.wallet.loads, 1, "signed once");
  } finally {
    await w.close();
  }
});

test("P10-XR03 no durable binding store: refused before any key read or signature; nothing transmitted or paid", async () => {
  const seen: PaymentPayload[] = [];
  const w = await x402World({ sellerHooks: { onPayment: (p) => seen.push(p) } });
  try {
    const adapter = createX402EvmAdapter(w.adapterConfig);
    const req = w.request();
    await assert.rejects(
      adapter.pay({ intent_hash: "e".repeat(64), request: req, claim_id: C, authorization_expiry: w.clock.now() + 60 }),
      (err: unknown) => err instanceof PaymentRefusedError && /X402_PAYMENT_BINDING_REQUIRED/.test((err as Error).message),
    );
    assert.equal(w.wallet.loads, 0, "the key was never read");
    assert.equal(seen.length, 0, "no signed payment left the adapter");
    assert.equal(w.facilitator.calls.settle, 0);
    assert.equal(w.chain.transfers().length, 0);
  } finally {
    await w.close();
  }
});

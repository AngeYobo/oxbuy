// SPDX-License-Identifier: MIT
/**
 * x402 / EIP-3009 testnet integration: required security tests (mandate §7), offline.
 *
 * Real components: authorization service, gateway, executor, durable journal + checkpoint, outcome
 * reporter, x402 EIP-3009 adapter, x402 seller, HTTP JSON-RPC client. Simulated: the chain and the
 * facilitator (tests/x402/sim.ts). Every test asserts the ground truth: on-chain Transfer events,
 * the number of wallet-key reads (signatures), facilitator settlements, and the budget.
 *
 * X1 valid payment · X2 missing/invalid authorization · X3 expiry · X4 recipient · X5 amount ·
 * X6 chain id / network · X7 token / contract / EIP-712 domain · X8 replay · X9 duplicate submission ·
 * X10 timeout after broadcast · X11 crash during execution (in-process part) · X12 revert and lying
 * servers · X13 restarts · X14 auth outage · X15 journal + checkpoint rollback · X16 concurrency ·
 * X17 final / non-final · X18 key hygiene
 */
import assert from "node:assert/strict";
import { cpSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import { createX402EvmAdapter } from "../../src/adapters/x402-evm/x402-evm.ts";
import { verifyOnchainSettlement } from "../../src/chain/eip3009-evidence.ts";
import { authorizedTestnet, CELO_SEPOLIA } from "../../src/chain/networks.ts";
import { createPaymentExecutor } from "../../src/executor/executor.ts";
import { openFilePaymentJournal } from "../../src/executor/payment-journal.ts";
import type { PaymentPayload } from "../../src/x402/wire.ts";
import { PRICE, x402World, type World } from "./harness.ts";

async function withWorld(fn: (w: World) => Promise<void>, o?: Parameters<typeof x402World>[0]) {
  const w = await x402World(o);
  try {
    await fn(w);
  } finally {
    await w.close();
  }
}
const nothingPaid = (w: World) => {
  assert.equal(w.chain.transfers().length, 0, "no transfer on chain");
  assert.equal(w.facilitator.calls.settle, 0, "nothing reached /settle");
};
const neverSigned = (w: World) => {
  assert.equal(w.wallet.loads, 0, "the wallet key was never read (nothing signed)");
  nothingPaid(w);
};
const setRoute = (w: World, over: Record<string, unknown>) => {
  w.seller.routes[0] = { ...w.route, requirements: { ...w.route.requirements, ...over } as never };
};

// ── X1 ─────────────────────────────────────────────────────────────────────

test("X1 valid authorized payment: one EIP-3009 transfer of the live price to the authorized recipient, nonce bound to the intent, proven on chain, budget settled", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    const r = await w.submit(a);
    assert.deepEqual([r.decision, r.executed], ["ALLOW", true], JSON.stringify(r));
    const t = w.chain.transfers();
    assert.equal(t.length, 1);
    assert.deepEqual([t[0]!.from, t[0]!.to, t[0]!.value, t[0]!.nonce], [w.payer, w.payee, PRICE, w.nonceFor(a.authorization.intent_hash)]);
    assert.equal(r.receipt.reference, t[0]!.hash, "the receipt is the mined transaction");
    assert.equal(w.wallet.loads, 1);
    assert.equal(w.journal.inspect(a.authorization.intent_hash)?.state, "SETTLED");
    await w.report();
    const res = await w.reservation(a.authorization.auth_id);
    assert.deepEqual([res.state, res.charged], ["CONFIRMED", PRICE.toString()]);
    assert.equal(await w.spent(), PRICE);
  }));

test("X1-b the signed authorization never outlives the OxDeAI authorization (validBefore <= expiry) and pays exactly the authorized recipient", () => {
  const seen: PaymentPayload[] = [];
  return withWorld(
    async (w) => {
      const a = await w.authorize();
      assert.equal((await w.submit(a)).decision, "ALLOW");
      assert.equal(seen.length, 1);
      const p = seen[0]!.payload.authorization;
      assert.ok(BigInt(p.validBefore) <= BigInt(a.authorization.expiry), `${p.validBefore} <= ${a.authorization.expiry}`);
      assert.deepEqual([p.from, p.to, p.value, p.nonce], [w.payer, w.payee, PRICE.toString(), w.nonceFor(a.authorization.intent_hash)]);
    },
    { ttlSeconds: 30, sellerHooks: { onPayment: (p) => seen.push(p) } },
  );
});

// ── X2 ─────────────────────────────────────────────────────────────────────

test("X2 missing, invalid, foreign or caller-asserted authorization: never signed, never paid", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    const deny = async (x: unknown) => {
      const r = await w.submit(x as never);
      assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
    };
    await deny({ ...a, authorization: undefined });
    await deny({ ...a, authorization: { ...a.authorization, signature: "AAAA" } });
    await deny({ ...a, request: w.request({ body: JSON.stringify({ q: "other" }) }) }); // authorization of another intent
    await deny({ ...a, authorization: { ...a.authorization, audience: "attacker" } });
    // Directly at the executor, with the internal token: a caller assertion is never authority.
    const direct = await w.executeDirect({ action: { request: a.request, intent_ref: a.intent_ref }, authorization: { authorized: true } });
    assert.equal(direct.executed, false);
    const extra = await w.executeDirect({ action: { request: a.request, intent_ref: a.intent_ref }, authorization: a.authorization, authorized: true });
    assert.equal(extra.executed, false, "an extra caller-controlled field is refused");
    const noToken = await w.executeDirect({ action: { request: a.request, intent_ref: a.intent_ref }, authorization: a.authorization }, {});
    assert.equal(noToken.status, 403);
    neverSigned(w);
    // The genuine authorization still works afterwards.
    assert.equal((await w.submit(a)).decision, "ALLOW");
    assert.equal(w.chain.transfers().length, 1);
  }));

// ── X3 ─────────────────────────────────────────────────────────────────────

test("X3 expired authorization: refused before any signature; an authorization too close to expiry is refused by the adapter", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    w.clock.advance(61);
    assert.notEqual((await w.submit(a)).decision, "ALLOW");
    neverSigned(w);
    const b = await w.authorize();
    w.clock.advance(55); // 5 s left: below the adapter's 10 s minimum validity
    const r = await w.submit(b);
    assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
    assert.match(String(r.detail), /X402_AUTHORIZATION_TOO_CLOSE_TO_EXPIRY/);
    assert.equal(r.final, true, "the claim committed: the authorization can never be claimed again");
    neverSigned(w);
  }));

// ── X4 ─────────────────────────────────────────────────────────────────────

test("X4 recipient mismatch: a 402 naming another payee, an unapproved recipient, or an agent-chosen recipient is never paid", async () => {
  await withWorld(async (w) => {
    const a = await w.authorize();
    setRoute(w, { payTo: "0x000000000000000000000000000000000000dead" });
    const r = await w.submit(a);
    assert.notEqual(r.decision, "ALLOW");
    assert.match(String(r.detail), /RECIPIENT_MISMATCH/);
    neverSigned(w);
  });
  await withWorld(
    async (w) => {
      const r = await w.submit(await w.authorize());
      assert.match(String(r.detail), /X402_RECIPIENT_NOT_APPROVED/, JSON.stringify(r));
      neverSigned(w);
    },
    { adapter: { approvedRecipients: [] } },
  );
  await withWorld(async (w) => {
    const d = await w.auth.authorize(w.request({ recipient: "0x000000000000000000000000000000000000beef" }));
    assert.equal(d.decision, "DENY", "the policy only allows the configured recipient");
    neverSigned(w);
  });
});

// ── X5 ─────────────────────────────────────────────────────────────────────

test("X5 amount: above the authorized max is refused before signing; a lower live price pays exactly that price; above the policy max is denied", async () => {
  await withWorld(async (w) => {
    const a = await w.authorize();
    setRoute(w, { amount: (PRICE + 1n).toString() });
    const r = await w.submit(a);
    assert.notEqual(r.decision, "ALLOW");
    assert.match(String(r.detail), /EXCEEDS_AUTHORIZED_MAX/);
    neverSigned(w);
  });
  await withWorld(async (w) => {
    const a = await w.authorize();
    setRoute(w, { amount: "600" });
    assert.equal((await w.submit(a)).decision, "ALLOW");
    assert.deepEqual(w.chain.transfers().map((t) => t.value), [600n]);
    await w.report();
    assert.equal(await w.spent(), 600n, "charged the settled amount, the rest released");
  });
  await withWorld(async (w) => {
    const d = await w.auth.authorize(w.request({ max_amount: "2001" }));
    assert.equal(d.decision, "DENY", "per-action maximum");
  });
});

// ── X6 ─────────────────────────────────────────────────────────────────────

test("X6 wrong chain id or network: refused before the key is read; mainnet is never authorized", async () => {
  await withWorld(async (w) => {
    const a = await w.authorize();
    w.chain.faults.chainIdOverride = 42220n;
    const r = await w.submit(a);
    assert.match(String(r.detail), /X402_CHAIN_ID_MISMATCH:42220/);
    neverSigned(w);
  });
  await withWorld(async (w) => {
    const a = await w.authorize();
    setRoute(w, { network: "eip155:42220" });
    const r = await w.submit(a);
    assert.notEqual(r.decision, "ALLOW");
    neverSigned(w);
  });
  await withWorld(async (w) => {
    const a = await w.authorize();
    w.chain.faults.rpcDown = true;
    const r = await w.submit(a);
    assert.match(String(r.detail), /X402_RPC_UNAVAILABLE_BEFORE_SIGNING/, "no chain-id proof: fail closed");
    neverSigned(w);
  });
  assert.throws(() => authorizedTestnet("eip155:42220"), /NETWORK_NOT_AUTHORIZED:mainnet/);
  assert.throws(() => authorizedTestnet("eip155:44787"), /NETWORK_NOT_AUTHORIZED/);
  assert.throws(() => createX402EvmAdapter({ network: "eip155:42220", rpc: undefined as never, loadWalletKey: () => new Uint8Array(), approvedRecipients: [] }), /NETWORK_NOT_AUTHORIZED/);
});

// ── X7 ─────────────────────────────────────────────────────────────────────

test("X7 token / contract / EIP-712 domain / transfer method mismatch: refused before signing", async () => {
  for (const over of [
    { asset: "0x765de816845861e75a25fca122bb6898b8b1282a" },
    { extra: { name: "USDC", version: "1" } },
    { extra: { name: "USD Coin", version: "2" } },
    { extra: { name: "USDC", version: "2", assetTransferMethod: "permit2" } },
    { scheme: "upto" },
  ]) {
    await withWorld(async (w) => {
      const a = await w.authorize();
      setRoute(w, over);
      const r = await w.submit(a);
      assert.notEqual(r.decision, "ALLOW", JSON.stringify(over));
      neverSigned(w);
    });
  }
});

// ── X8 ─────────────────────────────────────────────────────────────────────

test("X8 replay of a consumed authorization: refused by the gateway, then by the executor after gateway and executor restarts; one transfer only", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    assert.equal((await w.submit(a)).decision, "ALLOW");
    assert.notEqual((await w.submit(a)).decision, "ALLOW", "gateway replay store");
    w.restartGateway();
    assert.notEqual((await w.submit(a)).decision, "ALLOW", "executor journal");
    w.restartExecutor();
    w.restartGateway();
    const r = await w.submit(a);
    assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
    assert.equal(w.chain.transfers().length, 1);
    assert.equal(w.wallet.loads, 1, "signed once");
  }));

// ── X9 ─────────────────────────────────────────────────────────────────────

test("X9 duplicate submission: a payee re-submitting the signed authorization is reverted by the token (one use per nonce); a re-sign after total executor-state loss is refused by the on-chain nonce check", () => {
  const seen: PaymentPayload[] = [];
  return withWorld(
    async (w) => {
      const a = await w.authorize();
      assert.equal((await w.submit(a)).decision, "ALLOW");
      const p = seen[0]!.payload;
      const again = w.chain.transferWithAuthorization(
        { from: p.authorization.from, to: p.authorization.to, value: BigInt(p.authorization.value), validAfter: BigInt(p.authorization.validAfter), validBefore: BigInt(p.authorization.validBefore), nonce: p.authorization.nonce },
        p.signature,
      );
      assert.equal(again.status, 0);
      assert.match(String(again.reason), /used or canceled/);
      assert.equal(w.chain.transfers().length, 1);
      assert.equal(w.chain.balanceOf(w.payee), PRICE, "paid once");
      // Total loss of every OxDeAI-side store, and an authority that grants any claim: the chain still
      // remembers the intent's nonce, so the adapter refuses to sign a second payment.
      const amnesic = createPaymentExecutor({
        internalToken: "t".repeat(64),
        adapter: createX402EvmAdapter(w.adapterConfig),
        verification: { expectedAudience: "oxdeai-celo-poc.gateway", trustedKeySets: [w.auth.trustMaterial.keySet], trustedAuthorizationAuthorities: [w.auth.trustMaterial.authority], now: w.clock.now },
        journal: (await import("../../src/executor/payment-journal.ts")).createInMemoryPaymentJournal(w.clock.now),
        authority: { claim: async () => ({ ok: true }), void: async () => ({ acknowledged: false, final: false }) },
      });
      const r = await amnesic.handle({ action: { request: a.request, intent_ref: a.intent_ref }, authorization: a.authorization }, { [INTERNAL_EXECUTOR_TOKEN_HEADER]: "t".repeat(64) });
      assert.equal(r.executed, "unknown", JSON.stringify(r.body));
      assert.match(String((r.body as any).error), /X402_NONCE_ALREADY_CONSUMED/);
      assert.equal(w.wallet.loads, 2, "the key was read for the check, but nothing new was signed");
      assert.equal(seen.length, 1, "no second signed authorization ever left the executor");
      assert.equal(w.chain.transfers().length, 1);
    },
    { sellerHooks: { onPayment: (p) => seen.push(p) } },
  );
});

// ── X10 ────────────────────────────────────────────────────────────────────

test("X10-a response lost after broadcast: PAYMENT_UNKNOWN, held fully charged, never re-signed; reconciled only with the mined receipt", () =>
  withWorld(
    async (w) => {
      const a = await w.authorize();
      const r = await w.submit(a);
      assert.equal(r.decision, "INDETERMINATE", JSON.stringify(r));
      assert.equal(w.chain.transfers().length, 1, "it did pay");
      const rec = w.journal.inspect(a.authorization.intent_hash)!;
      assert.equal(rec.state, "UNKNOWN");
      assert.match(String(rec.detail), new RegExp(w.nonceFor(a.authorization.intent_hash)), "the journal holds what reconciliation needs");
      w.restartGateway();
      assert.notEqual((await w.submit(a)).decision, "ALLOW");
      assert.equal(w.wallet.loads, 1, "never re-signed");
      await w.report();
      const held = await w.reservation(a.authorization.auth_id);
      assert.deepEqual([held.state, held.charged], ["UNCERTAIN", PRICE.toString()], "no evidence yet: fully charged, never released");
      // Operator reconciliation from the chain (the tx hash comes from the explorer / facilitator logs).
      const tx = w.chain.transfers()[0]!.hash;
      const ev = await verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, { asset: CELO_SEPOLIA.assets[0]!.address, payer: w.payer, payTo: w.payee, nonce: w.nonceFor(a.authorization.intent_hash), maxAmount: PRICE, signedAmount: PRICE, txHash: tx });
      w.journal.resolve(a.authorization.intent_hash, ev, "x402 test: settled on chain");
      await w.report();
      const done = await w.reservation(a.authorization.auth_id);
      assert.deepEqual([done.state, done.charged], ["CONFIRMED", PRICE.toString()]);
    },
    { sellerHooks: { afterSettle: () => "drop" } },
  ));

test("X10-b settlement_pending and an unavailable RPC after broadcast: PAYMENT_UNKNOWN (pending), never a success or a failure without the receipt", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    w.facilitator.faults.pendingAfterBroadcast = true;
    w.chain.faults.holdReceipts = true;
    const r = await w.submit(a);
    assert.equal(r.decision, "INDETERMINATE", JSON.stringify(r));
    assert.match(String(r.detail), /X402_TX_PENDING/);
    const b = await w.authorize({ body: JSON.stringify({ q: "second" }) });
    w.facilitator.faults.pendingAfterBroadcast = false;
    w.chain.faults.holdReceipts = false;
    w.seller.routes[0] = { ...w.route }; // unchanged
    const tx = w.chain.submissions[0]!.hash;
    // RPC goes down right after the broadcast of the second payment.
    w.facilitator.faults.pendingAfterBroadcast = true;
    const origSettle = w.facilitator.client.settle;
    w.facilitator.client.settle = async (p, q) => {
      const out = await origSettle(p, q);
      w.chain.faults.rpcDown = true;
      return out;
    };
    const r2 = await w.submit(b);
    assert.equal(r2.decision, "INDETERMINATE", JSON.stringify(r2));
    w.chain.faults.rpcDown = false;
    assert.equal(w.chain.transfers().length, 2, "both did settle on chain");
    const ev = await verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, { asset: CELO_SEPOLIA.assets[0]!.address, payer: w.payer, payTo: w.payee, nonce: w.nonceFor(a.authorization.intent_hash), maxAmount: PRICE, signedAmount: PRICE, txHash: tx });
    assert.equal(ev.amount, PRICE.toString());
  }));

// ── X11 ────────────────────────────────────────────────────────────────────

test("X11 crash window after the signature left (journal write fails after pay): the executor answers PAYMENT_UNKNOWN; after restart the intent needs reconciliation and is never paid twice", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    // The process "dies" after the payment and before its outcome is recorded: record() throws.
    const j = w.journal;
    const realRecord = j.record.bind(j);
    (j as any).record = () => {
      throw new Error("injected: process died before recording");
    };
    const r = await w.submit(a);
    assert.notEqual(r.decision, "ALLOW");
    assert.equal(r.executed, "unknown");
    (j as any).record = realRecord;
    w.restartExecutor();
    assert.deepEqual(w.journal.needsReconciliation.map((x) => x.intent_hash), [a.authorization.intent_hash]);
    w.restartGateway();
    assert.notEqual((await w.submit(a)).decision, "ALLOW");
    assert.equal(w.chain.transfers().length, 1);
    assert.equal(w.wallet.loads, 1);
  }));

// ── X12 ────────────────────────────────────────────────────────────────────

test("X12 reverted transaction: PAYMENT_UNKNOWN, no settlement evidence, fully charged; the signed authorization can still settle until validBefore, and only that exact payment can", () => {
  const seen: PaymentPayload[] = [];
  return withWorld(
    async (w) => {
      const a = await w.authorize();
      w.chain.faults.revertNext = true;
      const r = await w.submit(a);
      assert.equal(r.decision, "INDETERMINATE", JSON.stringify(r));
      assert.match(String(r.detail), /X402_NOT_SETTLED_UNCONFIRMED:invalid_transaction_state/);
      const tx = w.chain.submissions[0]!.hash;
      const nonce = w.nonceFor(a.authorization.intent_hash);
      const want = { asset: CELO_SEPOLIA.assets[0]!.address, payer: w.payer, payTo: w.payee, nonce, maxAmount: PRICE, signedAmount: PRICE, txHash: tx };
      await assert.rejects(verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, want), /NO_SETTLEMENT_EVIDENCE:.*reverted/);
      assert.equal(w.chain.isConsumed(w.payer, nonce), false);
      await w.report();
      assert.deepEqual([(await w.reservation(a.authorization.auth_id)).state, await w.spent()], ["UNCERTAIN", PRICE]);
      // The payee settles the captured authorization later: exactly the authorized transfer, once.
      const p = seen[0]!.payload;
      const late = w.chain.transferWithAuthorization({ from: p.authorization.from, to: p.authorization.to, value: BigInt(p.authorization.value), validAfter: BigInt(p.authorization.validAfter), validBefore: BigInt(p.authorization.validBefore), nonce }, p.signature);
      assert.equal(late.status, 1);
      const ev = await verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, { ...want, txHash: late.hash });
      w.journal.resolve(a.authorization.intent_hash, ev, "x402 test: late settlement of the signed authorization");
      await w.report();
      assert.equal((await w.reservation(a.authorization.auth_id)).state, "CONFIRMED");
    },
    { sellerHooks: { onPayment: (p) => seen.push(p) } },
  );
});

test("X12-b lying seller / facilitator: success with an unknown transaction, or with another payment's transaction, is never accepted as settlement", async () => {
  await withWorld(async (w) => {
    const a = await w.authorize();
    w.facilitator.faults.lieSuccessUnknownTx = true;
    const r = await w.submit(a);
    assert.equal(r.decision, "INDETERMINATE", JSON.stringify(r));
    assert.match(String(r.detail), /X402_TX_PENDING/);
    assert.equal(w.chain.transfers().length, 0);
  });
  await withWorld(async (w) => {
    const first = await w.authorize();
    assert.equal((await w.submit(first)).decision, "ALLOW");
    const otherTx = w.chain.transfers()[0]!.hash;
    const b = await w.authorize({ body: JSON.stringify({ q: "second" }) });
    w.facilitator.client.settle = async (p) => ({ success: true, transaction: otherTx, network: CELO_SEPOLIA.caip2, payer: p.payload.authorization.from });
    const r = await w.submit(b);
    assert.equal(r.decision, "INDETERMINATE", JSON.stringify(r));
    assert.match(String(r.detail), /X402_TX_EVIDENCE_MISMATCH/);
    assert.equal(w.chain.transfers().length, 1);
  });
  await withWorld(async (w) => {
    const a = await w.authorize();
    w.facilitator.faults.broadcastThenDenyBroadcast = true;
    const r = await w.submit(a);
    assert.equal(r.decision, "INDETERMINATE", "a 'not settled' answer is not proof of non-payment");
    assert.equal(w.chain.transfers().length, 1, "it did settle");
  });
});

// ── X13 ────────────────────────────────────────────────────────────────────

test("X13 gateway and executor restarts: no false positive, previous payments stay consumed, new payments work", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    assert.equal((await w.submit(a)).decision, "ALLOW");
    w.restartExecutor();
    w.restartGateway();
    assert.notEqual((await w.submit(a)).decision, "ALLOW");
    const b = await w.authorize({ body: JSON.stringify({ q: "after restart" }) });
    assert.equal((await w.submit(b)).decision, "ALLOW");
    assert.equal(w.chain.transfers().length, 2);
    assert.notEqual(w.chain.transfers()[0]!.nonce, w.chain.transfers()[1]!.nonce);
  }));

// ── X14 ────────────────────────────────────────────────────────────────────

test("X14 authorization service outage: no claim, no signature, no payment; the rejection is final only if the VOID is confirmed", async () => {
  await withWorld(async (w) => {
    const a = await w.authorize();
    w.down.claim = true;
    const r = await w.submit(a);
    assert.notEqual(r.decision, "ALLOW");
    assert.match(String(r.detail), /CLAIM_UNAVAILABLE/);
    assert.equal(r.final, true, "the VOID was confirmed");
    neverSigned(w);
  });
  await withWorld(async (w) => {
    const a = await w.authorize();
    w.down.claim = true;
    w.down.void = true;
    const r = await w.submit(a);
    assert.equal(r.final, false, "outage: not confirmed, not final");
    assert.equal((await w.reservation(a.authorization.auth_id)).state, "RESERVED");
    neverSigned(w);
  });
});

// ── X15 ────────────────────────────────────────────────────────────────────

test("X15 journal and checkpoint rollback: a journal-only restore is detected; a joint restore is stopped by the auth service; and with every OxDeAI store gone, by the on-chain nonce", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    w.journal.close();
    const snap = join(w.dirs.dir, "snap");
    cpSync(w.dirs.journalDir, join(snap, "journal"), { recursive: true });
    cpSync(w.dirs.checkpoint.path, join(snap, "checkpoint.log"));
    w.restartExecutor();
    assert.equal((await w.submit(a)).decision, "ALLOW");
    // (a) journal restored alone: detected.
    w.journal.close();
    rmSync(w.dirs.journalDir, { recursive: true, force: true });
    cpSync(join(snap, "journal"), w.dirs.journalDir, { recursive: true });
    assert.throws(() => openFilePaymentJournal(w.dirs.journalDir, { checkpoint: w.dirs.checkpoint }), /JOURNAL_ROLLBACK_DETECTED/);
    // (b) journal AND checkpoint restored together (F-SIBLING end state): no executor-side memory.
    cpSync(join(snap, "checkpoint.log"), w.dirs.checkpoint.path);
    w.restartExecutor();
    w.restartGateway();
    const r = await w.submit(a);
    assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
    assert.match(String(r.detail), /CLAIM_REFUSED:NOT_ELIGIBLE/, "the auth service granted its single claim already");
    assert.equal(w.chain.transfers().length, 1);
    assert.equal(w.wallet.loads, 1);
  }));

// ── X16 ────────────────────────────────────────────────────────────────────

test("X16 concurrent attempts: the same authorization twice at once pays once; two authorizations at once pay twice with distinct nonces", () =>
  withWorld(async (w) => {
    const a = await w.authorize();
    const [r1, r2] = await Promise.all([w.submit(a), w.submit(a)]);
    assert.deepEqual([r1.decision, r2.decision].filter((d) => d === "ALLOW").length, 1);
    assert.equal(w.chain.transfers().length, 1);
    w.restartGateway();
    // Issued one after the other (concurrent PDP decisions are refused POLICY_STATE_CONFLICT by design), submitted at once.
    const x = await w.authorize({ body: JSON.stringify({ q: "x" }) });
    const y = await w.authorize({ body: JSON.stringify({ q: "y" }) });
    const [rx, ry, rxAgain] = await Promise.all([w.submit(x), w.submit(y), w.submit(x)]);
    assert.deepEqual([rx.decision, ry.decision].sort(), ["ALLOW", "ALLOW"]);
    assert.notEqual(rxAgain.decision, "ALLOW");
    const t = w.chain.transfers();
    assert.equal(t.length, 3);
    assert.equal(new Set(t.map((z) => z.nonce)).size, 3);
    await w.report();
    assert.equal(await w.spent(), 3n * PRICE);
  }, { budget: 5_000n }));

// ── X17 ────────────────────────────────────────────────────────────────────

test("X17 final / non-final propagation through the gateway for x402 rejections", async () => {
  await withWorld(async (w) => {
    const a = await w.authorize();
    setRoute(w, { amount: (PRICE * 2n).toString() }); // quote above the authorization: rejected before execution
    const r = await w.submit(a);
    assert.deepEqual([r.decision, r.final], ["DENY", true], JSON.stringify(r));
  });
  await withWorld(async (w) => {
    const a = await w.authorize();
    setRoute(w, { amount: (PRICE * 2n).toString() });
    w.down.void = true;
    const r = await w.submit(a);
    assert.deepEqual([r.decision, r.final], ["DENY", false], JSON.stringify(r));
  });
  await withWorld(async (w) => {
    const a = await w.authorize();
    w.chain.faults.chainIdOverride = 1n; // refused inside pay, after the claim
    const r = await w.submit(a);
    assert.deepEqual([r.decision, r.final], ["DENY", true], JSON.stringify(r));
  });
});

// ── X18 ────────────────────────────────────────────────────────────────────

test("X18 key hygiene: the payer key never appears in the journal, checkpoint, adapter logs, or anything sent to the seller", () => {
  const logs: string[] = [];
  const sent: string[] = [];
  let keyHex = "";
  return withWorld(
    async (w) => {
      keyHex = Buffer.from(w.adapterConfig.loadWalletKey()).toString("hex");
      w.wallet.loads = 0;
      const a = await w.authorize();
      assert.equal((await w.submit(a)).decision, "ALLOW");
      w.journal.close();
      const files: string[] = [];
      const walk = (d: string) => {
        for (const n of readdirSync(d)) {
          const p = join(d, n);
          if (statSync(p).isDirectory()) walk(p);
          else files.push(readFileSync(p, "utf8"));
        }
      };
      walk(w.dirs.dir);
      for (const text of [...files, ...logs, ...sent]) assert.ok(!text.toLowerCase().includes(keyHex), "private key leaked");
      w.restartExecutor();
    },
    { adapter: { log: (e) => logs.push(JSON.stringify(e)) }, sellerHooks: { onPayment: (p) => sent.push(JSON.stringify(p)) } },
  );
});

// ── X19: F-SIBLING on the x402 rail (reproduction, not a fix) ─────────────────

async function fSiblingSetup(w: World) {
  const a = await w.authorize();
  w.journal.close();
  const snap = join(w.dirs.dir, "fsib");
  cpSync(w.dirs.journalDir, join(snap, "journal"), { recursive: true });
  cpSync(w.dirs.checkpoint.path, join(snap, "checkpoint.log"));
  w.restartExecutor();
  // Non-final rejection: the 402 drifted above the authorization while the auth service is unreachable.
  setRoute(w, { amount: (PRICE * 2n).toString() });
  w.down.void = true;
  const r = await w.submit(a);
  assert.deepEqual([r.decision, r.final], ["DENY", false], JSON.stringify(r));
  w.down.void = false;
  w.seller.routes[0] = w.route;
  // Journal AND checkpoint restored together (laundered): no executor-side memory of the rejection.
  w.journal.close();
  rmSync(w.dirs.journalDir, { recursive: true, force: true });
  cpSync(join(snap, "journal"), w.dirs.journalDir, { recursive: true });
  cpSync(join(snap, "checkpoint.log"), w.dirs.checkpoint.path);
  w.restartExecutor();
  w.restartGateway();
  return a;
}

test("X19-a F-SIBLING residual reproduced on x402: a non-final rejection followed by a joint journal + checkpoint restore can pay once (exactly the authorized transfer); never twice", () =>
  withWorld(async (w) => {
    const a = await fSiblingSetup(w);
    const r = await w.submit(a);
    assert.equal(r.decision, "ALLOW", "RESIDUAL: the rejection was not final, and nothing remembers it");
    assert.deepEqual(w.chain.transfers().map((t) => [t.to, t.value]), [[w.payee, PRICE]]);
    w.restartGateway();
    assert.notEqual((await w.submit(a)).decision, "ALLOW");
    assert.equal(w.chain.transfers().length, 1, "duplicates stay impossible (nonce)");
  }));

test("X19-b proposed remediation R1, mechanism only (simulated, NOT implemented in the executor): once the intent's nonce is canceled on chain, the same F-SIBLING sequence can no longer pay", () =>
  withWorld(async (w) => {
    const a = await fSiblingSetup(w);
    // What R1 would do at rejection time when the VOID is unconfirmed: cancelAuthorization(payer, f(intent)).
    w.chain.cancel(w.payer, w.nonceFor(a.authorization.intent_hash));
    const r = await w.submit(a);
    assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
    assert.match(String(r.detail), /X402_NONCE_ALREADY_CONSUMED/);
    assert.equal(w.chain.transfers().length, 0, "the chain remembered the rejection");
  }));

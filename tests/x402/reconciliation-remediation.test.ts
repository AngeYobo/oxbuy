// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { createHttpRpc, RpcError } from "../../src/chain/rpc.ts";
import { approvedReconciliationRpc } from "../../src/chain/reconciliation-rpc.ts";
import { verifyOnchainSettlement } from "../../src/chain/eip3009-evidence.ts";
import { CELO_SEPOLIA } from "../../src/chain/networks.ts";
import { validatePaymentBinding } from "../../src/executor/payment-binding.ts";
import { openFilePaymentJournal } from "../../src/executor/payment-journal.ts";
import { PRICE, x402World } from "./harness.ts";

const fakeFetch = (body: unknown, status = 200): typeof fetch => (async () => new Response(JSON.stringify(body), { status })) as typeof fetch;
for (const [name, body, status] of [
  ["valid", { jsonrpc: "2.0", id: 1, result: "0x1" }, 200],
  ["wrong ID", { jsonrpc: "2.0", id: 2, result: "0x1" }, 200],
  ["wrong version", { jsonrpc: "1.0", id: 1, result: "0x1" }, 200],
  ["missing ID", { jsonrpc: "2.0", result: "0x1" }, 200],
  ["neither result nor error", { jsonrpc: "2.0", id: 1 }, 200],
  ["both", { jsonrpc: "2.0", id: 1, result: "0x1", error: { code: 1, message: "bad" } }, 200],
  ["HTTP failure", { jsonrpc: "2.0", id: 1, result: "0x1" }, 503],
  ["null", null, 200], ["array", [], 200], ["primitive", 1, 200],
  ["bad error", { jsonrpc: "2.0", id: 1, error: { message: "bad" } }, 200],
  ["RPC error", { jsonrpc: "2.0", id: 1, error: { code: -32000, message: "bad" } }, 200],
] as const) test(`R04 envelope: ${name}`, async () => {
  const r = createHttpRpc("http://localhost", { fetch: fakeFetch(body, status) });
  if (name === "valid") assert.equal(await r.chainId(), 1n);
  else await assert.rejects(r.chainId(), RpcError);
});
test("R04 malformed JSON and network failure are RpcError", async () => {
  for (const f of [(async () => new Response("{")) as typeof fetch, (async () => { throw new TypeError("network"); }) as typeof fetch])
    await assert.rejects(createHttpRpc("http://localhost", { fetch: f }).chainId(), RpcError);
});
test("R04 timeout; R03 redirect refused without contacting destination", async () => {
  let destinationHits = 0;
  const destination = createServer((_q, s) => { destinationHits++; s.end('{}'); });
  const server = createServer((q, s) => {
    if (q.url === "/redirect") s.writeHead(302, { location: `http://127.0.0.1:${(destination.address() as any).port}` }).end();
  });
  await new Promise<void>((r) => destination.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  try {
    const url = `http://127.0.0.1:${(server.address() as any).port}`;
    await assert.rejects(createHttpRpc(url, { timeoutMs: 30 }).chainId(), RpcError);
    await assert.rejects(createHttpRpc(`${url}/redirect`).chainId(), RpcError);
    assert.equal(destinationHits, 0);
  } finally { server.closeAllConnections(); destination.closeAllConnections(); await Promise.all([new Promise<void>((r) => server.close(() => r())), new Promise<void>((r) => destination.close(() => r()))]); }
});
test("R03 explicit private policy allows only listed Sepolia endpoints", () => {
  const d = mkdtempSync(join(tmpdir(), "rpc-policy-"));
  const p = join(d, "policy.json");
  try {
    writeFileSync(p, JSON.stringify({ network: CELO_SEPOLIA.caip2, endpoints: ["http://127.0.0.1:1234"] }), { mode: 0o600 });
    assert.equal(approvedReconciliationRpc("http://127.0.0.1:1234", p), "http://127.0.0.1:1234/");
    assert.throws(() => approvedReconciliationRpc("http://127.0.0.1:4321", p), /NOT_APPROVED/);
    assert.throws(() => approvedReconciliationRpc("http://127.0.0.1:1234", undefined), /NOT_APPROVED/);
    writeFileSync(p, JSON.stringify({ network: "eip155:42220", endpoints: ["http://127.0.0.1:1234"] }));
    assert.throws(() => approvedReconciliationRpc("http://127.0.0.1:1234", p), /NOT_APPROVED/);
  } finally { rmSync(d, { recursive: true }); }
});

test("R01/R02 receipt identity, exact amount below maximum, absent/reverted/wrong-chain/unavailable evidence", async () => {
  const w = await x402World();
  try {
    const a = await w.authorize({ max_amount: (PRICE * 2n).toString() });
    assert.equal((await w.submit(a)).decision, "ALLOW");
    const b = w.journal.inspect(a.authorization.intent_hash)!.payment_binding!;
    const tx = w.chain.transfers()[0]!.hash;
    const want = { asset: b.asset, payer: b.payer, payTo: b.recipient, nonce: b.nonce, maxAmount: PRICE * 2n, signedAmount: BigInt(b.amount), txHash: tx };
    assert.equal((await verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, want)).amount, PRICE.toString());
    const receipt = (await w.rpc.receipt(tx))!;
    for (const transactionHash of ["0x" + "ab".repeat(32), "broken"]) await assert.rejects(verifyOnchainSettlement({ ...w.rpc, receipt: async () => ({ ...receipt, transactionHash }) }, CELO_SEPOLIA, want), /hash mismatch/);
    await assert.rejects(verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, { ...want, signedAmount: PRICE + 1n }), /differs from signed/);
    await assert.rejects(verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, { ...want, maxAmount: PRICE - 1n }), /outside the authorization/);
    await assert.rejects(verifyOnchainSettlement({ ...w.rpc, receipt: async () => null }, CELO_SEPOLIA, want), /NO_SETTLEMENT_EVIDENCE/);
    await assert.rejects(verifyOnchainSettlement({ ...w.rpc, receipt: async () => ({ ...receipt, status: 0 }) }, CELO_SEPOLIA, want), /NO_SETTLEMENT_EVIDENCE/);
    await assert.rejects(verifyOnchainSettlement({ ...w.rpc, chainId: async () => 42220n }, CELO_SEPOLIA, want), /chain id/);
    await assert.rejects(verifyOnchainSettlement({ ...w.rpc, chainId: async () => { throw new RpcError("unavailable"); } }, CELO_SEPOLIA, want), RpcError);
  } finally { await w.close(); }
});

test("R02 binding persisted and signature authenticated before transmission; immutable and no replay", async () => {
  let observed = false;
  const w = await x402World({ sellerHooks: { afterSettle: () => "drop" } });
  try {
    const a = await w.authorize();
    const original = w.journal.bindPayment.bind(w.journal);
    w.journal.bindPayment = (h, b) => {
      assert.equal(h, a.authorization.intent_hash);
      assert.equal(b.claim_id, w.journal.inspect(h)!.claim_id);
      assert.throws(() => original(h, { ...b, intent_hash: "ab".repeat(32) }), /PAYMENT_BINDING_INVALID/);
      assert.throws(() => original(h, { ...b, claim_id: "ab".repeat(16) }), /PAYMENT_BINDING_INVALID/);
      original(h, b);
      assert.equal(w.chain.transfers().length, 0);
      assert.ok(readFileSync(w.dirs.checkpoint.path, "utf8").includes('"PAYMENT_BINDING"'));
      observed = true;
    };
    assert.equal((await w.submit(a)).decision, "INDETERMINATE");
    assert.ok(observed);
    const rec = w.journal.inspect(a.authorization.intent_hash)!;
    validatePaymentBinding(rec, rec.payment_binding!);
    assert.throws(() => validatePaymentBinding(rec, { ...rec.payment_binding!, amount: (PRICE + 1n).toString() }), /INVALID/);
    assert.throws(() => w.journal.bindPayment(rec.intent_hash, rec.payment_binding!), /REFUSED/);
    w.restartExecutor(); w.restartGateway();
    assert.notEqual((await w.submit(a)).decision, "ALLOW");
    assert.equal(w.wallet.loads, 1);
    assert.equal(w.chain.transfers().length, 1);
  } finally { await w.close(); }
});

for (const window of ["before journal", "before checkpoint", "after checkpoint"] as const)
 test(`R02 persistence/crash window ${window} blocks transmission and repeat signing`, async () => {
  const w = await x402World();
  try {
    const a = await w.authorize();
    const original = w.journal.bindPayment.bind(w.journal);
    w.journal.bindPayment = (h, b) => {
      if (window === "before checkpoint") {
        // Durable journal write exists; checkpoint acknowledgement has not happened.
        const p = join(w.dirs.journalDir, "intents", h);
        const r = JSON.parse(readFileSync(p, "utf8"));
        writeFileSync(p, JSON.stringify({ ...r, payment_binding: b }));
      }
      if (window === "after checkpoint") original(h, b);
      throw new Error("injected persistence/crash");
    };
    assert.equal((await w.submit(a)).decision, "INDETERMINATE");
    assert.equal(w.chain.transfers().length, 0);
    assert.equal(w.facilitator.calls.settle, 0);
    w.restartExecutor(); w.restartGateway();
    assert.notEqual((await w.submit(a)).decision, "ALLOW");
    assert.equal(w.wallet.loads, 1);
  } finally { await w.close(); }
});

test("R02 journal binding rollback is detected and recovered; legacy and corrupt evidence refuse resolution", async () => {
  const w = await x402World({ sellerHooks: { afterSettle: () => "drop" } });
  try {
    const a = await w.authorize();
    await w.submit(a);
    const h = a.authorization.intent_hash;
    const rec = w.journal.inspect(h)!;
    const b = rec.payment_binding!;
    const ev = await verifyOnchainSettlement(w.rpc, CELO_SEPOLIA, { asset: b.asset, payer: b.payer, payTo: b.recipient, nonce: b.nonce, maxAmount: PRICE, signedAmount: PRICE, txHash: w.chain.transfers()[0]!.hash });
    assert.throws(() => w.journal.resolve(h, { ...ev, amount: (PRICE - 1n).toString() }, "bad"), /MISMATCH/);
    w.journal.close();
    const p = join(w.dirs.journalDir, "intents", h);
    const { payment_binding: _, ...legacy } = rec;
    writeFileSync(p, JSON.stringify(legacy));
    assert.throws(() => openFilePaymentJournal(w.dirs.journalDir, { checkpoint: w.dirs.checkpoint }), /ROLLBACK_DETECTED/);
    const recovery = openFilePaymentJournal(w.dirs.journalDir, { checkpoint: { ...w.dirs.checkpoint, mode: "recover" } });
    recovery.recoverFromCheckpoint("binding rollback test");
    assert.deepEqual(recovery.inspect(h)!.payment_binding, b);
    recovery.close();
    w.restartExecutor();
    // Recovery preserves UNKNOWN. Apply its authenticated report before reconciliation:
    // RESOLVED_SETTLED is valid only from the service's UNCERTAIN state.
    const delivered: { outcome: string; result: string }[] = [];
    const originalSettle = w.auth.settle;
    w.auth.settle = async (signed) => {
      const result = await originalSettle(signed);
      delivered.push({ outcome: (signed as { report: { outcome: string } }).report.outcome, result: result.status });
      return result;
    };
    assert.equal((await w.reservation(a.authorization.auth_id)).state, "EXECUTING");
    await w.report();
    assert.deepEqual(delivered, [{ outcome: "UNCERTAIN", result: "APPLIED" }]);
    assert.equal(w.journal.acked(a.authorization.auth_id, "UNCERTAIN"), true);
    assert.equal((await w.reservation(a.authorization.auth_id)).state, "UNCERTAIN");
    assert.equal((await w.reservation(a.authorization.auth_id)).charged, PRICE.toString());
    assert.equal(await w.spent(), PRICE);
    writeFileSync(p, JSON.stringify(legacy));
    assert.throws(() => w.journal.resolve(h, ev, "legacy"), /BINDING_REQUIRED/);
    writeFileSync(p, JSON.stringify({ ...rec, payment_binding: { ...b, amount: "1" } }));
    assert.throws(() => w.journal.resolve(h, ev, "corrupt"), /BINDING_REQUIRED/);
    writeFileSync(p, JSON.stringify(rec));
    w.journal.resolve(h, ev, "valid");
    await w.report();
    assert.deepEqual(delivered, [{ outcome: "UNCERTAIN", result: "APPLIED" }, { outcome: "RESOLVED_SETTLED", result: "APPLIED" }]);
    assert.equal(w.journal.acked(a.authorization.auth_id, "RESOLVED_SETTLED"), true);
    assert.equal((await w.reservation(a.authorization.auth_id)).state, "CONFIRMED");
    assert.equal((await w.reservation(a.authorization.auth_id)).charged, PRICE.toString());
    assert.equal(await w.spent(), PRICE);
    assert.equal(w.chain.transfers().length, 1);
    assert.equal(w.wallet.loads, 1);
  } finally { await w.close(); }
});

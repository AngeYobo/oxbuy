// SPDX-License-Identifier: MIT
/**
 * OxDeAI Guarded Buyer (product demo), offline: the real CLI, OxDeAI stack and x402 adapter against a simulated
 * buy-style gateway (x402 v1, JSON 402, X-PAYMENT), SimChain and SimFacilitator. Not evidence about the real
 * buy gateway or Celo Sepolia (run `npm run x402:probe` and `npm run buyer` for that).
 *
 *   GB1 one authorized purchase produces the brief; exactly one transfer to the approved recipient; budget settled;
 *       the unapproved purchase is denied by the PDP before anything is signed or paid
 *   GB2 out-of-policy purchases never pay: price above the per-call ceiling, budget exhausted
 *   GB3 catalog validation: mainnet, non-https, unknown token, price above ceiling are refused
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { addressOfPrivateKey, parsePrivateKey } from "../../src/chain/evm.ts";
import { createHttpRpc } from "../../src/chain/rpc.ts";
import { validateCatalog } from "../../src/product/catalog.ts";
import { runBuyer } from "../../src/product/buyer-cli.ts";
import { createGuardedBuyer, requestFor } from "../../src/product/guarded-buyer.ts";
import { createGuardedStack } from "../../src/product/stack.ts";
import { startSeller } from "../../src/x402/seller.ts";
import { TESTNET_NETWORK, TESTNET_USDC } from "../../src/x402/testnet-profile.ts";
import { createSimChain, createSimFacilitator } from "../x402/sim.ts";

const ORIGIN = "https://gateway.usebuy.test";
const PATH = "/v1/social/x/posts/search";
const PRICE = 1000n;
const POSTS = { data: [
  { text: "Loving the new Acme espresso machine, coffee is great", author: { username: "alice" }, like_count: 12, url: "https://x.com/alice/1" },
  { text: "Acme delivery was late again, support slow", author: { username: "bob" }, like_count: 3 },
  { text: "Acme espresso beats the competition on price", author: { username: "carol" }, like_count: 7 },
] };

async function world() {
  const dir = mkdtempSync(join(tmpdir(), "oxdeai-x402-gb-"));
  const keyHex = randomBytes(32).toString("hex");
  const keyFile = join(dir, "payer.key");
  writeFileSync(keyFile, keyHex, { mode: 0o600 });
  const payer = addressOfPrivateKey(parsePrivateKey(keyHex));
  const payee = addressOfPrivateKey(randomBytes(32));
  const chain = createSimChain({ network: TESTNET_NETWORK, asset: TESTNET_USDC, now: () => Math.floor(Date.now() / 1000) });
  const rpcUrl = await chain.listen();
  chain.mint(payer, 100_000n);
  const fac = createSimFacilitator(chain, TESTNET_NETWORK);
  const requirements = { scheme: "exact", network: TESTNET_NETWORK.caip2, amount: PRICE.toString(), asset: "0x01C5C0122039549AD1493B8220cABEdD739BC44E", payTo: payee, maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } };
  const seller = await startSeller({
    publicOrigin: ORIGIN,
    x402Version: 1,
    facilitator: fac.client,
    routes: [
      { method: "POST", path: PATH, description: "X post search", requirements, body: () => JSON.stringify(POSTS) },
      { method: "POST", path: "/v1/social/linkedin/profile", description: "LinkedIn profile", requirements, body: () => "{}" },
    ],
  });
  const catalog = {
    network: TESTNET_NETWORK.caip2,
    budget: "2500",
    per_call_max: "2000",
    services: [{ service_id: "buy-x-search", method: "POST", url: `${ORIGIN}${PATH}`, network: TESTNET_NETWORK.caip2, asset: TESTNET_USDC.address, pay_to: payee, max_price: PRICE.toString(), purpose: "brand mentions on X" }],
  };
  const catalogFile = join(dir, "catalog.json");
  writeFileSync(catalogFile, JSON.stringify(catalog));
  const env = { OXDEAI_TESTNET_PAYER_KEY_FILE: keyFile, OXDEAI_TESTNET_RPC_URL: rpcUrl, OXDEAI_BUYER_STATE_DIR: join(dir, "state"), OXDEAI_BUYER_EVIDENCE_DIR: join(dir, "evidence") };
  return {
    dir, keyHex, keyFile, payer, payee, chain, fac, seller, catalog, catalogFile, env, rpcUrl,
    async close() {
      await seller.close();
      await chain.close();
      if (dir.startsWith(join(tmpdir(), "oxdeai-x402-gb-"))) rmSync(dir, { recursive: true, force: true });
    },
  };
}

test("GB1 Guarded Buyer: one authorized x402 purchase builds the brief; the unapproved purchase is denied before any payment", async () => {
  const w = await world();
  try {
    const lines: string[] = [];
    const ev = await runBuyer(["--catalog", w.catalogFile, "--topic", "Acme", "--deny-demo"], w.env, (l) => lines.push(l), { endpoints: { [ORIGIN]: w.seller.url } });
    const r = ev.results as Record<string, any>;
    assert.equal(r.authorized.decision, "ALLOW", lines.join("\n"));
    assert.match(r.brief, /# OxBuy brief: Acme/);
    assert.match(r.brief, /\*\*espresso\*\* \(2\)/);
    assert.match(r.brief, /@alice/);
    assert.deepEqual([r.denied.stage, r.denied.decision], ["authorize", "DENY"], JSON.stringify(r.denied));
    const t = w.chain.transfers();
    assert.deepEqual([t.length, t[0]!.from, t[0]!.to, t[0]!.value], [1, w.payer, w.payee, PRICE], "only the authorized purchase paid");
    assert.equal(r.spent, PRICE.toString(), "budget settled at the paid amount");
    const evidenceText = readFileSync(lines.find((l) => l.startsWith("evidence: "))!.slice(10), "utf8");
    assert.ok(!evidenceText.includes(w.keyHex), "no key in the evidence");
  } finally {
    await w.close();
  }
});

test("GB2 out-of-policy purchases never pay: above the per-call ceiling, then budget exhausted", async () => {
  const w = await world();
  try {
    const catalog = validateCatalog(w.catalog);
    const stack = createGuardedStack({
      catalog, rpc: createHttpRpc(w.rpcUrl), loadWalletKey: () => parsePrivateKey(w.keyHex), stateDir: join(w.dir, "s2"),
      endpoints: { [ORIGIN]: w.seller.url }, receiptTimeoutMs: 2_000, receiptPollMs: 50,
    });
    const buyer = createGuardedBuyer(stack, catalog);
    try {
      const s = catalog.services[0]!;
      const tooExpensive = await buyer.attempt({ ...requestFor(s, { body: { query: "x" } }), max_amount: "2001" });
      assert.deepEqual([tooExpensive.stage, tooExpensive.decision], ["authorize", "DENY"], JSON.stringify(tooExpensive));
      // Budget 2500, price 1000: two purchases fit, the third is denied by the PDP.
      for (const q of ["a", "b"]) assert.equal((await buyer.attempt(requestFor(s, { body: { query: q } }))).decision, "ALLOW");
      const third = await buyer.attempt(requestFor(s, { body: { query: "c" } }));
      assert.deepEqual([third.stage, third.decision], ["authorize", "DENY"], JSON.stringify(third));
      assert.match(String(third.reasons), /BUDGET/);
      assert.equal(w.chain.transfers().length, 2);
    } finally {
      stack.close();
    }
  } finally {
    await w.close();
  }
});

test("GB3 catalog validation refuses mainnet, non-https, unknown tokens and prices above the ceiling", () => {
  const ok = { network: "eip155:11142220", budget: "5000", per_call_max: "2000", services: [{ service_id: "s", method: "POST", url: "https://g.test/p", network: "eip155:11142220", asset: TESTNET_USDC.address, pay_to: "0x" + "11".repeat(20), max_price: "1000" }] };
  assert.equal(validateCatalog(ok).services.length, 1);
  const bad: [unknown, RegExp][] = [
    [{ ...ok, network: "eip155:42220" }, /NETWORK_NOT_AUTHORIZED:mainnet/],
    [{ ...ok, services: [{ ...ok.services[0], url: "http://g.test/p" }] }, /https/],
    [{ ...ok, services: [{ ...ok.services[0], asset: "0x765de816845861e75a25fca122bb6898b8b1282a" }] }, /ASSET_NOT_AUTHORIZED/],
    [{ ...ok, services: [{ ...ok.services[0], max_price: "2001" }] }, /max_price/],
    [{ ...ok, per_call_max: "6000" }, /per_call_max exceeds budget/],
  ];
  for (const [c, re] of bad) assert.throws(() => validateCatalog(c), re);
});

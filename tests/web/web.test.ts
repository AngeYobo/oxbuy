// SPDX-License-Identifier: MIT
/**
 * OxBuy web app, offline.
 *
 *   W1 every playground scenario reaches its expected decision at the expected layer; refusals never read the key
 *   W2 server: static page with CSP, status, scenario endpoint, input validation, live disabled by default
 *   W3 live endpoint end to end against SimChain + a simulated buy-style seller: one paid purchase with a brief,
 *      per-client cap, topic validation, a refused purchase does not use the allowance
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { addressOfPrivateKey, parsePrivateKey } from "../../src/chain/evm.ts";
import { runScenario, SCENARIOS } from "../../src/web/scenarios.ts";
import { createApp, liveConfig } from "../../src/web/server.ts";
import { startSeller } from "../../src/x402/seller.ts";
import { TESTNET_NETWORK, TESTNET_USDC } from "../../src/x402/testnet-profile.ts";
import { createSimChain, createSimFacilitator } from "../x402/sim.ts";

const EXPECT: Record<string, [string, string | undefined, RegExp | undefined]> = {
  allow: ["ALLOW", undefined, undefined],
  unapproved: ["DENY", "pdp", /ALLOWLIST_TARGET/],
  over_max: ["DENY", "pdp", /PER_ACTION_CAP_EXCEEDED/],
  tampered: ["DENY", "gateway", /INTENT_HASH_MISMATCH/],
  payto_swap: ["DENY", "executor", /RECIPIENT_MISMATCH/],
  price_raise: ["DENY", "executor", /EXCEEDS_AUTHORIZED_MAX/],
  replay: ["DENY", "gateway", /REPLAY/],
  expired: ["DENY", "gateway", /EXPIRED/],
};

test("W1 playground scenarios: expected decision, layer and reason; refusals never read the key; replay pays once", async () => {
  assert.deepEqual(SCENARIOS.map((s) => s.id).sort(), Object.keys(EXPECT).sort());
  for (const s of SCENARIOS) {
    const r = await runScenario(s.id);
    const [decision, layer, reason] = EXPECT[s.id]!;
    assert.equal(r.decision, decision, `${s.id}: ${JSON.stringify(r)}`);
    assert.equal(r.decision, s.expected, s.id);
    assert.equal(r.stoppedAt, layer, s.id);
    if (reason) assert.match(String(r.reason), reason, s.id);
    if (s.id === "allow" || s.id === "replay") {
      assert.equal(r.transfers.length, 1, s.id);
      assert.equal(r.keyReads, 1, s.id);
      assert.equal(r.nonceBoundToIntent, true, s.id);
    } else {
      assert.equal(r.transfers.length, 0, s.id);
      assert.equal(r.keyReads, 0, `${s.id}: the wallet key was never read`);
    }
  }
});

async function listen(app: ReturnType<typeof createApp>) {
  await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
  const post = async (path: string, body: unknown, ip = "1.1.1.1") => {
    const res = await fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": ip }, body: JSON.stringify(body) });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };
  return { base, post, close: () => new Promise<void>((r) => app.close(() => r())) };
}

test("W2 server: page with CSP, status, scenarios, validation; live purchases are off unless OXBUY_LIVE=1", async () => {
  const live = liveConfig({});
  assert.equal(live.enabled, false);
  const s = await listen(createApp({ live }));
  try {
    const page = await fetch(`${s.base}/`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get("content-security-policy") ?? "", /default-src 'self'/);
    assert.match(await page.text(), /<title>OxBuy<\/title>/);
    for (const p of ["/app.js", "/style.css", "/logo.png", "/favicon.png", "/api/health"]) assert.equal((await fetch(`${s.base}${p}`)).status, 200, p);
    assert.equal((await fetch(`${s.base}/../package.json`)).status, 404);
    const st = (await (await fetch(`${s.base}/api/status`)).json()) as Record<string, any>;
    assert.equal(st.live.enabled, false);
    assert.equal(st.scenarios.length, 8);
    const r = await s.post("/api/scenario", { id: "payto_swap" });
    assert.equal(r.status, 200);
    assert.equal(r.body.decision, "DENY");
    assert.equal((await s.post("/api/scenario", { id: "nope" })).status, 400);
    assert.equal((await s.post("/api/live", { topic: "celo" })).status, 403);
  } finally {
    await s.close();
  }
});

const ORIGIN = "https://gateway.usebuy.test";
const PATH = "/v1/social/x/posts/search";
const PRICE = 1000n;

test("W3 live endpoint (offline, simulated chain and seller): pays once with a brief; caps and validation hold; a refusal does not use the allowance", async () => {
  const dir = mkdtempSync(join(tmpdir(), "oxbuy-web-"));
  const keyHex = randomBytes(32).toString("hex");
  const payer = addressOfPrivateKey(parsePrivateKey(keyHex));
  const payee = addressOfPrivateKey(randomBytes(32));
  const chain = createSimChain({ network: TESTNET_NETWORK, asset: TESTNET_USDC, now: () => Math.floor(Date.now() / 1000) });
  const rpcUrl = await chain.listen();
  chain.mint(payer, 100_000n);
  const fac = createSimFacilitator(chain, TESTNET_NETWORK);
  const requirements = { scheme: "exact", network: TESTNET_NETWORK.caip2, amount: PRICE.toString(), asset: "0x01C5C0122039549AD1493B8220cABEdD739BC44E", payTo: payee, maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } };
  const posts = { data: [{ text: "Celo stablecoins are growing", author: { username: "alice" }, like_count: 4 }] };
  const seller = await startSeller({ publicOrigin: ORIGIN, x402Version: 1, facilitator: fac.client, routes: [{ method: "POST", path: PATH, description: "X post search", requirements, body: () => JSON.stringify(posts) }] });
  const catalogFile = join(dir, "catalog.json");
  writeFileSync(catalogFile, JSON.stringify({
    network: TESTNET_NETWORK.caip2,
    budget: "5000",
    per_call_max: "2000",
    services: [{ service_id: "buy-x-search", method: "POST", url: `${ORIGIN}${PATH}`, network: TESTNET_NETWORK.caip2, asset: TESTNET_USDC.address, pay_to: payee, max_price: PRICE.toString() }],
  }));
  const live = liveConfig({
    OXBUY_LIVE: "1",
    OXBUY_PAYER_KEY: keyHex,
    OXBUY_CATALOG_FILE: catalogFile,
    OXBUY_LIVE_MAX_PURCHASES: "3",
    OXBUY_LIVE_PER_CLIENT: "1",
    OXDEAI_TESTNET_RPC_URL: rpcUrl,
    OXDEAI_BUYER_STATE_DIR: join(dir, "state"),
    OXDEAI_BUYER_EVIDENCE_DIR: join(dir, "evidence"),
  });
  assert.equal(live.enabled, true);
  const s = await listen(createApp({ live, extra: { endpoints: { [ORIGIN]: seller.url } } }));
  try {
    const st = (await (await fetch(`${s.base}/api/status`)).json()) as Record<string, any>;
    assert.deepEqual([st.live.enabled, st.live.wallet, st.live.remaining], [true, payer, 3]);
    assert.equal((await s.post("/api/live", { topic: "<script>" })).status, 400);
    const r = await s.post("/api/live", { topic: "Celo stablecoins" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.decision, "ALLOW");
    assert.match(r.body.tx, /^0x[0-9a-f]{64}$/);
    assert.match(r.body.brief, /Celo stablecoins/);
    assert.equal(r.body.remaining, 2);
    assert.equal(chain.transfers().length, 1);
    assert.equal((await s.post("/api/live", { topic: "again" })).status, 409, "per-client cap");
    // The seller now asks too much: refused before signing, and the allowance is given back.
    seller.routes[0] = { ...seller.routes[0]!, requirements: { ...requirements, amount: (PRICE + 1n).toString() } as never };
    const d = await s.post("/api/live", { topic: "Celo" }, "2.2.2.2");
    assert.equal(d.status, 200);
    assert.equal(d.body.decision, "DENY", JSON.stringify(d.body));
    assert.equal(d.body.remaining, 2);
    assert.equal(chain.transfers().length, 1);
    const st2 = (await (await fetch(`${s.base}/api/status`)).json()) as Record<string, any>;
    assert.equal(st2.recent.length, 1);
    assert.equal(JSON.stringify(st2).includes(keyHex), false, "the key never appears in the API");
  } finally {
    await s.close();
    await seller.close();
    await chain.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

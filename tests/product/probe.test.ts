// SPDX-License-Identifier: MIT
/**
 * x402 probe CLI (no payment): PASS / FAIL verdict and exit code, against a simulated buy-style gateway (x402 v1).
 *   PR1 a Celo Sepolia offer in the configured token: "PROBE PASS", exit 0, catalog_entry with the offer's recipient and price
 *   PR2 mainnet-only offer: "PROBE FAIL", exit 3, nothing payable
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { test } from "node:test";
import { addressOfPrivateKey } from "../../src/chain/evm.ts";
import { startSeller } from "../../src/x402/seller.ts";
import { TESTNET_NETWORK } from "../../src/x402/testnet-profile.ts";
import { REPO_ROOT } from "../isolation/trusted-artifact.ts";

const run = (args: string[]) =>
  new Promise<{ code: number | null; out: string }>((resolve) => {
    const c = spawn(process.execPath, [join(REPO_ROOT, "src/testnet/x402-probe.ts"), ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    c.on("close", (code) => resolve({ code, out }));
  });

async function seller(network: string) {
  const payTo = addressOfPrivateKey(randomBytes(32));
  const s = await startSeller({
    publicOrigin: "https://gateway.usebuy.test",
    x402Version: 1,
    facilitator: { verify: async () => ({ isValid: false }), settle: async () => ({ success: false, transaction: "", network }), supported: async () => ({}) },
    routes: [{ method: "POST", path: "/v1/social/x/posts/search", description: "X search", requirements: { scheme: "exact", network, amount: "1000", asset: "0x01C5C0122039549AD1493B8220cABEdD739BC44E", payTo, maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } }, body: () => "{}" }],
  });
  return { s, payTo };
}

test("PR1 probe PASS on a payable Celo Sepolia offer (exit 0, catalog entry from the live 402)", async () => {
  const { s, payTo } = await seller(TESTNET_NETWORK.caip2);
  try {
    const r = await run(["POST", `${s.url}/v1/social/x/posts/search`, '{"query":"celo"}']);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /PROBE PASS/);
    assert.match(r.out, new RegExp(`"pay_to": "${payTo}"`));
    assert.match(r.out, /"max_price": "1000"/);
    assert.match(r.out, /"x402": 1/);
  } finally {
    await s.close();
  }
});

test("PR2 probe FAIL when only mainnet is offered (exit 3, no catalog entry)", async () => {
  const { s } = await seller("eip155:42220");
  try {
    const r = await run(["POST", `${s.url}/v1/social/x/posts/search`, '{"query":"celo"}']);
    assert.equal(r.code, 3, r.out);
    assert.match(r.out, /PROBE FAIL: no payable Celo Sepolia offer \(celo: network celo is not Celo Sepolia/);
    assert.doesNotMatch(r.out, /catalog_entry/);
  } finally {
    await s.close();
  }
});

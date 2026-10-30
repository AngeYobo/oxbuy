// SPDX-License-Identifier: MIT
/**
 * x402 v1 wire format (the Celo buy gateway: JSON 402 body, X-PAYMENT / X-PAYMENT-RESPONSE, network "celo-sepolia").
 * Same OxDeAI binding as v2: every check runs on the normalized live offer before signing.
 *
 *   V1-1 authorized payment settles once, proven on chain, budget settled
 *   V1-2 recipient, amount, network-name and asset mismatches are refused before any key read
 *   V1-3 v1 codec strictness and network mapping
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePaymentRequiredV1, v1NetworkToCaip2 } from "../../src/x402/wire.ts";
import { PRICE, x402World, type World } from "./harness.ts";

async function withV1(fn: (w: World) => Promise<void>) {
  const w = await x402World({ x402Version: 1 });
  try {
    await fn(w);
  } finally {
    await w.close();
  }
}
const setRoute = (w: World, over: Record<string, unknown>) => {
  w.seller.routes[0] = { ...w.route, requirements: { ...w.route.requirements, ...over } as never };
};

test("V1-1 x402 v1 authorized payment: one transfer of the live price to the authorized recipient, proven on chain, budget settled", () =>
  withV1(async (w) => {
    const a = await w.authorize();
    const r = await w.submit(a);
    assert.deepEqual([r.decision, r.executed], ["ALLOW", true], JSON.stringify(r));
    const t = w.chain.transfers();
    assert.deepEqual([t.length, t[0]!.to, t[0]!.value, t[0]!.nonce], [1, w.payee, PRICE, w.nonceFor(a.authorization.intent_hash)]);
    assert.equal(r.receipt.network, "eip155:11142220");
    await w.report();
    assert.equal((await w.reservation(a.authorization.auth_id)).state, "CONFIRMED");
    assert.notEqual((await w.submit(a)).decision, "ALLOW", "replay refused");
    assert.equal(w.chain.transfers().length, 1);
  }));

test("V1-2 x402 v1 mismatches are refused before the key is read: recipient, amount, unknown network name, asset", async () => {
  for (const over of [{ payTo: "0x000000000000000000000000000000000000dead" }, { amount: (PRICE + 1n).toString() }, { network: "x402v1:base" }, { asset: "0x765de816845861e75a25fca122bb6898b8b1282a" }]) {
    await withV1(async (w) => {
      const a = await w.authorize();
      setRoute(w, over);
      const r = await w.submit(a);
      assert.notEqual(r.decision, "ALLOW", JSON.stringify(over));
      assert.equal(w.wallet.loads, 0, `key read for ${JSON.stringify(over)}`);
      assert.equal(w.chain.transfers().length, 0);
    });
  }
});

test("V1-3 v1 codec: strict fields; only Celo network names map to CAIP-2", () => {
  const a = { scheme: "exact", network: "celo-sepolia", maxAmountRequired: "1000", asset: "0x01C5C0122039549AD1493B8220cABEdD739BC44E", payTo: "0x" + "11".repeat(20), resource: "https://x.test/p", description: "d", maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } };
  const [o] = parsePaymentRequiredV1({ x402Version: 1, error: "X-PAYMENT header is required", accepts: [a] });
  assert.deepEqual([o!.requirements.network, o!.requirements.amount, o!.wireNetwork, o!.resource], ["eip155:11142220", "1000", "celo-sepolia", "https://x.test/p"]);
  assert.equal(v1NetworkToCaip2("celo"), "eip155:42220");
  assert.equal(v1NetworkToCaip2("base"), "x402v1:base");
  for (const bad of [{ x402Version: 2, accepts: [a] }, { x402Version: 1, accepts: [] }, { x402Version: 1, accepts: [{ ...a, maxAmountRequired: "-1" }] }, { x402Version: 1, accepts: [{ ...a, resource: undefined }] }]) {
    assert.throws(() => parsePaymentRequiredV1(bad), /X402_MALFORMED/, JSON.stringify(bad));
  }
});

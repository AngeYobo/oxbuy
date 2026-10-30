// SPDX-License-Identifier: MIT
/**
 * LIVE Celo Sepolia test (real network, real facilitator, testnet funds). Skipped unless
 * OXDEAI_TESTNET_LIVE=1 and the variables of docs/TESTNET-X402.md §5 are set. Never runs in CI by
 * default; never touches mainnet (src/chain/networks.ts, and the chain-id check of runLiveDemo).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { runLiveDemo } from "../../src/testnet/live-demo.ts";

const live = process.env.OXDEAI_TESTNET_LIVE === "1";
test("LIVE-1 Celo Sepolia: authorized x402 payment settles on chain; replay, recipient and amount mismatches never pay; budget settled", { skip: live ? false : "NOT_TESTED here: set OXDEAI_TESTNET_LIVE=1 (docs/TESTNET-X402.md)", timeout: 300_000 }, async () => {
  const r = await runLiveDemo();
  assert.equal(r.ok, true, JSON.stringify(r.evidence.scenarios, null, 2));
});

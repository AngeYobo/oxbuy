// SPDX-License-Identifier: MIT
/**
 * Dry run of the live Celo Sepolia demonstration (src/testnet/live-demo.ts) against SimChain and a
 * simulated facilitator served over HTTP: the same code path the operator runs on testnet, minus the
 * real network. Proves the script logic, the HTTP facilitator client (X-API-Key sent),
 * and that the evidence file carries no secret. It is NOT evidence about Celo Sepolia.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { addressOfPrivateKey } from "../../src/chain/evm.ts";
import { TESTNET_NETWORK, TESTNET_USDC } from "../../src/x402/testnet-profile.ts";
import { runLiveDemo } from "../../src/testnet/live-demo.ts";
import { createSimChain, createSimFacilitator, serveFacilitator } from "./sim.ts";

test("LD1 live-demo dry run: L1-L5 pass against the simulator; the facilitator receives the API key; no secret in the evidence", async () => {
  const dir = mkdtempSync(join(tmpdir(), "oxdeai-x402-live-"));
  const key = randomBytes(32).toString("hex");
  const keyFile = join(dir, "payer.key");
  writeFileSync(keyFile, key, { mode: 0o600 });
  const payer = addressOfPrivateKey(Buffer.from(key, "hex"));
  const payTo = addressOfPrivateKey(randomBytes(32));
  const chain = createSimChain({ network: TESTNET_NETWORK, asset: TESTNET_USDC, now: () => Math.floor(Date.now() / 1000) });
  const rpcUrl = await chain.listen();
  chain.mint(payer, 50_000n);
  const apiKey = `test-${randomBytes(8).toString("hex")}`;
  const fac = await serveFacilitator(createSimFacilitator(chain, TESTNET_NETWORK).client, { apiKey });
  try {
    const lines: string[] = [];
    const r = await runLiveDemo(
      { OXDEAI_TESTNET_PAYER_KEY_FILE: keyFile, OXDEAI_TESTNET_PAY_TO: payTo, OXDEAI_X402_API_KEY: apiKey, OXDEAI_TESTNET_RPC_URL: rpcUrl, OXDEAI_X402_FACILITATOR_URL: fac.url, OXDEAI_TESTNET_EVIDENCE_DIR: join(dir, "evidence") },
      (l) => lines.push(l),
    );
    assert.equal(r.ok, true, lines.join("\n"));
    assert.deepEqual((r.evidence.scenarios as { id: string; result: string }[]).map((s) => s.result), ["PASS", "PASS", "PASS", "PASS", "PASS"]);
    assert.equal(chain.transfers().length, 1, "exactly one payment: L2-L4 never paid");
    assert.ok(fac.seenKeys.length >= 1 && fac.seenKeys.every((k) => k === apiKey));
    const text = readFileSync(r.evidencePath, "utf8");
    assert.ok(!text.includes(key) && !text.includes(apiKey), "no secret in the evidence file");
    // Refusals: wrong chain, open key file, missing config.
    chain.faults.chainIdOverride = 42220n;
    await assert.rejects(runLiveDemo({ OXDEAI_TESTNET_PAYER_KEY_FILE: keyFile, OXDEAI_TESTNET_PAY_TO: payTo, OXDEAI_X402_API_KEY: apiKey, OXDEAI_TESTNET_RPC_URL: rpcUrl }, () => undefined), /LIVE_WRONG_CHAIN:42220/);
    chain.faults.chainIdOverride = undefined;
    writeFileSync(join(dir, "open.key"), key, { mode: 0o644 });
    await assert.rejects(runLiveDemo({ OXDEAI_TESTNET_PAYER_KEY_FILE: join(dir, "open.key"), OXDEAI_TESTNET_PAY_TO: payTo, OXDEAI_X402_API_KEY: apiKey, OXDEAI_TESTNET_RPC_URL: rpcUrl }, () => undefined), /LIVE_KEY_FILE_TOO_OPEN/);
    await assert.rejects(runLiveDemo({}, () => undefined), /LIVE_CONFIG_MISSING:OXDEAI_TESTNET_PAYER_KEY_FILE/);
  } finally {
    await fac.close();
    await chain.close();
    if (dir.startsWith(join(tmpdir(), "oxdeai-x402-live-"))) rmSync(dir, { recursive: true, force: true });
  }
});

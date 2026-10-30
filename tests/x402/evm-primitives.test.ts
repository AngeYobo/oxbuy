// SPDX-License-Identifier: MIT
/**
 * EVM / EIP-3009 / x402 wire primitives.
 *
 *   EV1  EIP-712 constants equal the published typehashes; the signed example of the x402 v2 exact/EVM
 *        specification (Base Sepolia USDC) recovers to its stated payer: our digest is byte-exact with a
 *        signature produced by another implementation
 *   EV2  sign / recover round trip; low-s only; v in {27,28}; any change to a signed field changes the signer
 *   EV3  the EIP-3009 nonce is a deterministic function of the intent hash, distinct per intent
 *   EV4  x402 v2 header codecs are strict (version, encoding, amounts, required fields)
 *   EV5  JSON-RPC receipt parsing is strict
 *   EV6  network configuration: Celo Sepolia only; values as verified
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import {
  addressOfPrivateKey,
  EIP712_DOMAIN_TYPEHASH,
  eip3009NonceForIntent,
  hex,
  parsePrivateKey,
  recoverTransferAuthorizationSigner,
  signTransferAuthorization,
  TOPIC_TRANSFER,
  TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
} from "../../src/chain/evm.ts";
import { authorizedAsset, CELO_SEPOLIA } from "../../src/chain/networks.ts";
import { parseReceipt } from "../../src/chain/rpc.ts";
import { encodeHeader, parsePaymentPayload, parsePaymentRequired, parseSettleResponse } from "../../src/x402/wire.ts";

test("EV1 EIP-712 constants and the x402 specification's signed example (independent vector)", () => {
  assert.equal(hex(EIP712_DOMAIN_TYPEHASH), "0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");
  assert.equal(hex(TRANSFER_WITH_AUTHORIZATION_TYPEHASH), "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267");
  assert.equal(TOPIC_TRANSFER, "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
  // coinbase/x402 specs/schemes/exact/scheme_exact_evm.md (commit 0e6e8c55), PaymentPayload example.
  const domain = { name: "USDC", version: "2", chainId: 84532n, verifyingContract: "0x036cbd53842c5426634e7929541ec2318f3dcf7e" };
  const auth = {
    from: "0x857b06519e91e3a54538791bdbb0e22373e36b66",
    to: "0x209693bc6afc0c5328ba36faf03c514ef312287c",
    value: 10000n,
    validAfter: 1740672089n,
    validBefore: 1740672154n,
    nonce: "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480",
  };
  const sig = "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c";
  assert.equal(recoverTransferAuthorizationSigner(domain, auth, sig), auth.from);
  assert.notEqual(recoverTransferAuthorizationSigner({ ...domain, chainId: 11142220n }, auth, sig), auth.from, "the chain id is bound");
});

test("EV2 sign / recover round trip; every signed field is bound; malformed and high-s signatures are rejected", () => {
  const key = randomBytes(32);
  const me = addressOfPrivateKey(key);
  const d = { name: "USDC", version: "2", chainId: CELO_SEPOLIA.chainId, verifyingContract: CELO_SEPOLIA.assets[0]!.address };
  const a = { from: me, to: "0x" + "11".repeat(20), value: 1000n, validAfter: 1n, validBefore: 2n ** 40n, nonce: eip3009NonceForIntent("ab".repeat(32)) };
  const s = signTransferAuthorization(key, d, a);
  assert.match(s, /^0x[0-9a-f]{128}(1b|1c)$/);
  assert.equal(recoverTransferAuthorizationSigner(d, a, s), me);
  for (const changed of [{ to: "0x" + "22".repeat(20) }, { value: 1001n }, { validBefore: 3n }, { nonce: eip3009NonceForIntent("cd".repeat(32)) }]) {
    assert.notEqual(recoverTransferAuthorizationSigner(d, { ...a, ...changed }, s), me, JSON.stringify(changed, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
  }
  assert.notEqual(recoverTransferAuthorizationSigner({ ...d, verifyingContract: "0x" + "33".repeat(20) }, a, s), me, "the token contract is bound");
  assert.throws(() => recoverTransferAuthorizationSigner(d, a, s.slice(0, -2) + "1d"), /EVM_SIGNATURE_BAD_V/);
  assert.throws(() => recoverTransferAuthorizationSigner(d, a, "0x1234"), /EVM_SIGNATURE_MALFORMED/);
  // High-s twin of a valid signature: s' = n - s.
  const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const sHigh = (n - BigInt("0x" + s.slice(66, 130))).toString(16).padStart(64, "0");
  assert.throws(() => recoverTransferAuthorizationSigner(d, a, s.slice(0, 66) + sHigh + "1b"), /EVM_SIGNATURE_HIGH_S/);
  assert.throws(() => parsePrivateKey("0x" + "00".repeat(32)), /WALLET_KEY_INVALID/);
  assert.throws(() => parsePrivateKey("not a key"), /WALLET_KEY_MALFORMED/);
});

test("EV3 the EIP-3009 nonce is deterministic per intent and distinct across intents", () => {
  const i1 = "ab".repeat(32);
  assert.equal(eip3009NonceForIntent(i1), eip3009NonceForIntent(i1));
  assert.notEqual(eip3009NonceForIntent(i1), eip3009NonceForIntent("ac".repeat(32)));
  assert.match(eip3009NonceForIntent(i1), /^0x[0-9a-f]{64}$/);
  assert.throws(() => eip3009NonceForIntent("xyz"), /EVM_INTENT_HASH_INVALID/);
});

test("EV4 x402 v2 header codecs are strict", () => {
  const req = { scheme: "exact", network: "eip155:11142220", amount: "1000", asset: "0x01C5C0122039549AD1493B8220cABEdD739BC44E", payTo: "0x" + "11".repeat(20), maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } };
  const ok = parsePaymentRequired(encodeHeader({ x402Version: 2, resource: { url: "https://seller.oxdeai.test/v1/report" }, accepts: [req] }));
  assert.equal(ok.accepts[0]!.amount, "1000");
  for (const bad of [
    { x402Version: 1, resource: { url: "x" }, accepts: [req] },
    { x402Version: 2, resource: { url: "x" }, accepts: [] },
    { x402Version: 2, resource: { url: "x" }, accepts: [{ ...req, amount: "-1" }] },
    { x402Version: 2, resource: { url: "x" }, accepts: [{ ...req, amount: "01" }] },
    { x402Version: 2, resource: { url: "x" }, accepts: [{ ...req, maxTimeoutSeconds: 0 }] },
    { x402Version: 2, accepts: [req] },
  ]) {
    assert.throws(() => parsePaymentRequired(encodeHeader(bad)), /X402_MALFORMED/, JSON.stringify(bad));
  }
  assert.throws(() => parsePaymentRequired("not base64!"), /X402_MALFORMED:PAYMENT-REQUIRED:encoding/);
  assert.throws(() => parsePaymentRequired(undefined), /X402_MALFORMED/);
  assert.throws(() => parsePaymentPayload(encodeHeader({ x402Version: 2, accepted: req, payload: { signature: "0x", authorization: { from: "a", to: "b", value: "1.5", validAfter: "0", validBefore: "1", nonce: "n" } } })), /authorization.value/);
  assert.throws(() => parseSettleResponse({ success: "yes", transaction: "", network: "n" }), /X402_MALFORMED/);
  assert.deepEqual(parseSettleResponse({ success: false, errorReason: "settlement_pending", transaction: "0xab", network: "n" }).errorReason, "settlement_pending");
});

test("EV5 JSON-RPC receipt parsing is strict", () => {
  const h = "0x" + "aa".repeat(32);
  assert.equal(parseReceipt(null), null);
  const r = parseReceipt({ transactionHash: h, status: "0x1", blockNumber: "0x10", to: "0x" + "11".repeat(20), logs: [] })!;
  assert.deepEqual([r.status, r.blockNumber], [1, 16n]);
  for (const bad of [
    { transactionHash: "0x12", status: "0x1", blockNumber: "0x1", logs: [] },
    { transactionHash: h, status: "0x2", blockNumber: "0x1", logs: [] },
    { transactionHash: h, status: "0x1", blockNumber: "1", logs: [] },
    { transactionHash: h, status: "0x1", blockNumber: "0x1", logs: [{ address: "nope", topics: [], data: "0x" }] },
    { transactionHash: h, status: "0x1", blockNumber: "0x1" },
  ]) {
    assert.throws(() => parseReceipt(bad), /RPC_MALFORMED/, JSON.stringify(bad));
  }
});

test("EV6 network configuration: Celo Sepolia only, with the verified chain id, token and EIP-712 domain", () => {
  assert.deepEqual([CELO_SEPOLIA.caip2, CELO_SEPOLIA.chainId, CELO_SEPOLIA.testnet], ["eip155:11142220", 11142220n, true]);
  const usdc = authorizedAsset(CELO_SEPOLIA, "0x01C5C0122039549AD1493B8220cABEdD739BC44E");
  assert.deepEqual([usdc.address, usdc.decimals, usdc.eip712Name, usdc.eip712Version], ["0x01c5c0122039549ad1493b8220cabedd739bc44e", 6, "USDC", "2"]);
  assert.throws(() => authorizedAsset(CELO_SEPOLIA, "0xcebA9300f2b948710d2653dD7B07f33A8B32118C"), /ASSET_NOT_AUTHORIZED/, "the mainnet USDC address is not a testnet asset");
});

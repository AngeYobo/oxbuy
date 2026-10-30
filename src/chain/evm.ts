// SPDX-License-Identifier: MIT
/**
 * Minimal EVM primitives for EIP-3009 `transferWithAuthorization` (x402 `exact`, eip3009).
 *
 * Cryptography comes only from the audited @noble libraries (keccak-256, secp256k1 with low-s
 * signatures); this module only encodes. Every hex string is lower-case 0x-prefixed.
 *
 *   EIP-712 digest = keccak256(0x1901 || domainSeparator || hashStruct(TransferWithAuthorization))
 *   signature      = r || s || v  (65 bytes, v = 27 + recovery bit)
 *
 * Deterministic nonce (OxDeAI binding): the EIP-3009 nonce of a payment is derived from the OxDeAI
 * intent hash, which is unique per authorization (intent_ref carries a fresh intent id and nonce).
 * The token contract accepts a (payer, nonce) pair at most once, ever, so one authorized intent can
 * settle at most one transfer on chain, whatever happens to the executor's own state.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export const HEX32 = /^0x[0-9a-f]{64}$/;
export const ADDRESS = /^0x[0-9a-f]{40}$/;

export const hex = (b: Uint8Array): string => `0x${bytesToHex(b)}`;
export const unhex = (h: string): Uint8Array => hexToBytes(h.startsWith("0x") ? h.slice(2) : h);
export const keccak = (b: Uint8Array): Uint8Array => keccak_256(b);
export const keccakText = (s: string): Uint8Array => keccak_256(utf8ToBytes(s));

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** ABI word for a uint256 (throws outside [0, 2^256)). */
export function word(n: bigint): Uint8Array {
  if (n < 0n || n >= 1n << 256n) throw new Error("EVM_UINT256_RANGE");
  return unhex(n.toString(16).padStart(64, "0"));
}
/** ABI word for an address. */
export function addressWord(a: string): Uint8Array {
  if (!ADDRESS.test(a)) throw new Error(`EVM_ADDRESS_INVALID:${a}`);
  return concat(new Uint8Array(12), unhex(a));
}
function bytes32Word(h: string): Uint8Array {
  if (!HEX32.test(h)) throw new Error(`EVM_BYTES32_INVALID:${h}`);
  return unhex(h);
}

export type Eip712Domain = { readonly name: string; readonly version: string; readonly chainId: bigint; readonly verifyingContract: string };

export type TransferAuthorization = {
  readonly from: string;
  readonly to: string;
  readonly value: bigint;
  readonly validAfter: bigint;
  readonly validBefore: bigint;
  /** bytes32, lower-case hex. */
  readonly nonce: string;
};

export const EIP712_DOMAIN_TYPEHASH = keccakText("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
export const TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccakText(
  "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
);

export function domainSeparator(d: Eip712Domain): Uint8Array {
  return keccak(concat(EIP712_DOMAIN_TYPEHASH, keccakText(d.name), keccakText(d.version), word(d.chainId), addressWord(d.verifyingContract)));
}

export function transferAuthorizationDigest(d: Eip712Domain, a: TransferAuthorization): Uint8Array {
  const struct = keccak(
    concat(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, addressWord(a.from), addressWord(a.to), word(a.value), word(a.validAfter), word(a.validBefore), bytes32Word(a.nonce)),
  );
  return keccak(concat(new Uint8Array([0x19, 0x01]), domainSeparator(d), struct));
}

/** Lower-case address of an uncompressed or compressed secp256k1 public key. */
export function addressOfPublicKey(pub: Uint8Array): string {
  const uncompressed = pub.length === 65 ? pub : secp256k1.Point.fromBytes(pub).toBytes(false);
  return hex(keccak(uncompressed.slice(1)).slice(12));
}

export function addressOfPrivateKey(priv: Uint8Array): string {
  return addressOfPublicKey(secp256k1.getPublicKey(priv, false));
}

/** 65-byte r||s||v signature (low-s, v in {27, 28}) over a 32-byte digest. */
export function signDigest(priv: Uint8Array, digest: Uint8Array): string {
  const rec = secp256k1.sign(digest, priv, { prehash: false, format: "recovered", lowS: true });
  // noble "recovered" layout: recovery byte, then r (32), s (32).
  return hex(concat(rec.slice(1, 65), new Uint8Array([27 + rec[0]!])));
}

/** Recover the signer of a 65-byte r||s||v signature; throws on a malformed or high-s signature. */
export function recoverDigestSigner(digest: Uint8Array, signature: string): string {
  if (!/^0x[0-9a-f]{130}$/.test(signature)) throw new Error("EVM_SIGNATURE_MALFORMED");
  const b = unhex(signature);
  const v = b[64]!;
  if (v !== 27 && v !== 28) throw new Error("EVM_SIGNATURE_BAD_V");
  const rs = b.slice(0, 64);
  const sig = secp256k1.Signature.fromBytes(rs, "compact");
  if (sig.hasHighS()) throw new Error("EVM_SIGNATURE_HIGH_S");
  const pub = sig.addRecoveryBit(v - 27).recoverPublicKey(digest).toBytes(false);
  return addressOfPublicKey(pub);
}

export function signTransferAuthorization(priv: Uint8Array, d: Eip712Domain, a: TransferAuthorization): string {
  return signDigest(priv, transferAuthorizationDigest(d, a));
}

export function recoverTransferAuthorizationSigner(d: Eip712Domain, a: TransferAuthorization, signature: string): string {
  return recoverDigestSigner(transferAuthorizationDigest(d, a), signature);
}

/** EIP-3009 nonce bound to one OxDeAI intent (see header). */
export function eip3009NonceForIntent(intentHash: string): string {
  if (!/^[0-9a-f]{64}$/.test(intentHash)) throw new Error("EVM_INTENT_HASH_INVALID");
  return hex(sha256(concat(utf8ToBytes("oxdeai-celo-poc/x402-eip3009-nonce/v1\u0000"), unhex(intentHash))));
}

// ── ABI helpers for the reads the executor needs ────────────────────────────

export const selector = (sig: string): string => hex(keccakText(sig).slice(0, 4));
export const topic = (sig: string): string => hex(keccakText(sig));

export const SEL_AUTHORIZATION_STATE = selector("authorizationState(address,bytes32)");
export const TOPIC_TRANSFER = topic("Transfer(address,address,uint256)");
export const TOPIC_AUTHORIZATION_USED = topic("AuthorizationUsed(address,bytes32)");
export const TOPIC_AUTHORIZATION_CANCELED = topic("AuthorizationCanceled(address,bytes32)");

export const SEL_BALANCE_OF = selector("balanceOf(address)");
export const encodeBalanceOf = (owner: string): string => SEL_BALANCE_OF + bytesToHex(addressWord(owner));

export function encodeAuthorizationState(authorizer: string, nonce: string): string {
  return SEL_AUTHORIZATION_STATE + bytesToHex(addressWord(authorizer)) + bytesToHex(bytes32Word(nonce));
}

/** Topic encoding of an indexed address. */
export const addressTopic = (a: string): string => hex(addressWord(a));

/** A 32-byte ABI word as bigint (strict). */
export function decodeWord(h: string): bigint {
  if (!HEX32.test(h)) throw new Error("EVM_WORD_MALFORMED");
  return BigInt(h);
}

/** Lower-case private key bytes from a 0x-prefixed or bare 64-hex string; rejects anything else. */
export function parsePrivateKey(text: string): Uint8Array {
  const t = text.trim().toLowerCase();
  const h = t.startsWith("0x") ? t.slice(2) : t;
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error("WALLET_KEY_MALFORMED");
  const b = unhex(h);
  if (!secp256k1.utils.isValidSecretKey(b)) throw new Error("WALLET_KEY_INVALID");
  return b;
}

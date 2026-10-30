// SPDX-License-Identifier: MIT
/**
 * On-chain evidence for an EIP-3009 payment (x402 `exact`, eip3009), read through JSON-RPC.
 *
 * What the chain proves, and what it does not:
 *   - A mined, successful transaction whose receipt carries, FROM THE TOKEN CONTRACT,
 *       AuthorizationUsed(authorizer = payer, nonce)  and  Transfer(from = payer, to = payTo, value)
 *     proves that exactly this signed authorization settled, for `value`. This is the only accepted
 *     evidence of settlement.
 *   - `authorizationState(payer, nonce) == true` proves the nonce is consumed (used OR canceled); it
 *     is a necessary condition, never sufficient on its own.
 *   - A pending, unknown, dropped or reverted transaction proves nothing: the signed authorization may
 *     still settle (by any submitter) until `validBefore`.
 */
import { HEX32, addressTopic, decodeWord, encodeAuthorizationState, TOPIC_AUTHORIZATION_USED, TOPIC_TRANSFER } from "./evm.ts";
import type { EvmNetwork } from "./networks.ts";
import type { EvmRpc, RpcReceipt } from "./rpc.ts";

export type Eip3009Binding = {
  readonly asset: string;
  readonly payer: string;
  readonly payTo: string;
  readonly nonce: string;
};

export type OnchainSettlement = {
  readonly kind: "EIP3009_ONCHAIN";
  /** Transaction hash. */
  readonly reference: string;
  readonly amount: string;
  readonly network: string;
  readonly asset: string;
  readonly payer: string;
  readonly pay_to: string;
  readonly nonce: string;
  readonly block: string;
};

export async function authorizationConsumed(rpc: EvmRpc, b: Pick<Eip3009Binding, "asset" | "payer" | "nonce">): Promise<boolean> {
  const out = await rpc.call(b.asset, encodeAuthorizationState(b.payer, b.nonce));
  const v = decodeWord(out);
  if (v !== 0n && v !== 1n) throw new Error("EVIDENCE_INVALID:authorizationState is not a bool");
  return v === 1n;
}

/** The settled value if the receipt carries exactly this authorization's settlement, else null. */
export function settlementInReceipt(r: RpcReceipt, b: Eip3009Binding): bigint | null {
  if (r.status !== 1) return null;
  const fromToken = r.logs.filter((l) => l.address === b.asset);
  const used = fromToken.filter((l) => l.topics[0] === TOPIC_AUTHORIZATION_USED && l.topics[1] === addressTopic(b.payer) && l.topics[2] === b.nonce);
  const transfers = fromToken.filter((l) => l.topics[0] === TOPIC_TRANSFER && l.topics[1] === addressTopic(b.payer) && l.topics[2] === addressTopic(b.payTo));
  if (used.length !== 1 || transfers.length !== 1) return null;
  return decodeWord(transfers[0]!.data);
}

/**
 * Settlement evidence for one payment: the receipt of `txHash` must carry this authorization's
 * settlement, for at most `maxAmount`, and the nonce must be consumed. Throws EVIDENCE_INVALID:* or
 * NO_SETTLEMENT_EVIDENCE:* otherwise (absence is never proof of non-execution).
 */
export async function verifyOnchainSettlement(
  rpc: EvmRpc,
  network: EvmNetwork,
  want: Eip3009Binding & { readonly maxAmount: bigint; readonly signedAmount: bigint; readonly txHash: string },
): Promise<OnchainSettlement> {
  if (!HEX32.test(want.txHash.toLowerCase())) throw new Error("EVIDENCE_INVALID:transaction hash malformed");
  const chainId = await rpc.chainId();
  if (chainId !== network.chainId) throw new Error(`EVIDENCE_INVALID:chain id ${chainId} is not ${network.chainId}`);
  const r = await rpc.receipt(want.txHash);
  if (r === null) throw new Error(`NO_SETTLEMENT_EVIDENCE:transaction ${want.txHash} not mined (pending, dropped or unknown)`);
  if (typeof r.transactionHash !== "string" || !HEX32.test(r.transactionHash.toLowerCase()) || r.transactionHash.toLowerCase() !== want.txHash.toLowerCase()) throw new Error("EVIDENCE_INVALID:receipt transaction hash mismatch");
  if (r.status !== 1) throw new Error(`NO_SETTLEMENT_EVIDENCE:transaction ${want.txHash} reverted (the authorization may still settle until validBefore)`);
  const value = settlementInReceipt(r, want);
  if (value === null) throw new Error(`EVIDENCE_INVALID:transaction ${want.txHash} does not carry this authorization's AuthorizationUsed + Transfer`);
  if (value <= 0n || value > want.maxAmount) throw new Error("EVIDENCE_INVALID:amount outside the authorization");
  if (value !== want.signedAmount) throw new Error("EVIDENCE_INVALID:amount differs from signed payment");
  if (!(await authorizationConsumed(rpc, want))) throw new Error("EVIDENCE_INVALID:nonce not consumed on chain");
  return {
    kind: "EIP3009_ONCHAIN",
    reference: r.transactionHash,
    amount: value.toString(),
    network: network.caip2,
    asset: want.asset,
    payer: want.payer,
    pay_to: want.payTo,
    nonce: want.nonce,
    block: r.blockNumber.toString(),
  };
}

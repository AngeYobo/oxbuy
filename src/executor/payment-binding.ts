// SPDX-License-Identifier: MIT
/** Validate signed payment evidence; persistence and identity association use the protected checkpoint. */
import { eip3009NonceForIntent, recoverTransferAuthorizationSigner } from "../chain/evm.ts";
import { authorizedAsset, authorizedTestnet } from "../chain/networks.ts";
import type { PaymentBinding, PaymentJournalRecord } from "./payment-journal.ts";

export function validatePaymentBinding(r: PaymentJournalRecord, b: PaymentBinding): void {
  try {
    const net = authorizedTestnet(r.request.network);
    const asset = authorizedAsset(net, r.request.asset);
    const decimal = /^(0|[1-9][0-9]*)$/;
    if (!b || ![b.amount, b.chain_id, b.valid_after, b.valid_before].every((x) => typeof x === "string" && decimal.test(x)) ||
        b.intent_hash !== r.intent_hash || b.claim_id !== r.claim_id || !r.claim_id ||
        b.chain_id !== net.chainId.toString() || b.asset !== asset.address || b.recipient !== r.request.recipient ||
        b.nonce !== eip3009NonceForIntent(r.intent_hash) || BigInt(b.amount) <= 0n || BigInt(b.amount) > BigInt(r.request.max_amount) ||
        BigInt(b.valid_after) >= BigInt(b.valid_before)) throw new Error("binding mismatch");
    const signer = recoverTransferAuthorizationSigner(
      { name: asset.eip712Name, version: asset.eip712Version, chainId: net.chainId, verifyingContract: asset.address },
      { from: b.payer, to: b.recipient, value: BigInt(b.amount), validAfter: BigInt(b.valid_after), validBefore: BigInt(b.valid_before), nonce: b.nonce }, b.signature);
    if (signer !== b.payer) throw new Error("signer mismatch");
  } catch {
    throw new Error("PAYMENT_BINDING_INVALID");
  }
}

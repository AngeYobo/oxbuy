// SPDX-License-Identifier: MIT
/**
 * Durable mock settlement for the executor process.
 *
 * Stands in for the two things a real buy deployment protects: the wallet
 * credential and the chain. `pay` must read the mock wallet key before
 * signing, and a payment exists only once it is appended to the ledger file.
 * Both files live in the executor's private directory, so code running as
 * another OS identity cannot pay even if it imports this module: it cannot
 * read the key or append to the ledger.
 *
 * The key is random bytes, not a blockchain key; the ledger is not a chain.
 */
import { createHmac } from "node:crypto";
import { closeSync, existsSync, fchmodSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { PaymentRefusedError, type PaymentAdapter, type PaymentReceipt } from "../../executor/payment-adapter.ts";

export type MockSettlementPaths = { readonly walletKeyPath: string; readonly ledgerPath: string };

export type MockLedgerEntry = { readonly intent_hash: string; readonly receipt: PaymentReceipt; readonly mac: string };

export function withMockSettlement(inner: PaymentAdapter, paths: MockSettlementPaths): PaymentAdapter {
  return {
    quote: (request) => inner.quote(request),
    async pay(payment) {
      let key: Buffer;
      try {
        key = readFileSync(paths.walletKeyPath);
      } catch (err) {
        // Nothing has been signed without the key.
        throw new PaymentRefusedError(`MOCK_WALLET_UNAVAILABLE:${(err as NodeJS.ErrnoException).code ?? "ERROR"}`);
      }
      const receipt = await inner.pay(payment);
      const mac = createHmac("sha256", key).update(receipt.reference).digest("hex");
      // Settlement: the payment exists once this line is durable. A failure
      // here is not "nothing signed", so it propagates as a plain error.
      const fd = openSync(paths.ledgerPath, "a", 0o600);
      try {
        fchmodSync(fd, 0o600);
        writeSync(fd, `${JSON.stringify({ intent_hash: payment.intent_hash, receipt, mac } satisfies MockLedgerEntry)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return receipt;
    },
  };
}

export function readMockLedger(ledgerPath: string): MockLedgerEntry[] {
  if (!existsSync(ledgerPath)) return [];
  return readFileSync(ledgerPath, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as MockLedgerEntry);
}

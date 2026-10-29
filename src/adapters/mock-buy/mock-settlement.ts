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
 *
 * Phase 2D (D5): each ledger entry is bound to the payment's intent, its
 * execution claim, and the executor's journal (execution domain) by an HMAC
 * under the wallet key, which persists with the executor state root. Only the
 * executor identity can verify it (`verifySettlementEvidence`), and a
 * verified entry is the only accepted evidence that an uncertain claim
 * settled. Trust assumption: whoever holds the wallet key (the executor
 * identity, root) could forge an entry; for a real rail the evidence would be
 * the chain itself. There is no evidence of non-execution: a missing entry
 * proves nothing (a crash can precede the append while the payment exists).
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { closeSync, existsSync, fchmodSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import type { PurchaseRequest } from "../../agent/purchase-request.ts";
import { canonicalJson } from "../../executor/outcome-report.ts";
import { PaymentRefusedError, type PaymentAdapter, type PaymentReceipt } from "../../executor/payment-adapter.ts";
import type { SettlementEvidence } from "../../executor/payment-journal.ts";

export type MockSettlementPaths = { readonly walletKeyPath: string; readonly ledgerPath: string; readonly journalId: string };

export type MockLedgerEntry = {
  readonly intent_hash: string;
  readonly claim_id?: string;
  readonly journal_id?: string;
  readonly receipt: PaymentReceipt;
  readonly mac: string;
};

const macOf = (key: Buffer, e: Omit<MockLedgerEntry, "mac">) =>
  createHmac("sha256", key).update(canonicalJson({ intent_hash: e.intent_hash, claim_id: e.claim_id, journal_id: e.journal_id, receipt: e.receipt })).digest("hex");

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
      const entry = { intent_hash: payment.intent_hash, claim_id: payment.claim_id, journal_id: paths.journalId, receipt };
      const mac = macOf(key, entry);
      // Settlement: the payment exists once this line is durable. A failure
      // here is not "nothing signed", so it propagates as a plain error.
      const fd = openSync(paths.ledgerPath, "a", 0o600);
      try {
        fchmodSync(fd, 0o600);
        writeSync(fd, `${JSON.stringify({ ...entry, mac } satisfies MockLedgerEntry)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return receipt;
    },
  };
}

/**
 * Ledger entries. A final line that is not complete JSON (crash during the
 * append, before fsync returned) is not a payment and is skipped; an
 * unparsable line anywhere else is corruption and throws.
 */
export function readMockLedger(ledgerPath: string): MockLedgerEntry[] {
  if (!existsSync(ledgerPath)) return [];
  return parseMockLedger(readFileSync(ledgerPath, "utf8"));
}

export function parseMockLedger(text: string): MockLedgerEntry[] {
  const lines = text.split("\n").filter((line) => line !== "");
  const out: MockLedgerEntry[] = [];
  lines.forEach((line, i) => {
    try {
      out.push(JSON.parse(line) as MockLedgerEntry);
    } catch {
      if (i !== lines.length - 1 || text.endsWith("\n")) throw new Error(`LEDGER_CORRUPT:line ${i + 1}`);
    }
  });
  return out;
}

const ATOMIC = /^(0|[1-9][0-9]{0,30})$/;

/**
 * Settlement evidence for one claim (D5; run as the executor identity, which
 * alone can read the wallet key). Exactly one ledger entry for the intent,
 * with a valid MAC binding the intent, this claim, and this journal, and a
 * settled receipt inside the authorized binding. Anything else throws and
 * the reservation stays charged: NO_SETTLEMENT_EVIDENCE (absence is never
 * proof of non-execution), CONFLICTING_EVIDENCE, EVIDENCE_INVALID:*.
 */
export function verifySettlementEvidence(
  paths: { walletKeyPath: string; ledgerPath: string },
  want: { intent_hash: string; claim_id: string; journal_id: string; request: PurchaseRequest },
): SettlementEvidence {
  const key = readFileSync(paths.walletKeyPath);
  const entries = readMockLedger(paths.ledgerPath).filter((e) => e.intent_hash === want.intent_hash);
  if (entries.length === 0) throw new Error("NO_SETTLEMENT_EVIDENCE:no ledger entry (not proof of non-execution)");
  if (entries.length > 1) throw new Error(`CONFLICTING_EVIDENCE:${entries.length} ledger entries for the intent`);
  const e = entries[0]!;
  const expected = Buffer.from(macOf(key, e), "hex");
  const got = Buffer.from(typeof e.mac === "string" ? e.mac : "", "hex");
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) throw new Error("EVIDENCE_INVALID:mac");
  if (e.claim_id !== want.claim_id) throw new Error("EVIDENCE_INVALID:claim_id");
  if (e.journal_id !== want.journal_id) throw new Error("EVIDENCE_INVALID:journal_id");
  const r = e.receipt as Partial<PaymentReceipt> & { settled?: unknown };
  if (r.settled !== true || typeof r.reference !== "string" || typeof r.amount !== "string" || !ATOMIC.test(r.amount)) throw new Error("EVIDENCE_INVALID:receipt");
  if (BigInt(r.amount) > BigInt(want.request.max_amount)) throw new Error("EVIDENCE_INVALID:amount exceeds the authorization");
  if (r.network !== want.request.network || r.asset !== want.request.asset || String(r.pay_to).toLowerCase() !== want.request.recipient) {
    throw new Error("EVIDENCE_INVALID:outside the authorized binding");
  }
  return { kind: "MOCK_LEDGER_MAC", reference: r.reference, mac: e.mac, amount: r.amount };
}

// SPDX-License-Identifier: MIT
/**
 * Executor outcome reports (Phase 2C; F3).
 *
 * The executor tells the authorization service what its durable journal holds
 * for an auth_id, so the reservation for that authorization can move
 * (src/authorization/reservations.ts). A report is derived from the journal
 * (`deriveOutcome`), never from what a caller says, and it is signed with the
 * executor's own Ed25519 key, which no other identity can read.
 *
 * Endpoint authorization does not rest on the signature alone: reports are
 * delivered only over the dedicated settle socket, which only the executor
 * identity can reach, and every request carries a peer-identity proof whose
 * owner the kernel attests (src/isolation/settle-channel.ts).
 *
 * Replay and duplicates: a report is a statement about one auth_id's journal
 * state. Applying it is idempotent (ALREADY_APPLIED), an older report cannot
 * move a reservation backwards (STALE), and `report_id` binds the exact
 * content. Reports are re-derived and re-sent until acknowledged, so a crash
 * on either side can only cause a duplicate, never a lost or invented outcome.
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { NOT_EXECUTED_REASONS, OUTCOMES, type NotExecutedReason, type Outcome, type OutcomeFacts } from "../authorization/reservations.ts";
import type { AuthRecord, PaymentJournalRecord } from "./payment-journal.ts";

export const REPORT_TYPE = "oxdeai-celo-poc/outcome-report/v1";

export type OutcomeReport = {
  readonly type: typeof REPORT_TYPE;
  readonly auth_id: string;
  readonly intent_hash: string;
  readonly outcome: Outcome;
  readonly reason?: NotExecutedReason;
  readonly amount?: string;
  /** The reporting journal (execution domain, src/executor/execution-domain.ts). */
  readonly journal_id: string;
  readonly executor_kid: string;
};

export type SignedReport = { readonly report: OutcomeReport; readonly signature: string };

export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

export const reportId = (r: OutcomeReport) => createHash("sha256").update(canonicalJson(r)).digest("hex");

export function signReport(report: OutcomeReport, privateKeyPem: string): SignedReport {
  return { report, signature: sign(null, Buffer.from(canonicalJson(report)), createPrivateKey(privateKeyPem)).toString("base64") };
}

const REPORT_KEYS = new Set(["type", "auth_id", "intent_hash", "outcome", "reason", "amount", "journal_id", "executor_kid"]);

/** Verify shape and signature against the trusted executor key. Throws REPORT_INVALID:*. Returns the facts and the reporting journal. */
export function verifyReport(signed: unknown, trusted: { publicKeyPem: string; kid: string }): OutcomeFacts & { journal_id: string } {
  const s = signed as Partial<SignedReport> | null;
  if (typeof s !== "object" || s === null || typeof s.signature !== "string" || typeof s.report !== "object" || s.report === null) {
    throw new Error("REPORT_INVALID:shape");
  }
  const r = s.report;
  if (Object.keys(r).some((k) => !REPORT_KEYS.has(k))) throw new Error("REPORT_INVALID:keys");
  if (r.type !== REPORT_TYPE) throw new Error("REPORT_INVALID:type");
  if (r.executor_kid !== trusted.kid) throw new Error("REPORT_INVALID:kid");
  if (typeof r.auth_id !== "string" || r.auth_id === "" || typeof r.intent_hash !== "string" || !/^[0-9a-f]{64}$/.test(r.intent_hash)) {
    throw new Error("REPORT_INVALID:ids");
  }
  if (typeof r.journal_id !== "string" || !/^[0-9a-f]{32}$/.test(r.journal_id)) throw new Error("REPORT_INVALID:journal_id");
  if (!OUTCOMES.includes(r.outcome as Outcome)) throw new Error("REPORT_INVALID:outcome");
  if (r.reason !== undefined && !NOT_EXECUTED_REASONS.includes(r.reason)) throw new Error("REPORT_INVALID:reason");
  const ok = verify(null, Buffer.from(canonicalJson(r)), createPublicKey(trusted.publicKeyPem), Buffer.from(s.signature, "base64"));
  if (!ok) throw new Error("REPORT_INVALID:signature");
  return {
    auth_id: r.auth_id,
    intent_hash: r.intent_hash,
    outcome: r.outcome as Outcome,
    ...(r.reason !== undefined ? { reason: r.reason } : {}),
    ...(r.amount !== undefined ? { amount: r.amount } : {}),
    report_id: reportId(r as OutcomeReport),
    journal_id: r.journal_id,
  };
}

/**
 * What the journal durably says about an auth_id, as an outcome. `inFlight`:
 * the intent is being paid right now by this process. Returns null when
 * there is nothing reportable (unreadable auth record: consumed, never
 * released).
 */
export function deriveOutcome(
  auth: AuthRecord,
  intent: PaymentJournalRecord | undefined,
  inFlight: boolean,
): { outcome: Outcome; reason?: NotExecutedReason; amount?: string } | null {
  if (auth.detail === "JOURNAL_RECORD_UNREADABLE" || auth.auth_id === "") return null;
  if (auth.disposition === "REJECTED_BEFORE_EXECUTION") return { outcome: "NOT_EXECUTED", reason: "REJECTED_BEFORE_EXECUTION" };
  if (auth.disposition === "CANCELLED") return { outcome: "NOT_EXECUTED", reason: "CANCELLED" };
  // RESERVED: `pay` is only called after the intent record is durable.
  if (intent === undefined) return inFlight ? { outcome: "EXECUTING" } : { outcome: "NOT_EXECUTED", reason: "NOT_STARTED" };
  if (intent.auth_id !== auth.auth_id) return null; // intent belongs to another authorization
  if (intent.resolution) {
    return intent.resolution.verdict === "SETTLED" ? { outcome: "RESOLVED_SETTLED" } : { outcome: "RESOLVED_NOT_SETTLED" };
  }
  switch (intent.state) {
    case "STARTED":
      return inFlight ? { outcome: "EXECUTING" } : { outcome: "UNCERTAIN" };
    case "SETTLED": {
      const amount = (intent.receipt as { amount?: unknown } | undefined)?.amount;
      return typeof amount === "string" ? { outcome: "SETTLED", amount } : { outcome: "UNCERTAIN" };
    }
    case "REFUSED_BEFORE_SIGNING":
      return { outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING" };
    default:
      return { outcome: "UNCERTAIN" };
  }
}

/** Ack key: one acknowledgement per distinct outcome (and reason) of an auth_id. */
export const ackKey = (o: { outcome: Outcome; reason?: NotExecutedReason }) => (o.reason ? `${o.outcome}-${o.reason}` : o.outcome);

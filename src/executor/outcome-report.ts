// SPDX-License-Identifier: MIT
/**
 * Signed executor -> authorization service messages (Phase 2C; F3) and the
 * Phase 2D execution claim (architecture C, src/authorization/reservations.ts).
 *
 * Three message types, each with its own type string (one cannot be replayed
 * as another) and each signed with the executor's own Ed25519 key, which no
 * other identity can read:
 *   CLAIM   {auth_id, intent_hash, claim_id}           RESERVED -> EXECUTING(claim_id), before `pay`
 *   VOID    {auth_id, intent_hash, reason, claim_id?}   synchronous pre-execution rejection or claim abandonment
 *   REPORT  {auth_id, intent_hash, claim_id, outcome}   what the journal durably holds for that claim
 * All carry the reporting `journal_id` (execution domain).
 *
 * Endpoint authorization does not rest on the signature alone: messages are
 * delivered only over the dedicated settle socket, which only the executor
 * identity can reach, and every request carries a peer-identity proof whose
 * owner the kernel attests (src/isolation/settle-channel.ts).
 *
 * Reports are derived from the journal (`deriveOutcome`), never from what a
 * caller says, and only from POSITIVE records bound to a claim: a missing
 * record is never reported as non-execution. Applying a report is
 * idempotent; `report_id` binds the exact content.
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import {
  CLAIM_ID,
  NOT_EXECUTED_REASONS,
  OUTCOMES,
  VOID_REASONS,
  type NotExecutedReason,
  type Outcome,
  type OutcomeFacts,
  type VoidReason,
} from "../authorization/reservations.ts";
import type { AuthRecord, PaymentJournalRecord } from "./payment-journal.ts";

export const REPORT_TYPE = "oxdeai-celo-poc/outcome-report/v2";
export const CLAIM_TYPE = "oxdeai-celo-poc/execution-claim/v1";
export const VOID_TYPE = "oxdeai-celo-poc/execution-void/v1";

type Common = {
  readonly auth_id: string;
  readonly intent_hash: string;
  /** The reporting journal (execution domain, src/executor/execution-domain.ts). */
  readonly journal_id: string;
  readonly executor_kid: string;
};

export type OutcomeReport = Common & {
  readonly type: typeof REPORT_TYPE;
  readonly claim_id: string;
  readonly outcome: Outcome;
  readonly reason?: NotExecutedReason;
  readonly amount?: string;
};
export type ClaimMessage = Common & { readonly type: typeof CLAIM_TYPE; readonly claim_id: string };
export type VoidMessage = Common & { readonly type: typeof VOID_TYPE; readonly reason: VoidReason; readonly claim_id?: string };

export type Signed<T> = { readonly report: T; readonly signature: string };
export type SignedReport = Signed<OutcomeReport>;

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

export const reportId = (r: object) => createHash("sha256").update(canonicalJson(r)).digest("hex");

function signMessage<T extends object>(message: T, privateKeyPem: string): Signed<T> {
  return { report: message, signature: sign(null, Buffer.from(canonicalJson(message)), createPrivateKey(privateKeyPem)).toString("base64") };
}
export const signReport = (r: OutcomeReport, privateKeyPem: string) => signMessage(r, privateKeyPem);
export const signClaim = (c: ClaimMessage, privateKeyPem: string) => signMessage(c, privateKeyPem);
export const signVoid = (v: VoidMessage, privateKeyPem: string) => signMessage(v, privateKeyPem);

type Trusted = { publicKeyPem: string; kid: string };

/** Shape, type, common fields, and signature. Throws REPORT_INVALID:*. */
function verifyMessage(signed: unknown, trusted: Trusted, type: string, keys: ReadonlySet<string>): Record<string, unknown> {
  const s = signed as Partial<Signed<Record<string, unknown>>> | null;
  if (typeof s !== "object" || s === null || typeof s.signature !== "string" || typeof s.report !== "object" || s.report === null) {
    throw new Error("REPORT_INVALID:shape");
  }
  const r = s.report;
  if (Object.keys(r).some((k) => !keys.has(k))) throw new Error("REPORT_INVALID:keys");
  if (r.type !== type) throw new Error("REPORT_INVALID:type");
  if (r.executor_kid !== trusted.kid) throw new Error("REPORT_INVALID:kid");
  if (typeof r.auth_id !== "string" || r.auth_id === "" || typeof r.intent_hash !== "string" || !/^[0-9a-f]{64}$/.test(r.intent_hash)) {
    throw new Error("REPORT_INVALID:ids");
  }
  if (typeof r.journal_id !== "string" || !/^[0-9a-f]{32}$/.test(r.journal_id)) throw new Error("REPORT_INVALID:journal_id");
  if (r.claim_id !== undefined && (typeof r.claim_id !== "string" || !CLAIM_ID.test(r.claim_id))) throw new Error("REPORT_INVALID:claim_id");
  const ok = verify(null, Buffer.from(canonicalJson(r)), createPublicKey(trusted.publicKeyPem), Buffer.from(s.signature, "base64"));
  if (!ok) throw new Error("REPORT_INVALID:signature");
  return r;
}

const COMMON = ["type", "auth_id", "intent_hash", "journal_id", "executor_kid"];
const REPORT_KEYS = new Set([...COMMON, "claim_id", "outcome", "reason", "amount"]);
const CLAIM_KEYS = new Set([...COMMON, "claim_id"]);
const VOID_KEYS = new Set([...COMMON, "reason", "claim_id"]);

/** Verify an outcome report against the trusted executor key. Returns the facts and the reporting journal. */
export function verifyReport(signed: unknown, trusted: Trusted): OutcomeFacts & { journal_id: string } {
  const r = verifyMessage(signed, trusted, REPORT_TYPE, REPORT_KEYS);
  if (typeof r.claim_id !== "string") throw new Error("REPORT_INVALID:claim_id");
  if (!OUTCOMES.includes(r.outcome as Outcome)) throw new Error("REPORT_INVALID:outcome");
  if (r.reason !== undefined && !NOT_EXECUTED_REASONS.includes(r.reason as NotExecutedReason)) throw new Error("REPORT_INVALID:reason");
  return {
    auth_id: r.auth_id as string,
    intent_hash: r.intent_hash as string,
    claim_id: r.claim_id,
    outcome: r.outcome as Outcome,
    ...(r.reason !== undefined ? { reason: r.reason as NotExecutedReason } : {}),
    ...(r.amount !== undefined ? { amount: r.amount as string } : {}),
    report_id: reportId(r),
    journal_id: r.journal_id as string,
  };
}

export function verifyClaim(signed: unknown, trusted: Trusted): { auth_id: string; intent_hash: string; claim_id: string; journal_id: string } {
  const r = verifyMessage(signed, trusted, CLAIM_TYPE, CLAIM_KEYS);
  if (typeof r.claim_id !== "string") throw new Error("REPORT_INVALID:claim_id");
  return { auth_id: r.auth_id as string, intent_hash: r.intent_hash as string, claim_id: r.claim_id, journal_id: r.journal_id as string };
}

export function verifyVoid(signed: unknown, trusted: Trusted): { auth_id: string; intent_hash: string; reason: VoidReason; claim_id?: string; journal_id: string } {
  const r = verifyMessage(signed, trusted, VOID_TYPE, VOID_KEYS);
  if (!VOID_REASONS.includes(r.reason as VoidReason)) throw new Error("REPORT_INVALID:reason");
  return {
    auth_id: r.auth_id as string,
    intent_hash: r.intent_hash as string,
    reason: r.reason as VoidReason,
    ...(typeof r.claim_id === "string" ? { claim_id: r.claim_id } : {}),
    journal_id: r.journal_id as string,
  };
}

/**
 * What the journal durably says about a claim, as an outcome. Only intents
 * with a claim id are reportable (VOID covers unclaimed rejections
 * synchronously). `inFlight`: the intent is being claimed or paid right now
 * by this process; nothing is reported for it. Null: nothing to report.
 */
export function deriveOutcome(
  auth: AuthRecord,
  intent: PaymentJournalRecord | undefined,
  inFlight: boolean,
): { outcome: Outcome; reason?: NotExecutedReason; amount?: string; claim_id: string } | null {
  if (auth.detail === "JOURNAL_RECORD_UNREADABLE" || auth.auth_id === "" || auth.disposition !== "RESERVED") return null;
  if (intent === undefined || intent.auth_id !== auth.auth_id) return null; // no claim was ever sent, or another authorization's intent
  const c = intent.claim_id;
  if (typeof c !== "string" || !CLAIM_ID.test(c)) return null; // legacy (pre-claim) intent: held, never released
  if (inFlight) return null;
  if (intent.resolution) return { outcome: "RESOLVED_SETTLED", amount: intent.resolution.amount, claim_id: c };
  switch (intent.state) {
    case "SETTLED": {
      const amount = (intent.receipt as { amount?: unknown } | undefined)?.amount;
      return typeof amount === "string" ? { outcome: "SETTLED", amount, claim_id: c } : { outcome: "UNCERTAIN", claim_id: c };
    }
    case "REFUSED_BEFORE_SIGNING":
      return { outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING", claim_id: c };
    case "CLAIM_ABANDONED":
      return { outcome: "NOT_EXECUTED", reason: "CLAIM_ABANDONED", claim_id: c };
    case "CLAIM_REFUSED":
      return null; // the auth service refused the claim: nothing was committed, nothing to report
    default:
      return { outcome: "UNCERTAIN", claim_id: c }; // STARTED (not in flight) or UNKNOWN
  }
}

/** Ack key: one acknowledgement per distinct outcome (and reason) of an auth_id. */
export const ackKey = (o: { outcome: Outcome; reason?: NotExecutedReason }) => (o.reason ? `${o.outcome}-${o.reason}` : o.outcome);

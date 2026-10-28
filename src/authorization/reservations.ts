// SPDX-License-Identifier: MIT
/**
 * Financial state of each authorization (Phase 2C; F3).
 *
 * Every ALLOW creates a reservation, committed atomically with the budget
 * charge (`spent_in_period += max_amount`) in the same policy-state write.
 * The reservation then moves only on executor outcome reports, which are
 * signed by the executor and say what the executor's durable journal holds
 * for that auth_id (src/executor/outcome-report.ts):
 *
 *   RESERVED  --EXECUTING-->               EXECUTING
 *   RESERVED | EXECUTING --SETTLED(a)-->   CONFIRMED  charge = a; release max_amount - a
 *   RESERVED  --NOT_EXECUTED(*)-->         RELEASED   release max_amount
 *   EXECUTING --NOT_EXECUTED(REFUSED_BEFORE_SIGNING)--> RELEASED
 *   RESERVED | EXECUTING --UNCERTAIN-->    UNCERTAIN  held; never released automatically
 *   UNCERTAIN --RESOLVED_SETTLED-->        CONFIRMED  charge = max_amount (nothing released)
 *   UNCERTAIN --RESOLVED_NOT_SETTLED-->    RELEASED   release max_amount
 *
 * Release requires durable evidence that the authorization can no longer
 * execute: NOT_EXECUTED is reported only for an auth_id the executor has
 * consumed in its journal without (or before) calling `pay` (rejected before
 * execution, cancelled unused, refused before signing, or consumed by a
 * reservation whose payment never started); RESOLVED_NOT_SETTLED only after an
 * operator reconciled an uncertain payment. A consumed auth_id is refused
 * forever (AUTH_REPLAY), so a released reservation can never turn into a
 * payment. Uncertain outcomes keep their full charge.
 *
 * Reports are idempotent and cannot move a reservation backwards: the same
 * report again is ALREADY_APPLIED, an older one (e.g. EXECUTING after
 * CONFIRMED) is STALE, and a contradictory one is refused (REPORT_CONFLICT)
 * without changing anything.
 */

export type ReservationState = "RESERVED" | "EXECUTING" | "CONFIRMED" | "RELEASED" | "UNCERTAIN";

export type Outcome = "EXECUTING" | "SETTLED" | "NOT_EXECUTED" | "UNCERTAIN" | "RESOLVED_SETTLED" | "RESOLVED_NOT_SETTLED";
export const OUTCOMES: readonly Outcome[] = ["EXECUTING", "SETTLED", "NOT_EXECUTED", "UNCERTAIN", "RESOLVED_SETTLED", "RESOLVED_NOT_SETTLED"];
export type NotExecutedReason = "REJECTED_BEFORE_EXECUTION" | "CANCELLED" | "NOT_STARTED" | "REFUSED_BEFORE_SIGNING";
export const NOT_EXECUTED_REASONS: readonly NotExecutedReason[] = ["REJECTED_BEFORE_EXECUTION", "CANCELLED", "NOT_STARTED", "REFUSED_BEFORE_SIGNING"];

export type ReservationRecord = {
  readonly auth_id: string;
  readonly intent_hash: string;
  readonly agent_id: string;
  /** The only execution domain that may execute, report on, or cancel it (CX2). Null: unbound (never released). */
  readonly domain: { readonly journal_id: string; readonly executor_uid: number } | null;
  /** Authorized maximum, atomic units (decimal string). Immutable. */
  readonly amount: string;
  /** Currently charged against the budget, atomic units. */
  readonly charged: string;
  readonly expiry: number;
  readonly state: ReservationState;
  readonly created_at: number;
  readonly updated_at: number;
  readonly history: readonly { readonly state: ReservationState; readonly outcome?: Outcome; readonly reason?: string; readonly report_id?: string; readonly at: number }[];
};

export type Reservations = Readonly<Record<string, ReservationRecord>>;

/** The facts an outcome report asserts (after its signature was verified). */
export type OutcomeFacts = {
  readonly auth_id: string;
  readonly intent_hash: string;
  readonly outcome: Outcome;
  readonly reason?: NotExecutedReason;
  /** SETTLED only: settled amount, atomic units. */
  readonly amount?: string;
  readonly report_id: string;
};

export type ApplyResult =
  | { readonly kind: "APPLIED"; readonly next: ReservationRecord; readonly release: bigint }
  | { readonly kind: "ALREADY_APPLIED" | "STALE"; readonly next: ReservationRecord; readonly release: 0n };

const ATOMIC = /^(0|[1-9][0-9]{0,30})$/;

export class ReportRejected extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`REPORT_REJECTED:${code}`);
    this.code = code;
    this.name = "ReportRejected";
  }
}

export function newReservation(r: {
  auth_id: string;
  intent_hash: string;
  agent_id: string;
  domain: ReservationRecord["domain"];
  amount: string;
  expiry: number;
  at: number;
}): ReservationRecord {
  return { ...r, charged: r.amount, state: "RESERVED", created_at: r.at, updated_at: r.at, history: [{ state: "RESERVED", at: r.at }] };
}

/** Which state an outcome leads to, or null if that outcome is not allowed from `from`. */
function target(from: ReservationState, f: OutcomeFacts): ReservationState | null {
  switch (from) {
    case "RESERVED":
      if (f.outcome === "EXECUTING") return "EXECUTING";
      if (f.outcome === "SETTLED") return "CONFIRMED";
      if (f.outcome === "NOT_EXECUTED") return "RELEASED";
      if (f.outcome === "UNCERTAIN") return "UNCERTAIN";
      return null;
    case "EXECUTING":
      if (f.outcome === "SETTLED") return "CONFIRMED";
      if (f.outcome === "NOT_EXECUTED" && f.reason === "REFUSED_BEFORE_SIGNING") return "RELEASED";
      if (f.outcome === "UNCERTAIN") return "UNCERTAIN";
      return null;
    case "UNCERTAIN":
      if (f.outcome === "RESOLVED_SETTLED") return "CONFIRMED";
      if (f.outcome === "RESOLVED_NOT_SETTLED") return "RELEASED";
      return null;
    default:
      return null;
  }
}

/** Outcomes that, arriving after the reservation already moved past them, are harmless repeats. */
function isRepeatOrStale(rec: ReservationRecord, f: OutcomeFacts): "ALREADY_APPLIED" | "STALE" | null {
  const last = rec.history[rec.history.length - 1];
  if (last?.outcome === f.outcome && (f.outcome !== "NOT_EXECUTED" || last.reason === f.reason)) return "ALREADY_APPLIED";
  const seen = rec.history.some((h) => h.outcome === f.outcome && (f.outcome !== "NOT_EXECUTED" || h.reason === f.reason));
  if (seen) return "STALE";
  // A late EXECUTING after the payment already finished, or a late UNCERTAIN
  // after reconciliation, is older news, not a contradiction.
  if (f.outcome === "EXECUTING" && (rec.state === "CONFIRMED" || rec.state === "UNCERTAIN")) return "STALE";
  if (f.outcome === "UNCERTAIN" && rec.history.some((h) => h.state === "UNCERTAIN")) return "STALE";
  return null;
}

/**
 * Deterministic, validated transition. Throws ReportRejected (nothing
 * changes) for a mismatched binding, an invalid amount, or a contradiction.
 */
export function applyOutcome(rec: ReservationRecord, f: OutcomeFacts, at: number): ApplyResult {
  if (f.auth_id !== rec.auth_id) throw new ReportRejected("AUTH_ID_MISMATCH");
  if (f.intent_hash !== rec.intent_hash) throw new ReportRejected("INTENT_HASH_MISMATCH");
  if (f.outcome === "NOT_EXECUTED" && (f.reason === undefined || !NOT_EXECUTED_REASONS.includes(f.reason))) throw new ReportRejected("REASON_INVALID");
  if (f.outcome === "SETTLED") {
    if (typeof f.amount !== "string" || !ATOMIC.test(f.amount)) throw new ReportRejected("AMOUNT_INVALID");
    if (BigInt(f.amount) > BigInt(rec.amount)) throw new ReportRejected("AMOUNT_EXCEEDS_RESERVATION");
  }
  const repeat = isRepeatOrStale(rec, f);
  if (repeat !== null) return { kind: repeat, next: rec, release: 0n };

  const to = target(rec.state, f);
  if (to === null) throw new ReportRejected(`CONFLICT:${rec.state}+${f.outcome}${f.reason ? `(${f.reason})` : ""}`);

  const charged = BigInt(rec.charged);
  let nextCharged = charged;
  if (to === "CONFIRMED") nextCharged = f.outcome === "SETTLED" ? BigInt(f.amount!) : BigInt(rec.amount);
  if (to === "RELEASED") nextCharged = 0n;
  const next: ReservationRecord = {
    ...rec,
    state: to,
    charged: nextCharged.toString(),
    updated_at: at,
    history: [...rec.history, { state: to, outcome: f.outcome, ...(f.reason ? { reason: f.reason } : {}), report_id: f.report_id, at }],
  };
  return { kind: "APPLIED", next, release: charged - nextCharged };
}

/**
 * Restore support (src/isolation/policy-state-admin.ts): every reservation
 * that was not final in a restored backup is frozen as UNCERTAIN, so it can
 * only be resolved by an operator-reconciled report. A restored backup can
 * therefore never release a reservation a second time.
 */
export function freezeForRestore(reservations: Reservations, at: number): Reservations {
  const out: Record<string, ReservationRecord> = {};
  for (const [id, r] of Object.entries(reservations)) {
    out[id] =
      r.state === "CONFIRMED" || r.state === "RELEASED" || r.state === "UNCERTAIN"
        ? r
        : { ...r, state: "UNCERTAIN", updated_at: at, history: [...r.history, { state: "UNCERTAIN", reason: "RESTORED_FROM_BACKUP", at }] };
  }
  return out;
}

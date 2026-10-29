// SPDX-License-Identifier: MIT
/**
 * Financial state of each authorization (Phase 2C; F3) and its execution
 * claim (Phase 2D; architecture C, evidence/phase-2d/D3-DECISION.md).
 *
 * Every ALLOW creates a reservation, committed atomically with the budget
 * charge (`spent_in_period += max_amount`) in the same policy-state write.
 * The authorization service is the only authority on whether an
 * authorization may enter execution: the executor calls `pay` only after the
 * service durably committed a CLAIM, which is possible exactly once:
 *
 *   RESERVED  --CLAIM(c), now < expiry - minRemaining-->   EXECUTING(c)
 *   RESERVED  --VOID (acknowledged, synchronous)------->   RELEASED  release max_amount
 *   RESERVED  --now >= expiry (auth service clock)----->   RELEASED  release max_amount (EXPIRED_UNCLAIMED)
 *   EXECUTING(c) --SETTLED(c, a)------------------------>   CONFIRMED charge = a; release max_amount - a
 *   EXECUTING(c) --NOT_EXECUTED(c) REFUSED_BEFORE_SIGNING
 *                                 | CLAIM_ABANDONED----->   RELEASED  (positive record that pay(c) did not run)
 *   EXECUTING(c) --VOID(c, CLAIM_ABANDONED)------------->   RELEASED
 *   EXECUTING(c) --UNCERTAIN(c)------------------------->   UNCERTAIN held; never released automatically
 *   UNCERTAIN(c) --SETTLED(c, a) | RESOLVED_SETTLED(c, a)-> CONFIRMED charge = a (journal record or MAC-verified ledger evidence)
 *   frozen (legacy restore): never released; a confirmation keeps the full charge
 *
 * Safety (INV): RESERVED is never re-entered and a reservation is created
 * only for a fresh auth_id, so at most one claim per auth_id ever succeeds;
 * `pay` runs only with that claim's acknowledgement in hand. A reservation is
 * released only while unclaimed (then `pay` cannot have run) or on a positive
 * executor record bound to its claim: a missing record, a timeout, or the
 * absence of a ledger entry never releases anything. There is no transition
 * for non-execution of an UNCERTAIN claim (no positive mock evidence exists).
 *
 * Reports about a claim that is not the reservation's claim never move
 * money: on a RESERVED reservation the claim id is recorded as dead (a late
 * commit of that claim is then refused); otherwise they are acknowledged as
 * NOT_CLAIMED with no change. Reports are idempotent (ALREADY_APPLIED), older
 * news is STALE, contradictions are refused (CONFLICT) without changes.
 *
 * Reservations created before Phase 2D carry no `claim_required` flag: they
 * can never be claimed and are never released by expiry (fail-closed).
 */

export type ReservationState = "RESERVED" | "EXECUTING" | "CONFIRMED" | "RELEASED" | "UNCERTAIN";

export type Outcome = "SETTLED" | "NOT_EXECUTED" | "UNCERTAIN" | "RESOLVED_SETTLED";
export const OUTCOMES: readonly Outcome[] = ["SETTLED", "NOT_EXECUTED", "UNCERTAIN", "RESOLVED_SETTLED"];
/** Positive executor records that `pay(c)` did not run (outcome reports from EXECUTING). */
export type NotExecutedReason = "REFUSED_BEFORE_SIGNING" | "CLAIM_ABANDONED";
export const NOT_EXECUTED_REASONS: readonly NotExecutedReason[] = ["REFUSED_BEFORE_SIGNING", "CLAIM_ABANDONED"];
/** Synchronous VOID reasons. */
export type VoidReason = "REJECTED_BEFORE_EXECUTION" | "CLAIM_ABANDONED";
export const VOID_REASONS: readonly VoidReason[] = ["REJECTED_BEFORE_EXECUTION", "CLAIM_ABANDONED"];

export const CLAIM_ID = /^[0-9a-f]{32}$/;

export type HistoryEntry = {
  readonly state: ReservationState;
  readonly outcome?: Outcome | "CLAIM" | "VOID" | "EXPIRED";
  readonly reason?: string;
  readonly claim_id?: string;
  readonly report_id?: string;
  readonly at: number;
};

export type ReservationRecord = {
  readonly auth_id: string;
  readonly intent_hash: string;
  readonly agent_id: string;
  /** The only execution domain that may claim, report on, or void it (CX2). Null: unbound (in-process harness). */
  readonly domain: { readonly journal_id: string; readonly executor_uid: number } | null;
  /** Authorized maximum, atomic units (decimal string). Immutable. */
  readonly amount: string;
  /** Currently charged against the budget, atomic units. */
  readonly charged: string;
  readonly expiry: number;
  readonly state: ReservationState;
  /** Phase 2D: eligible for a claim and for expiry release. Absent on legacy reservations. */
  readonly claim_required?: true;
  /** The one committed claim (Phase 2D). */
  readonly claim?: { readonly claim_id: string; readonly at: number };
  /** Claim ids of attempts that never committed (reported dead); never claimable. */
  readonly dead_claims?: readonly string[];
  readonly created_at: number;
  readonly updated_at: number;
  readonly history: readonly HistoryEntry[];
};

export type Reservations = Readonly<Record<string, ReservationRecord>>;

/** The facts an outcome report asserts (after its signature was verified). */
export type OutcomeFacts = {
  readonly auth_id: string;
  readonly intent_hash: string;
  readonly claim_id: string;
  readonly outcome: Outcome;
  readonly reason?: NotExecutedReason;
  /** SETTLED / RESOLVED_SETTLED: settled amount, atomic units. */
  readonly amount?: string;
  readonly report_id: string;
};

export type ApplyKind = "APPLIED" | "ALREADY_APPLIED" | "STALE" | "NOT_CLAIMED" | "CLAIMED";
/** `changed`: `next` differs from the input and must be committed. `release`: charge returned to the budget. */
export type ApplyResult = { readonly kind: ApplyKind; readonly next: ReservationRecord; readonly release: bigint; readonly changed: boolean };

const ATOMIC = /^(0|[1-9][0-9]{0,30})$/;

export class ReportRejected extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`REPORT_REJECTED:${code}`);
    this.code = code;
    this.name = "ReportRejected";
  }
}

export class ClaimRefused extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`CLAIM_REFUSED:${code}`);
    this.code = code;
    this.name = "ClaimRefused";
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
  return { ...r, charged: r.amount, state: "RESERVED", claim_required: true, created_at: r.at, updated_at: r.at, history: [{ state: "RESERVED", at: r.at }] };
}

function moved(rec: ReservationRecord, to: ReservationState, charged: bigint, h: Omit<HistoryEntry, "state" | "at">, at: number, extra: Partial<ReservationRecord> = {}): ApplyResult {
  const before = BigInt(rec.charged);
  const next: ReservationRecord = { ...rec, ...extra, state: to, charged: charged.toString(), updated_at: at, history: [...rec.history, { state: to, ...h, at }] };
  return { kind: "APPLIED", next, release: before - charged, changed: true };
}
const unchanged = (rec: ReservationRecord, kind: ApplyKind): ApplyResult => ({ kind, next: rec, release: 0n, changed: false });

function checkBinding(rec: ReservationRecord, f: { auth_id: string; intent_hash: string }, Err: typeof ReportRejected | typeof ClaimRefused): void {
  if (f.auth_id !== rec.auth_id) throw new Err("AUTH_ID_MISMATCH");
  if (f.intent_hash !== rec.intent_hash) throw new Err("INTENT_HASH_MISMATCH");
}

/**
 * CLAIM: RESERVED -> EXECUTING(c), only for a Phase 2D reservation, a fresh
 * claim id, and an authorization still valid on the caller's (auth service)
 * clock. Every other state, including a repeat of the same claim, is refused:
 * an acknowledgement is issued at most once per reservation.
 */
export function applyClaim(rec: ReservationRecord, c: { auth_id: string; intent_hash: string; claim_id: string }, now: number, minRemainingSeconds = 0): ApplyResult {
  checkBinding(rec, c, ClaimRefused);
  if (!CLAIM_ID.test(c.claim_id)) throw new ClaimRefused("CLAIM_ID_INVALID");
  if (rec.state !== "RESERVED") throw new ClaimRefused(`NOT_ELIGIBLE:${rec.state}`);
  if (rec.claim_required !== true) throw new ClaimRefused("NOT_ELIGIBLE:LEGACY_RESERVATION");
  if (rec.claim !== undefined) throw new ClaimRefused("NOT_ELIGIBLE:ALREADY_CLAIMED");
  if (rec.dead_claims?.includes(c.claim_id)) throw new ClaimRefused("NOT_ELIGIBLE:DEAD_CLAIM");
  if (!(now < rec.expiry - minRemainingSeconds)) throw new ClaimRefused("AUTH_EXPIRED_AT_CLAIM");
  const r = moved(rec, "EXECUTING", BigInt(rec.charged), { outcome: "CLAIM", claim_id: c.claim_id }, now, { claim: { claim_id: c.claim_id, at: now } });
  return { ...r, kind: "CLAIMED" };
}

/**
 * VOID (synchronous, acknowledged): an unclaimed reservation is released
 * (pay cannot have run); a claimed one only by its own claim's abandonment.
 */
export function applyVoid(rec: ReservationRecord, v: { auth_id: string; intent_hash: string; reason: VoidReason; claim_id?: string }, at: number): ApplyResult {
  checkBinding(rec, v, ReportRejected);
  if (!VOID_REASONS.includes(v.reason)) throw new ReportRejected("REASON_INVALID");
  if (v.claim_id !== undefined && !CLAIM_ID.test(v.claim_id)) throw new ReportRejected("CLAIM_ID_INVALID");
  if (v.reason === "CLAIM_ABANDONED" && v.claim_id === undefined) throw new ReportRejected("CLAIM_ID_REQUIRED");
  const last = rec.history[rec.history.length - 1];
  if (rec.state === "RELEASED" && last?.outcome === "VOID" && last.reason === v.reason && last.claim_id === v.claim_id) return unchanged(rec, "ALREADY_APPLIED");
  const h = { outcome: "VOID" as const, reason: v.reason, ...(v.claim_id !== undefined ? { claim_id: v.claim_id } : {}) };
  if (rec.state === "RESERVED") {
    if (rec.claim_required !== true) throw new ReportRejected("VOID_NOT_ELIGIBLE:LEGACY_RESERVATION");
    return moved(rec, "RELEASED", 0n, h, at, v.claim_id !== undefined ? { dead_claims: [...(rec.dead_claims ?? []), v.claim_id] } : {});
  }
  if (rec.state === "EXECUTING" && v.reason === "CLAIM_ABANDONED" && rec.claim?.claim_id === v.claim_id) return moved(rec, "RELEASED", 0n, h, at);
  throw new ReportRejected(`VOID_NOT_ELIGIBLE:${rec.state}`);
}

/** Expiry release (auth service clock): only an unclaimed Phase 2D reservation, at or after its authorization's expiry. */
export function releaseIfExpired(rec: ReservationRecord, now: number): ApplyResult | null {
  if (rec.state !== "RESERVED" || rec.claim_required !== true || rec.claim !== undefined || now < rec.expiry) return null;
  return moved(rec, "RELEASED", 0n, { outcome: "EXPIRED", reason: "EXPIRED_UNCLAIMED" }, now);
}

function target(from: ReservationState, f: OutcomeFacts): ReservationState | null {
  if (from === "EXECUTING") {
    if (f.outcome === "SETTLED") return "CONFIRMED";
    if (f.outcome === "NOT_EXECUTED") return "RELEASED";
    if (f.outcome === "UNCERTAIN") return "UNCERTAIN";
  }
  // A positive settlement record (journal SETTLED, or a MAC-verified resolution) confirms an uncertain claim.
  if (from === "UNCERTAIN" && (f.outcome === "RESOLVED_SETTLED" || f.outcome === "SETTLED")) return "CONFIRMED";
  return null;
}

/** Frozen by a legacy restore: its charge cannot be attributed (max(backup, head)), so nothing is ever returned. */
const isFrozen = (rec: ReservationRecord) => rec.history.some((h) => h.reason === "RESTORED_FROM_BACKUP");

function isRepeatOrStale(rec: ReservationRecord, f: OutcomeFacts): "ALREADY_APPLIED" | "STALE" | null {
  const same = (h: HistoryEntry) => h.outcome === f.outcome && h.claim_id === f.claim_id && (f.outcome !== "NOT_EXECUTED" || h.reason === f.reason);
  const last = rec.history[rec.history.length - 1];
  if (last && same(last)) return "ALREADY_APPLIED";
  if (rec.history.some(same)) return "STALE";
  // A late UNCERTAIN after its reconciliation is older news, not a contradiction.
  if (f.outcome === "UNCERTAIN" && rec.history.some((h) => h.state === "UNCERTAIN" && h.claim_id === f.claim_id)) return "STALE";
  return null;
}

/**
 * Outcome report for claim `f.claim_id`. Throws ReportRejected (nothing
 * changes) for a mismatched binding, an invalid amount or reason, a
 * settlement without the reservation's claim, or a contradiction.
 */
export function applyOutcome(rec: ReservationRecord, f: OutcomeFacts, at: number): ApplyResult {
  checkBinding(rec, f, ReportRejected);
  if (!CLAIM_ID.test(f.claim_id)) throw new ReportRejected("CLAIM_ID_INVALID");
  if (f.outcome === "NOT_EXECUTED" && (f.reason === undefined || !NOT_EXECUTED_REASONS.includes(f.reason))) throw new ReportRejected("REASON_INVALID");
  if (f.outcome !== "NOT_EXECUTED" && f.reason !== undefined) throw new ReportRejected("REASON_INVALID");
  const settles = f.outcome === "SETTLED" || f.outcome === "RESOLVED_SETTLED";
  if (settles) {
    if (typeof f.amount !== "string" || !ATOMIC.test(f.amount)) throw new ReportRejected("AMOUNT_INVALID");
    if (BigInt(f.amount) > BigInt(rec.amount)) throw new ReportRejected("AMOUNT_EXCEEDS_RESERVATION");
  } else if (f.amount !== undefined) throw new ReportRejected("AMOUNT_INVALID");

  if (rec.claim?.claim_id !== f.claim_id) {
    // Not this reservation's claim: never moves money.
    if (settles) throw new ReportRejected("SETTLEMENT_WITHOUT_CLAIM");
    if (rec.state === "RESERVED" && !(rec.dead_claims ?? []).includes(f.claim_id)) {
      // That attempt never committed (the reservation is still RESERVED, which is never re-entered):
      // a late commit of it is refused from now on. The reservation stays charged until VOID or expiry.
      const next = { ...rec, dead_claims: [...(rec.dead_claims ?? []), f.claim_id], updated_at: at };
      return { kind: "NOT_CLAIMED", next, release: 0n, changed: true };
    }
    return unchanged(rec, "NOT_CLAIMED");
  }

  const repeat = isRepeatOrStale(rec, f);
  if (repeat !== null) return unchanged(rec, repeat);
  const to = target(rec.state, f);
  if (to === null) throw new ReportRejected(`CONFLICT:${rec.state}+${f.outcome}${f.reason ? `(${f.reason})` : ""}`);
  if (to === "RELEASED" && isFrozen(rec)) throw new ReportRejected("FROZEN_RESERVATION_NOT_RELEASABLE");
  const charged = to === "CONFIRMED" ? (isFrozen(rec) ? BigInt(rec.charged) : BigInt(f.amount!)) : to === "RELEASED" ? 0n : BigInt(rec.charged);
  return moved(rec, to, charged, { outcome: f.outcome, ...(f.reason ? { reason: f.reason } : {}), claim_id: f.claim_id, report_id: f.report_id }, at);
}

/**
 * Legacy backup restore (src/isolation/policy-state-admin.ts): every
 * reservation that was not final in the backup is frozen as UNCERTAIN. A
 * frozen reservation can never be claimed, voided, or expired, and only a
 * settlement report for its own recorded claim can confirm it; otherwise it
 * stays charged.
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

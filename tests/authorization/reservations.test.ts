// SPDX-License-Identifier: MIT
/** Phase 2C (F3): the reservation state machine is deterministic, validated, idempotent, and never releases twice. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { applyOutcome, freezeForRestore, newReservation, OUTCOMES, ReportRejected, type OutcomeFacts, type ReservationRecord } from "../../src/authorization/reservations.ts";

const D = { journal_id: "a".repeat(32), executor_uid: 994 };
const base = newReservation({ auth_id: "A", intent_hash: "h".repeat(64), agent_id: "agent", domain: D, amount: "10000", expiry: 100, at: 1 });
const f = (outcome: OutcomeFacts["outcome"], extra: Partial<OutcomeFacts> = {}): OutcomeFacts => ({ auth_id: "A", intent_hash: "h".repeat(64), outcome, report_id: `r-${outcome}`, ...extra });
const step = (r: ReservationRecord, x: OutcomeFacts) => applyOutcome(r, x, 2);

test("RS1 a new reservation is RESERVED, bound to its domain, and charged its full amount", () => {
  assert.equal(base.state, "RESERVED");
  assert.equal(base.charged, "10000");
  assert.deepEqual(base.domain, D);
});

test("RS2 allowed transitions and the amount released by each", () => {
  const cases: Array<[ReservationRecord, OutcomeFacts, string, bigint]> = [
    [base, f("EXECUTING"), "EXECUTING", 0n],
    [base, f("SETTLED", { amount: "10000" }), "CONFIRMED", 0n],
    [base, f("SETTLED", { amount: "7000" }), "CONFIRMED", 3000n],
    [base, f("NOT_EXECUTED", { reason: "REJECTED_BEFORE_EXECUTION" }), "RELEASED", 10000n],
    [base, f("NOT_EXECUTED", { reason: "CANCELLED" }), "RELEASED", 10000n],
    [base, f("NOT_EXECUTED", { reason: "NOT_STARTED" }), "RELEASED", 10000n],
    [base, f("UNCERTAIN"), "UNCERTAIN", 0n],
  ];
  for (const [r, x, to, rel] of cases) {
    const out = step(r, x);
    assert.equal(out.kind, "APPLIED");
    assert.equal(out.next.state, to, x.outcome);
    assert.equal(out.release, rel, `${x.outcome} release`);
    assert.equal(BigInt(out.next.charged), BigInt(r.charged) - rel);
  }
  const executing = step(base, f("EXECUTING")).next;
  assert.equal(step(executing, f("SETTLED", { amount: "10000" })).next.state, "CONFIRMED");
  assert.equal(step(executing, f("UNCERTAIN")).next.state, "UNCERTAIN");
  assert.equal(step(executing, f("NOT_EXECUTED", { reason: "REFUSED_BEFORE_SIGNING" })).next.state, "RELEASED");
  const uncertain = step(base, f("UNCERTAIN")).next;
  assert.deepEqual([step(uncertain, f("RESOLVED_SETTLED")).next.state, step(uncertain, f("RESOLVED_SETTLED")).release], ["CONFIRMED", 0n]);
  assert.deepEqual([step(uncertain, f("RESOLVED_NOT_SETTLED")).next.state, step(uncertain, f("RESOLVED_NOT_SETTLED")).release], ["RELEASED", 10000n]);
});

test("RS3 an uncertain or executing payment is never released except by evidence it did not pay", () => {
  const uncertain = step(base, f("UNCERTAIN")).next;
  for (const reason of ["REJECTED_BEFORE_EXECUTION", "CANCELLED", "NOT_STARTED", "REFUSED_BEFORE_SIGNING"] as const) {
    assert.throws(() => step(uncertain, f("NOT_EXECUTED", { reason })), ReportRejected, reason);
  }
  assert.throws(() => step(uncertain, f("SETTLED", { amount: "1" })), ReportRejected);
  const executing = step(base, f("EXECUTING")).next;
  for (const reason of ["REJECTED_BEFORE_EXECUTION", "CANCELLED", "NOT_STARTED"] as const) {
    assert.throws(() => step(executing, f("NOT_EXECUTED", { reason })), /CONFLICT:EXECUTING\+NOT_EXECUTED/);
  }
  for (const r of [base, executing]) for (const o of ["RESOLVED_SETTLED", "RESOLVED_NOT_SETTLED"] as const) assert.throws(() => step(r, f(o)), ReportRejected);
});

test("RS4 duplicates are ALREADY_APPLIED, older news is STALE, contradictions are refused; nothing releases twice", () => {
  const confirmed = step(base, f("SETTLED", { amount: "7000" })).next;
  assert.deepEqual([step(confirmed, f("SETTLED", { amount: "7000" })).kind, step(confirmed, f("SETTLED", { amount: "7000" })).release], ["ALREADY_APPLIED", 0n]);
  assert.equal(step(confirmed, f("EXECUTING")).kind, "STALE");
  assert.throws(() => step(confirmed, f("NOT_EXECUTED", { reason: "CANCELLED" })), /CONFLICT:CONFIRMED/);
  const released = step(base, f("NOT_EXECUTED", { reason: "CANCELLED" })).next;
  assert.deepEqual([step(released, f("NOT_EXECUTED", { reason: "CANCELLED" })).kind, step(released, f("NOT_EXECUTED", { reason: "CANCELLED" })).release], ["ALREADY_APPLIED", 0n]);
  for (const o of ["EXECUTING", "UNCERTAIN", "RESOLVED_NOT_SETTLED", "RESOLVED_SETTLED"] as const) assert.throws(() => step(released, f(o)), ReportRejected, o);
  assert.throws(() => step(released, f("SETTLED", { amount: "10000" })), ReportRejected);
  assert.throws(() => step(released, f("NOT_EXECUTED", { reason: "NOT_STARTED" })), ReportRejected, "a different release reason is not a repeat");
  // Exhaustive: every outcome on every terminal state releases nothing more.
  for (const r of [confirmed, released]) {
    for (const o of OUTCOMES) {
      for (const reason of [undefined, "CANCELLED", "REFUSED_BEFORE_SIGNING"] as const) {
        try {
          assert.equal(step(r, f(o, { amount: "1", ...(reason ? { reason } : {}) })).release, 0n);
        } catch (e) {
          assert.ok(e instanceof ReportRejected, String(e));
        }
      }
    }
  }
});

test("RS5 binding, amount, and reason are validated before anything changes", () => {
  assert.throws(() => step(base, { ...f("EXECUTING"), auth_id: "B" }), /AUTH_ID_MISMATCH/);
  assert.throws(() => step(base, { ...f("EXECUTING"), intent_hash: "x".repeat(64) }), /INTENT_HASH_MISMATCH/);
  assert.throws(() => step(base, f("SETTLED", { amount: "10001" })), /AMOUNT_EXCEEDS_RESERVATION/);
  assert.throws(() => step(base, f("SETTLED", { amount: "-1" })), /AMOUNT_INVALID/);
  assert.throws(() => step(base, f("SETTLED", { amount: "01" })), /AMOUNT_INVALID/);
  assert.throws(() => step(base, f("SETTLED")), /AMOUNT_INVALID/);
  assert.throws(() => step(base, f("NOT_EXECUTED")), /REASON_INVALID/);
  assert.throws(() => step(base, f("NOT_EXECUTED", { reason: "PAID_ELSEWHERE" as never })), /REASON_INVALID/);
});

test("RS6 transitions are deterministic and recorded in the history", () => {
  const a = step(base, f("SETTLED", { amount: "7000" }));
  const b = step(base, f("SETTLED", { amount: "7000" }));
  assert.deepEqual(a, b);
  assert.deepEqual(a.next.history.map((h) => [h.state, h.outcome ?? null, h.report_id ?? null]), [
    ["RESERVED", null, null],
    ["CONFIRMED", "SETTLED", "r-SETTLED"],
  ]);
});

test("RS7 restore freezes every non-final reservation as UNCERTAIN and keeps its charge", () => {
  const confirmed = step(base, f("SETTLED", { amount: "10000" })).next;
  const executing = step({ ...base, auth_id: "E" }, { ...f("EXECUTING"), auth_id: "E" }).next;
  const out = freezeForRestore({ A: base, E: executing, C: { ...confirmed, auth_id: "C" } }, 9);
  assert.equal(out.A!.state, "UNCERTAIN");
  assert.equal(out.E!.state, "UNCERTAIN");
  assert.equal(out.C!.state, "CONFIRMED");
  assert.equal(out.A!.charged, "10000");
  assert.throws(() => step(out.A!, f("NOT_EXECUTED", { reason: "CANCELLED" })), ReportRejected, "a restored reservation cannot be released by a cancellation");
});

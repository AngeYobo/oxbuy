// SPDX-License-Identifier: MIT
/**
 * Phase 2C (F3) / Phase 2D (architecture C): the reservation state machine is
 * deterministic, validated, idempotent, never releases twice, never releases
 * a claimed reservation without a positive record of non-execution, and
 * grants at most one claim per reservation.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  applyClaim,
  applyOutcome,
  applyVoid,
  ClaimRefused,
  freezeForRestore,
  newReservation,
  OUTCOMES,
  releaseIfExpired,
  ReportRejected,
  type OutcomeFacts,
  type ReservationRecord,
} from "../../src/authorization/reservations.ts";

const D = { journal_id: "a".repeat(32), executor_uid: 994 };
const H = "h".repeat(64);
const C = "c".repeat(32);
const C2 = "d".repeat(32);
const base = newReservation({ auth_id: "A", intent_hash: H, agent_id: "agent", domain: D, amount: "10000", expiry: 100, at: 1 });
const f = (outcome: OutcomeFacts["outcome"], extra: Partial<OutcomeFacts> = {}): OutcomeFacts => ({ auth_id: "A", intent_hash: H, claim_id: C, outcome, report_id: `r-${outcome}`, ...extra });
const step = (r: ReservationRecord, x: OutcomeFacts) => applyOutcome(r, x, 2);
const claimed = applyClaim(base, { auth_id: "A", intent_hash: H, claim_id: C }, 50).next;
const uncertain = step(claimed, f("UNCERTAIN")).next;

test("RS1 a new reservation is RESERVED, bound to its domain, charged its full amount, and claimable (Phase 2D)", () => {
  assert.equal(base.state, "RESERVED");
  assert.equal(base.charged, "10000");
  assert.deepEqual(base.domain, D);
  assert.equal(base.claim_required, true);
  assert.equal(base.claim, undefined);
});

test("RS2 allowed transitions and the amount released by each", () => {
  const cases: Array<[ReservationRecord, OutcomeFacts, string, bigint]> = [
    [claimed, f("SETTLED", { amount: "10000" }), "CONFIRMED", 0n],
    [claimed, f("SETTLED", { amount: "7000" }), "CONFIRMED", 3000n],
    [claimed, f("NOT_EXECUTED", { reason: "REFUSED_BEFORE_SIGNING" }), "RELEASED", 10000n],
    [claimed, f("NOT_EXECUTED", { reason: "CLAIM_ABANDONED" }), "RELEASED", 10000n],
    [claimed, f("UNCERTAIN"), "UNCERTAIN", 0n],
    [uncertain, f("RESOLVED_SETTLED", { amount: "10000" }), "CONFIRMED", 0n],
    [uncertain, f("RESOLVED_SETTLED", { amount: "6000" }), "CONFIRMED", 4000n],
    [uncertain, f("SETTLED", { amount: "9000" }), "CONFIRMED", 1000n],
  ];
  for (const [r, x, to, rel] of cases) {
    const out = step(r, x);
    assert.equal(out.kind, "APPLIED");
    assert.equal(out.next.state, to, x.outcome);
    assert.equal(out.release, rel, `${x.outcome} release`);
    assert.equal(BigInt(out.next.charged), BigInt(r.charged) - rel);
  }
  // Release paths of an unclaimed reservation: acknowledged VOID, or expiry on the service's clock.
  const v = applyVoid(base, { auth_id: "A", intent_hash: H, reason: "REJECTED_BEFORE_EXECUTION" }, 2);
  assert.deepEqual([v.next.state, v.release], ["RELEASED", 10000n]);
  const e = releaseIfExpired(base, 100)!;
  assert.deepEqual([e.next.state, e.release, e.next.history.at(-1)!.reason], ["RELEASED", 10000n, "EXPIRED_UNCLAIMED"]);
});

test("RS3 a claimed or uncertain payment is never released except by a positive record bound to its claim", () => {
  // UNCERTAIN: no non-execution transition exists at all (no positive mock evidence of non-execution).
  for (const reason of ["REFUSED_BEFORE_SIGNING", "CLAIM_ABANDONED"] as const) {
    assert.throws(() => step(uncertain, f("NOT_EXECUTED", { reason })), ReportRejected, reason);
  }
  assert.throws(() => applyVoid(uncertain, { auth_id: "A", intent_hash: H, reason: "CLAIM_ABANDONED", claim_id: C }, 2), /VOID_NOT_ELIGIBLE:UNCERTAIN/);
  // EXECUTING: a VOID without the claim's own abandonment, or for another claim, is refused.
  assert.throws(() => applyVoid(claimed, { auth_id: "A", intent_hash: H, reason: "REJECTED_BEFORE_EXECUTION" }, 2), /VOID_NOT_ELIGIBLE:EXECUTING/);
  assert.throws(() => applyVoid(claimed, { auth_id: "A", intent_hash: H, reason: "CLAIM_ABANDONED", claim_id: C2 }, 2), /VOID_NOT_ELIGIBLE:EXECUTING/);
  assert.equal(applyVoid(claimed, { auth_id: "A", intent_hash: H, reason: "CLAIM_ABANDONED", claim_id: C }, 2).next.state, "RELEASED");
  // A report naming another claim never moves a claimed reservation.
  for (const o of [f("NOT_EXECUTED", { reason: "REFUSED_BEFORE_SIGNING", claim_id: C2 }), f("UNCERTAIN", { claim_id: C2 })]) {
    const out = step(claimed, o);
    assert.deepEqual([out.kind, out.changed, out.release, out.next.state], ["NOT_CLAIMED", false, 0n, "EXECUTING"]);
  }
  assert.throws(() => step(claimed, f("SETTLED", { amount: "1", claim_id: C2 })), /SETTLEMENT_WITHOUT_CLAIM/);
  // Expiry never releases a claimed or uncertain reservation.
  assert.equal(releaseIfExpired(claimed, 10_000), null);
  assert.equal(releaseIfExpired(uncertain, 10_000), null);
});

test("RS4 duplicates are ALREADY_APPLIED, older news is STALE, contradictions are refused; nothing releases twice", () => {
  const confirmed = step(claimed, f("SETTLED", { amount: "7000" })).next;
  assert.deepEqual([step(confirmed, f("SETTLED", { amount: "7000" })).kind, step(confirmed, f("SETTLED", { amount: "7000" })).release], ["ALREADY_APPLIED", 0n]);
  assert.throws(() => step(confirmed, f("NOT_EXECUTED", { reason: "REFUSED_BEFORE_SIGNING" })), /CONFLICT:CONFIRMED/);
  const released = step(claimed, f("NOT_EXECUTED", { reason: "REFUSED_BEFORE_SIGNING" })).next;
  assert.deepEqual([step(released, f("NOT_EXECUTED", { reason: "REFUSED_BEFORE_SIGNING" })).kind, step(released, f("NOT_EXECUTED", { reason: "REFUSED_BEFORE_SIGNING" })).release], ["ALREADY_APPLIED", 0n]);
  for (const o of ["UNCERTAIN", "RESOLVED_SETTLED"] as const) assert.throws(() => step(released, f(o, o === "RESOLVED_SETTLED" ? { amount: "1" } : {})), ReportRejected, o);
  assert.throws(() => step(released, f("SETTLED", { amount: "10000" })), ReportRejected);
  assert.throws(() => step(released, f("NOT_EXECUTED", { reason: "CLAIM_ABANDONED" })), ReportRejected, "a different release reason is not a repeat");
  const voided = applyVoid(base, { auth_id: "A", intent_hash: H, reason: "REJECTED_BEFORE_EXECUTION" }, 2).next;
  assert.deepEqual([applyVoid(voided, { auth_id: "A", intent_hash: H, reason: "REJECTED_BEFORE_EXECUTION" }, 3).kind, applyVoid(voided, { auth_id: "A", intent_hash: H, reason: "REJECTED_BEFORE_EXECUTION" }, 3).release], ["ALREADY_APPLIED", 0n]);
  // Exhaustive: every outcome on every terminal state, for this and another claim, releases nothing more.
  for (const r of [confirmed, released, voided]) {
    for (const o of OUTCOMES) {
      for (const claim_id of [C, C2]) {
        for (const reason of [undefined, "REFUSED_BEFORE_SIGNING", "CLAIM_ABANDONED"] as const) {
          try {
            assert.equal(step(r, f(o, { amount: "1", claim_id, ...(reason ? { reason } : {}) })).release, 0n);
          } catch (e) {
            assert.ok(e instanceof ReportRejected, String(e));
          }
        }
      }
    }
    for (const reason of ["REJECTED_BEFORE_EXECUTION", "CLAIM_ABANDONED"] as const) {
      try {
        assert.equal(applyVoid(r, { auth_id: "A", intent_hash: H, reason, claim_id: C }, 3).release, 0n);
      } catch (e) {
        assert.ok(e instanceof ReportRejected, String(e));
      }
    }
    assert.equal(releaseIfExpired(r, 10_000), null);
  }
});

test("RS5 binding, amount, claim id, and reason are validated before anything changes", () => {
  assert.throws(() => step(claimed, { ...f("UNCERTAIN"), auth_id: "B" }), /AUTH_ID_MISMATCH/);
  assert.throws(() => step(claimed, { ...f("UNCERTAIN"), intent_hash: "x".repeat(64) }), /INTENT_HASH_MISMATCH/);
  assert.throws(() => step(claimed, f("SETTLED", { amount: "10001" })), /AMOUNT_EXCEEDS_RESERVATION/);
  assert.throws(() => step(uncertain, f("RESOLVED_SETTLED", { amount: "10001" })), /AMOUNT_EXCEEDS_RESERVATION/);
  assert.throws(() => step(claimed, f("SETTLED", { amount: "-1" })), /AMOUNT_INVALID/);
  assert.throws(() => step(claimed, f("SETTLED", { amount: "01" })), /AMOUNT_INVALID/);
  assert.throws(() => step(claimed, f("SETTLED")), /AMOUNT_INVALID/);
  assert.throws(() => step(uncertain, f("RESOLVED_SETTLED")), /AMOUNT_INVALID/);
  assert.throws(() => step(claimed, f("NOT_EXECUTED")), /REASON_INVALID/);
  assert.throws(() => step(claimed, f("NOT_EXECUTED", { reason: "CANCELLED" as never })), /REASON_INVALID/);
  assert.throws(() => step(claimed, f("UNCERTAIN", { claim_id: "short" })), /CLAIM_ID_INVALID/);
  assert.throws(() => applyVoid(base, { auth_id: "A", intent_hash: H, reason: "CLAIM_ABANDONED" }, 2), /CLAIM_ID_REQUIRED/);
  assert.throws(() => applyVoid(base, { auth_id: "A", intent_hash: H, reason: "NOT_STARTED" as never }, 2), /REASON_INVALID/);
});

test("RS6 transitions are deterministic and recorded in the history with their claim", () => {
  const a = step(claimed, f("SETTLED", { amount: "7000" }));
  const b = step(claimed, f("SETTLED", { amount: "7000" }));
  assert.deepEqual(a, b);
  assert.deepEqual(a.next.history.map((h) => [h.state, h.outcome ?? null, h.claim_id ?? null, h.report_id ?? null]), [
    ["RESERVED", null, null, null],
    ["EXECUTING", "CLAIM", C, null],
    ["CONFIRMED", "SETTLED", C, "r-SETTLED"],
  ]);
});

test("RS7 legacy restore freezes every non-final reservation as UNCERTAIN; frozen ones are never claimed, voided, expired, or released, and a confirmation keeps the full charge", () => {
  const confirmed = step(claimed, f("SETTLED", { amount: "10000" })).next;
  const out = freezeForRestore({ A: base, E: { ...claimed, auth_id: "E" }, C: { ...confirmed, auth_id: "C" } }, 9);
  assert.equal(out.A!.state, "UNCERTAIN");
  assert.equal(out.E!.state, "UNCERTAIN");
  assert.equal(out.C!.state, "CONFIRMED");
  assert.equal(out.A!.charged, "10000");
  assert.throws(() => applyClaim(out.A!, { auth_id: "A", intent_hash: H, claim_id: C2 }, 50), /NOT_ELIGIBLE:UNCERTAIN/);
  assert.throws(() => applyVoid(out.A!, { auth_id: "A", intent_hash: H, reason: "REJECTED_BEFORE_EXECUTION" }, 50), /VOID_NOT_ELIGIBLE/);
  assert.equal(releaseIfExpired(out.A!, 10_000), null);
  const e = { ...out.E!, auth_id: "A" };
  assert.throws(() => step(e, f("NOT_EXECUTED", { reason: "REFUSED_BEFORE_SIGNING" })), ReportRejected, "no release of a frozen reservation");
  const conf = step(e, f("RESOLVED_SETTLED", { amount: "6000" }));
  assert.deepEqual([conf.next.state, conf.release, conf.next.charged], ["CONFIRMED", 0n, "10000"], "frozen: the charge cannot be attributed, nothing is returned");
  assert.throws(() => step(out.A!, f("RESOLVED_SETTLED", { amount: "1" })), /SETTLEMENT_WITHOUT_CLAIM/, "no claim recorded: cannot be confirmed either");
});

test("RS8 claim: only once, only RESERVED, only before expiry on the service's clock, never for a dead or legacy claim", () => {
  const r = applyClaim(base, { auth_id: "A", intent_hash: H, claim_id: C }, 99);
  assert.deepEqual([r.kind, r.next.state, r.next.claim?.claim_id, r.release], ["CLAIMED", "EXECUTING", C, 0n]);
  assert.throws(() => applyClaim(r.next, { auth_id: "A", intent_hash: H, claim_id: C }, 99), /NOT_ELIGIBLE:EXECUTING/, "a repeat of the same claim is not re-acknowledged");
  assert.throws(() => applyClaim(r.next, { auth_id: "A", intent_hash: H, claim_id: C2 }, 99), /NOT_ELIGIBLE:EXECUTING/);
  assert.throws(() => applyClaim(base, { auth_id: "A", intent_hash: H, claim_id: C }, 100), /AUTH_EXPIRED_AT_CLAIM/, "exclusive bound: now == expiry");
  assert.throws(() => applyClaim(base, { auth_id: "A", intent_hash: H, claim_id: C }, 96, 5), /AUTH_EXPIRED_AT_CLAIM/, "minRemainingSeconds");
  assert.equal(applyClaim(base, { auth_id: "A", intent_hash: H, claim_id: C }, 94, 5).next.state, "EXECUTING");
  assert.throws(() => applyClaim(base, { auth_id: "A", intent_hash: "x".repeat(64), claim_id: C }, 50), /INTENT_HASH_MISMATCH/);
  assert.throws(() => applyClaim(base, { auth_id: "A", intent_hash: H, claim_id: "nothex" }, 50), /CLAIM_ID_INVALID/);
  const { claim_required: _c, ...legacy } = base;
  assert.throws(() => applyClaim(legacy as ReservationRecord, { auth_id: "A", intent_hash: H, claim_id: C }, 50), /LEGACY_RESERVATION/);
  for (const s of ["CONFIRMED", "RELEASED", "UNCERTAIN"] as const) {
    assert.throws(() => applyClaim({ ...base, state: s }, { auth_id: "A", intent_hash: H, claim_id: C }, 50), ClaimRefused, s);
  }
});

test("RS9 a report about a claim that never committed marks it dead; that claim can never be granted later", () => {
  const out = step(base, f("UNCERTAIN", { claim_id: C2 }));
  assert.deepEqual([out.kind, out.changed, out.release, out.next.state, out.next.dead_claims], ["NOT_CLAIMED", true, 0n, "RESERVED", [C2]]);
  assert.throws(() => applyClaim(out.next, { auth_id: "A", intent_hash: H, claim_id: C2 }, 50), /DEAD_CLAIM/);
  assert.equal(applyClaim(out.next, { auth_id: "A", intent_hash: H, claim_id: C }, 50).next.state, "EXECUTING", "a fresh claim is still possible");
  assert.deepEqual([step(out.next, f("UNCERTAIN", { claim_id: C2 })).kind, step(out.next, f("UNCERTAIN", { claim_id: C2 })).changed], ["NOT_CLAIMED", false]);
  // The journal-derived abandonment of an uncommitted claim does not release (only a synchronous VOID does).
  const ab = step(base, f("NOT_EXECUTED", { reason: "CLAIM_ABANDONED", claim_id: C2 }));
  assert.deepEqual([ab.next.state, ab.release], ["RESERVED", 0n]);
  // A synchronous VOID of the abandoned claim releases it, and marks the claim dead.
  const v = applyVoid(base, { auth_id: "A", intent_hash: H, reason: "CLAIM_ABANDONED", claim_id: C2 }, 2);
  assert.deepEqual([v.next.state, v.release, v.next.dead_claims], ["RELEASED", 10000n, [C2]]);
});

test("RS10 expiry release: only unclaimed Phase 2D reservations, at or after expiry", () => {
  assert.equal(releaseIfExpired(base, 99), null);
  assert.equal(releaseIfExpired(base, 100)!.next.state, "RELEASED");
  const { claim_required: _c, ...legacy } = base;
  assert.equal(releaseIfExpired(legacy as ReservationRecord, 10_000), null, "legacy reservations are never released by expiry");
  assert.equal(releaseIfExpired(claimed, 10_000), null);
});

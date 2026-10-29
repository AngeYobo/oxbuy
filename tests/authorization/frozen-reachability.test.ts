// SPDX-License-Identifier: MIT
/**
 * Independent audit: lead "frozen reservation release" (surviving mutant D16).
 *
 * D16 deletes the guard `if (to === "RELEASED" && isFrozen(rec)) throw ...` in
 * applyOutcome. `to === "RELEASED"` only arises from EXECUTING (target()), so
 * the guard matters only if a frozen record (history reason RESTORED_FROM_BACKUP)
 * can ever be EXECUTING. This test explores, exhaustively up to a bounded
 * depth, every transition the reservation state machine offers (claim, void,
 * expiry release, every outcome report kind, own and foreign claim ids,
 * amounts, times), starting from freezeForRestore() applied to records in every
 * state, and asserts:
 *   FR1  no reachable frozen record is ever EXECUTING (so the guard is unreachable);
 *   FR2  no reachable frozen record is ever RELEASED and none ever returns charge.
 * FR2 is the security property itself, so it also holds with the D16 mutant if FR1 holds.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  applyClaim,
  applyOutcome,
  applyVoid,
  freezeForRestore,
  newReservation,
  releaseIfExpired,
  type ApplyResult,
  type OutcomeFacts,
  type ReservationRecord,
} from "../../src/authorization/reservations.ts";

const H = "a".repeat(64);
const C1 = "1".repeat(32);
const C2 = "2".repeat(32);
const base = newReservation({ auth_id: "A", intent_hash: H, agent_id: "agent", domain: null, amount: "100", expiry: 1000, at: 1 });
const isFrozen = (r: ReservationRecord) => r.history.some((h) => h.reason === "RESTORED_FROM_BACKUP");

/** Records in every state the store can hold (including a legacy one without claim_required). */
function seeds(): ReservationRecord[] {
  const executing = applyClaim(base, { auth_id: "A", intent_hash: H, claim_id: C1 }, 10).next;
  const confirmed = applyOutcome(executing, { auth_id: "A", intent_hash: H, claim_id: C1, outcome: "SETTLED", amount: "60", report_id: "r1" }, 11).next;
  const uncertain = applyOutcome(executing, { auth_id: "A", intent_hash: H, claim_id: C1, outcome: "UNCERTAIN", report_id: "r2" }, 11).next;
  const released = applyVoid(base, { auth_id: "A", intent_hash: H, reason: "REJECTED_BEFORE_EXECUTION" }, 11).next;
  const { claim_required: _c, ...legacy } = base;
  const legacyExecuting = { ...legacy, state: "EXECUTING" as const };
  return [base, executing, confirmed, uncertain, released, legacy as ReservationRecord, legacyExecuting as ReservationRecord];
}

function steps(r: ReservationRecord): ApplyResult[] {
  const out: ApplyResult[] = [];
  const attempt = (f: () => ApplyResult | null) => {
    try {
      const x = f();
      if (x) out.push(x);
    } catch {
      /* refused: no transition */
    }
  };
  for (const now of [5, 999, 1000, 5000]) {
    for (const c of [C1, C2]) attempt(() => applyClaim(r, { auth_id: "A", intent_hash: H, claim_id: c }, now));
    attempt(() => releaseIfExpired(r, now));
  }
  for (const reason of ["REJECTED_BEFORE_EXECUTION", "CLAIM_ABANDONED"] as const) {
    for (const claim_id of [undefined, C1, C2]) attempt(() => applyVoid(r, { auth_id: "A", intent_hash: H, reason, ...(claim_id ? { claim_id } : {}) }, 50));
  }
  const facts: Omit<OutcomeFacts, "claim_id" | "report_id">[] = [
    { auth_id: "A", intent_hash: H, outcome: "SETTLED", amount: "0" },
    { auth_id: "A", intent_hash: H, outcome: "SETTLED", amount: "100" },
    { auth_id: "A", intent_hash: H, outcome: "RESOLVED_SETTLED", amount: "40" },
    { auth_id: "A", intent_hash: H, outcome: "UNCERTAIN" },
    { auth_id: "A", intent_hash: H, outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING" },
    { auth_id: "A", intent_hash: H, outcome: "NOT_EXECUTED", reason: "CLAIM_ABANDONED" },
  ];
  let k = 0;
  for (const f of facts) for (const claim_id of [C1, C2]) attempt(() => applyOutcome(r, { ...f, claim_id, report_id: `rep-${k++}` } as OutcomeFacts, 60));
  return out;
}

test("FR1/FR2 bounded exhaustive exploration from every frozen seed: a frozen record is never EXECUTING, never RELEASED, never returns charge", () => {
  const key = (r: ReservationRecord) => JSON.stringify([r.state, r.charged, r.claim?.claim_id, r.dead_claims, r.history.map((h) => [h.state, h.outcome, h.reason, h.claim_id])]);
  let explored = 0;
  let frozenSeen = 0;
  for (const seed of seeds()) {
    const frozen = freezeForRestore({ A: seed }, 7).A!;
    const start = BigInt(frozen.charged);
    const seen = new Set<string>([key(frozen)]);
    let frontier = [frozen];
    for (let depth = 0; depth < 6 && frontier.length > 0; depth++) {
      const next: ReservationRecord[] = [];
      for (const r of frontier) {
        explored += 1;
        if (isFrozen(r)) {
          frozenSeen += 1;
          assert.notEqual(r.state, "EXECUTING", `FR1 frozen record reached EXECUTING: ${key(r)}`);
          assert.notEqual(r.state, "RELEASED", `FR2 frozen record released: ${key(r)}`);
          assert.equal(BigInt(r.charged), start, `FR2 frozen record returned charge: ${key(r)}`);
        }
        for (const s of steps(r)) {
          if (isFrozen(r) && s.release !== 0n) assert.fail(`FR2 a transition of a frozen record released ${s.release}`);
          const k = key(s.next);
          if (!seen.has(k)) {
            seen.add(k);
            next.push(s.next);
          }
        }
      }
      frontier = next;
    }
  }
  assert.ok(frozenSeen > 0, "frozen records were explored");
  assert.ok(explored >= seeds().length, `explored ${explored} states`);
});

test("FR0 positive control: the same explorer, from an unfrozen RESERVED record, reaches EXECUTING, UNCERTAIN, CONFIRMED, and RELEASED", () => {
  const reached = new Set<string>();
  let frontier = [base];
  const seen = new Set<string>();
  for (let depth = 0; depth < 4; depth++) {
    const next: ReservationRecord[] = [];
    for (const r of frontier) {
      reached.add(r.state);
      for (const s of steps(r)) {
        const k = JSON.stringify(s.next);
        if (!seen.has(k)) {
          seen.add(k);
          next.push(s.next);
        }
      }
    }
    frontier = next;
  }
  for (const st of ["RESERVED", "EXECUTING", "UNCERTAIN", "CONFIRMED", "RELEASED"]) assert.ok(reached.has(st), `explorer reaches ${st}`);
});

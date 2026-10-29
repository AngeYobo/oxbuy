// SPDX-License-Identifier: MIT
/** Phase 2C (N3, CX1): anchor chain verification and the crash-state transition table, as pure functions. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { nextEntry, parseAnchor, reconcile, sha256, type AnchorEntry, type AnchorLog } from "../../src/authorization/policy-anchor.ts";

type Body = Omit<AnchorEntry, "seq" | "prev" | "hash">;
function build(bodies: Body[]): string {
  let text = "";
  let log: AnchorLog | undefined;
  for (const b of bodies) {
    text += nextEntry(log, b).text;
    log = parseAnchor(text);
  }
  return text;
}
const S = (v: number) => ({ version: v, state_sha256: sha256(`state-${v}`) });
const prepare = (v: number, op: AnchorEntry["op"] = "COMMIT"): Body => ({ kind: "PREPARE", op, ...S(v), spent: { a: String(v * 10) } });
const done = (v: number): Body => ({ kind: "DONE", ...S(v) });
const genesis = [prepare(0, "INIT"), done(0)];
const reason = (r: ReturnType<typeof reconcile>) => (r.action === "REFUSE" ? r.reason : r.action);

test("AN1 a completed chain: head is the latest DONE, nothing pending", () => {
  const log = parseAnchor(build([...genesis, prepare(1), done(1), prepare(2), done(2)]));
  assert.equal(log.head!.version, 2);
  assert.equal(log.pending, undefined);
  assert.deepEqual(log.completed.map((c) => c.version), [0, 1, 2]);
  assert.deepEqual(log.head!.spent, { a: "20" });
});

test("AN2 the crash-state table, row by row", () => {
  const open = parseAnchor(build([...genesis, prepare(1), done(1), prepare(2)]));
  assert.equal(reconcile(open, S(1)).action, "ABORT_PENDING", "crash 1..3: file is the head");
  assert.equal(reconcile(open, S(2)).action, "COMPLETE_PENDING", "crash 3..5: file is the pending version");
  const closed = parseAnchor(build([...genesis, prepare(1), done(1), prepare(2), done(2)]));
  assert.equal(reconcile(closed, S(2)).action, "ACCEPT", "crash 5..6 or no crash");
  // CX1: an older state after a completed DONE is a rollback, never a torn commit.
  assert.match(reason(reconcile(closed, S(1))), /POLICY_STATE_ROLLBACK:state version 1, anchor head version 2/);
  assert.match(reason(reconcile(closed, S(0))), /POLICY_STATE_ROLLBACK/);
  assert.match(reason(reconcile(open, S(0))), /POLICY_STATE_ROLLBACK/, "older than the head while a PREPARE is open");
  assert.match(reason(reconcile(closed, { version: 2, state_sha256: sha256("tampered") })), /POLICY_STATE_ANCHOR_MISMATCH/);
  assert.match(reason(reconcile(closed, { version: 9, state_sha256: sha256("future") })), /POLICY_STATE_ANCHOR_MISMATCH/);
  // Genesis written, state not yet complete: the INIT PREPARE is completed only by its exact file.
  const initOnly = parseAnchor(build([prepare(0, "INIT")]));
  assert.equal(reconcile(initOnly, S(0)).action, "COMPLETE_PENDING");
  assert.match(reason(reconcile(initOnly, S(1))), /POLICY_STATE_ANCHOR_MISMATCH/);
});

test("AN3 aborted versions never become completed (restore) sources", () => {
  const text = build([...genesis, prepare(1)]);
  const log = parseAnchor(text);
  const aborted = parseAnchor(text + nextEntry(log, { kind: "ABORT", aborts: log.pending!.seq }).text);
  assert.equal(aborted.pending, undefined);
  assert.deepEqual(aborted.completed.map((c) => c.version), [0]);
  assert.match(reason(reconcile(aborted, S(1))), /POLICY_STATE_ANCHOR_MISMATCH/, "the aborted version is not accepted later");
});

test("AN4 tampering, reordering, truncation at the start, and protocol violations are detected", () => {
  const text = build([...genesis, prepare(1), done(1)]);
  const lines = text.trim().split("\n");
  const edited = lines.map((l, i) => (i === 1 ? l.replace(/"version":0/, '"version":5') : l)).join("\n") + "\n";
  assert.throws(() => parseAnchor(edited), /POLICY_ANCHOR_CORRUPT:chain broken/);
  assert.throws(() => parseAnchor([lines[0], lines[2], lines[1], lines[3]].join("\n") + "\n"), /POLICY_ANCHOR_CORRUPT/);
  assert.throws(() => parseAnchor(lines.slice(1).join("\n") + "\n"), /POLICY_ANCHOR_CORRUPT/);
  assert.throws(() => parseAnchor(""), /POLICY_ANCHOR_CORRUPT:empty/);
  const g = build(genesis);
  assert.throws(() => parseAnchor(g + nextEntry(parseAnchor(g), done(7)).text), /DONE .* without matching PREPARE/);
  const two = build([...genesis, prepare(1)]);
  assert.throws(() => parseAnchor(two + nextEntry(parseAnchor(two), prepare(2)).text), /while .* is open/);
  assert.throws(() => parseAnchor(g + nextEntry(parseAnchor(g), { kind: "ABORT", aborts: 0 }).text), /ABORT .* not open/);
  const down = build([...genesis, prepare(1), done(1), prepare(2), done(2), prepare(3), done(3)]);
  assert.throws(() => parseAnchor(down + nextEntry(parseAnchor(down), prepare(2)).text + ""), (e: Error) => e.message.startsWith("POLICY_ANCHOR_CORRUPT") || false);
});

test("AN5 a torn final line is tolerated only as the last line, until an ABORT names it", () => {
  const text = build(genesis);
  const torn = `${text}{"seq":2,"kind":"PREP`;
  const log = parseAnchor(torn);
  assert.equal(log.tornTail, '{"seq":2,"kind":"PREP');
  assert.equal(log.needsNewline, true);
  const healed = torn + nextEntry(log, { kind: "ABORT", torn_sha256: sha256(log.tornTail!) }).text;
  assert.equal(parseAnchor(healed).head!.version, 0);
  assert.equal(parseAnchor(healed).tornTail, undefined);
  const lines = text.trim().split("\n");
  assert.throws(() => parseAnchor(`${lines[0]}\n{"broken\n${lines[1]}\n`), /POLICY_ANCHOR_CORRUPT/);
});

// ── CX3: strict version progression (AN4 above is the original regression) ──

const corrupt = (bodies: Body[], extra: Body, re: RegExp) => {
  const text = build(bodies);
  assert.throws(() => parseAnchor(text + nextEntry(parseAnchor(text), extra).text), re);
};

test("AN6 CX3: duplicate, stale, skipped, and bypassing PREPAREs are rejected", () => {
  const chain = [...genesis, prepare(1), done(1), prepare(2), done(2), prepare(3), done(3)];
  corrupt(chain, prepare(2), /PREPARE 8 for version 2, expected 4/); // stale (the CX3 entry)
  corrupt(chain, prepare(3), /for version 3, expected 4/); // duplicate of the head
  corrupt(chain, prepare(5), /for version 5, expected 4/); // skipped version
  corrupt(chain, prepare(0), /expected 4/);
  corrupt([...chain, prepare(4)], prepare(4), /PREPARE 9 while 8 is open/); // duplicate while open
  corrupt([...chain, prepare(4)], prepare(5), /while 8 is open/); // unfinished PREPARE bypassed
  corrupt(chain, prepare(4, "INIT"), /INIT after the genesis/);
  corrupt(chain, prepare(4, "MIGRATE"), /MIGRATE after the genesis/);
  corrupt([prepare(0, "INIT")], prepare(1), /while 0 is open/);
});

test("AN7 CX3: malformed DONE and ABORT sequences are rejected", () => {
  corrupt(genesis, done(0), /DONE 2 without matching PREPARE/); // DONE twice
  corrupt([...genesis, prepare(1)], done(2), /without matching PREPARE/); // DONE for another version
  corrupt([...genesis, prepare(1)], { kind: "DONE", version: 1, state_sha256: sha256("other") }, /without matching PREPARE/); // other content
  corrupt([...genesis, prepare(1)], { kind: "ABORT", aborts: 0 }, /not open/); // aborting a completed entry
  corrupt([prepare(0, "INIT")], { kind: "ABORT", aborts: 0 }, /ABORT 1 of the genesis/);
  corrupt(genesis, { kind: "ABORT", torn_sha256: sha256("nothing torn") }, /does not follow the torn line/);
  corrupt(genesis, { kind: "ABORT" }, /does not follow the torn line/);
  // A PREPARE for a malformed version.
  corrupt(genesis, { kind: "PREPARE", op: "COMMIT", version: 1.5, state_sha256: sha256("x"), spent: {} }, /POLICY_ANCHOR_CORRUPT:PREPARE 2/);
});

test("AN8 CX3: reconcile enforces the version rule itself, even on a hand-built log", () => {
  const log = parseAnchor(build([...genesis, prepare(1), done(1), prepare(2), done(2), prepare(3), done(3)]));
  // The CX3 shape, constructed without parseAnchor: pending version 2 under head 3.
  const forged = { ...log, pending: { ...log.entries[4]!, seq: 8 } };
  assert.match(reason(reconcile(forged, S(2))), /POLICY_ANCHOR_INCONSISTENT:pending version 2, head version 3/);
  const skipped = { ...log, pending: { ...log.entries[4]!, seq: 8, version: 5 } };
  assert.match(reason(reconcile(skipped, { version: 5, state_sha256: log.entries[4]!.state_sha256! })), /POLICY_ANCHOR_INCONSISTENT/);
  const wrongOp = { ...log, pending: { ...log.entries[4]!, seq: 8, version: 4, op: "INIT" as const } };
  assert.match(reason(reconcile(wrongOp, { version: 4, state_sha256: log.entries[4]!.state_sha256! })), /POLICY_ANCHOR_INCONSISTENT/);
});

test("AN9 valid crash recovery after PREPARE: abort, then retry of the same version, then complete", () => {
  const text = build([...genesis, prepare(1), done(1), prepare(2)]);
  const open = parseAnchor(text);
  assert.equal(reconcile(open, S(1)).action, "ABORT_PENDING");
  const aborted = text + nextEntry(open, { kind: "ABORT", aborts: open.pending!.seq }).text;
  // The next commit prepares version 2 again (the aborted one never existed).
  const retried = aborted + nextEntry(parseAnchor(aborted), prepare(2)).text;
  const r = parseAnchor(retried);
  assert.equal(r.pending!.version, 2);
  assert.equal(reconcile(r, S(2)).action, "COMPLETE_PENDING");
  const completed = parseAnchor(retried + nextEntry(r, done(2)).text);
  assert.equal(completed.head!.version, 2);
  assert.deepEqual(completed.completed.map((c) => c.version), [0, 1, 2]);
});

test("AN10 valid operator restoration: RESTORE for exactly head + 1, completed by its exact state", () => {
  const text = build([...genesis, prepare(1), done(1), prepare(2), done(2)]);
  const restore: Body = { kind: "PREPARE", op: "RESTORE", version: 3, state_sha256: sha256("restored"), spent: { a: "20" }, from_sha256: S(1).state_sha256 };
  const log = parseAnchor(text + nextEntry(parseAnchor(text), restore).text);
  assert.equal(reconcile(log, { version: 3, state_sha256: sha256("restored") }).action, "COMPLETE_PENDING");
  assert.equal(reconcile(log, S(2)).action, "ABORT_PENDING", "restore interrupted before its rename: it did not happen");
  assert.match(reason(reconcile(log, S(1))), /POLICY_STATE_ROLLBACK/, "the backup itself is still not accepted as current");
  corrupt([...genesis, prepare(1), done(1), prepare(2), done(2)], { ...restore, version: 2 }, /for version 2, expected 3/);
  // A migration genesis may start at any version and continues from there.
  const mig = build([{ kind: "PREPARE", op: "MIGRATE", ...S(7), spent: {}, from_sha256: sha256("v1") }, done(7), prepare(8), done(8)]);
  assert.equal(parseAnchor(mig).head!.version, 8);
});

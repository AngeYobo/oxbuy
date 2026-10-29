// SPDX-License-Identifier: MIT
/**
 * CK1-CK10: executor consumption checkpoint (src/executor/executor-anchor.ts) and its use by the durable
 * payment journal (AUD-02 / AUD-03 / AUD-04). In process, on temporary directories; the append-only
 * attribute is exercised by the process-level tests (tests/isolation/journal-rollback.test.ts).
 *
 * A "rollback" here is what an executor-state restore does: the journal directory is replaced by an
 * older copy while the checkpoint (outside the state root) keeps everything appended since.
 */
import assert from "node:assert/strict";
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { parseCheckpoint, readCheckpoint } from "../../src/executor/executor-anchor.ts";
import { initFilePaymentJournal, journalIdOf, openFilePaymentJournal, type FilePaymentJournal, type SettlementEvidence } from "../../src/executor/payment-journal.ts";
import { requestFor, SERVICES } from "../helpers.ts";

const REQ = requestFor(SERVICES.weather);
const H = (c: string) => c.repeat(64);
const C = (c: string) => c.repeat(32);
const authKey = (id: string) => createHash("sha256").update(id).digest("hex");

const dirs: string[] = [];
const opened: FilePaymentJournal[] = [];
afterEach(() => {
  for (const j of opened.splice(0)) j.close();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A sealed journal: <d>/executor/journal and its checkpoint <d>/cp.log (empty file sealed by `seal` mode). */
function fresh() {
  const d = mkdtempSync(join(tmpdir(), "oxdeai-anchor-test-"));
  dirs.push(d);
  const dir = join(d, "executor", "journal");
  mkdirSync(join(d, "executor"));
  initFilePaymentJournal(dir);
  const cp = join(d, "cp.log");
  writeFileSync(cp, "");
  const sealer = openFilePaymentJournal(dir, { checkpoint: { path: cp, mode: "seal", requireAppendOnly: false } });
  sealer.close();
  const open = (mode?: "normal" | "recover") => {
    const j = openFilePaymentJournal(dir, { checkpoint: { path: cp, mode, requireAppendOnly: false } });
    opened.push(j);
    return j;
  };
  const close = (j: FilePaymentJournal) => {
    j.close();
    opened.splice(opened.indexOf(j), 1);
  };
  const snapshot = () => {
    const s = join(d, `snap-${dirs.length}-${Math.random().toString(16).slice(2)}`);
    cpSync(dir, s, { recursive: true });
    return s;
  };
  const restore = (s: string) => {
    rmSync(dir, { recursive: true, force: true });
    cpSync(s, dir, { recursive: true });
  };
  return { d, dir, cp, open, close, snapshot, restore, entries: () => readCheckpoint(cp).entries };
}

test("CK1 seal and normal operation: GENESIS binds the journal; every consumption and final state is checkpointed; reopen is clean", () => {
  const f = fresh();
  const j = f.open();
  assert.deepEqual(j.reserve({ intent_hash: H("1"), auth_id: "a1", request: REQ, claim_id: C("1") }), { ok: true });
  j.record(H("1"), "SETTLED", undefined, { settled: true, amount: "10000" });
  j.consume({ auth_id: "a2", intent_hash: H("2"), disposition: "REJECTED_BEFORE_EXECUTION", detail: "quote drift" });
  f.close(j);
  const kinds = f.entries().map((e) => e.kind);
  assert.deepEqual(kinds, ["GENESIS", "CONSUME", "FINAL", "CONSUME"]);
  const g = f.entries()[0]!;
  assert.equal(g.kind === "GENESIS" && g.journal_id, journalIdOf(f.dir));
  const k = f.open();
  assert.deepEqual(k.rolledBack, []);
  assert.equal(f.entries().length, 4, "a clean reopen appends nothing");
});

test("CK2 a valid older journal restored is detected at open (JOURNAL_ROLLBACK_DETECTED) and nothing is appended", () => {
  const f = fresh();
  const snap = f.snapshot();
  const j = f.open();
  j.consume({ auth_id: "rejected", intent_hash: H("3"), disposition: "REJECTED_BEFORE_EXECUTION" });
  f.close(j);
  f.restore(snap);
  const before = readFileSync(f.cp, "utf8");
  assert.throws(() => f.open(), /JOURNAL_ROLLBACK_DETECTED:1 checkpointed fact\(s\) missing.*AUTH_MISSING rejected/);
  assert.equal(readFileSync(f.cp, "utf8"), before, "a refused open appends nothing");
  assert.throws(() => f.open(), /JOURNAL_ROLLBACK_DETECTED/, "and keeps refusing (the lock was released)");
});

test("CK3 a rollback while running is caught before the consumption is reused: the replay is refused and the journal stops writing", () => {
  const f = fresh();
  const j = f.open();
  j.consume({ auth_id: "rej", intent_hash: H("4"), disposition: "REJECTED_BEFORE_EXECUTION" });
  unlinkSync(join(f.dir, "auths", authKey("rej"))); // the record vanishes under the running process
  assert.throws(() => j.reserve({ intent_hash: H("5"), auth_id: "rej", request: REQ, claim_id: C("5") }), /JOURNAL_ROLLBACK_DETECTED/);
  assert.equal(j.inspect(H("5")), undefined, "no intent was reserved");
  assert.throws(() => j.consume({ auth_id: "other", intent_hash: H("6"), disposition: "REJECTED_BEFORE_EXECUTION" }), /JOURNAL_UNAVAILABLE/, "every later write is refused");
});

test("CK4 crash between the journal write and its checkpoint entry: the next open catches up; no false rollback", () => {
  const f = fresh();
  const j = f.open();
  // A checkpoint append that never happens stands in for a process killed between the two writes
  // (0007: a journal can no longer be opened for writing without its checkpoint).
  f.close(j);
  const killed = openFilePaymentJournal(f.dir, {
    checkpoint: { path: f.cp, requireAppendOnly: false, beforeAppend: () => { throw new Error("killed before the checkpoint append"); } },
  });
  assert.throws(() => killed.reserve({ intent_hash: H("7"), auth_id: "a7", request: REQ, claim_id: C("7") }), /JOURNAL_CHECKPOINT_UNAVAILABLE/);
  killed.close();
  const k = f.open();
  assert.deepEqual(k.rolledBack, []);
  assert.equal(f.entries().at(-1)!.kind, "CONSUME", "caught up");
  assert.deepEqual(k.reserve({ intent_hash: H("8"), auth_id: "a7", request: REQ, claim_id: C("8") }), { ok: false, reason: "AUTH_REPLAY" });
});

test("CK5 torn final checkpoint line (crash during an append) is acknowledged; detection still works afterwards", () => {
  const f = fresh();
  appendFileSync(f.cp, '{"seq":1,"kind":"CONS');
  const j = f.open();
  assert.equal(f.entries().at(-1)!.kind, "TORN");
  const snap = f.snapshot();
  j.consume({ auth_id: "t1", intent_hash: H("8"), disposition: "REJECTED_BEFORE_EXECUTION" });
  f.close(j);
  f.restore(snap);
  assert.throws(() => f.open(), /JOURNAL_ROLLBACK_DETECTED/);
});

test("CK6 checkpoint unavailable or wrong: missing, unsealed, foreign journal, corrupt chain all refuse to open", () => {
  const f = fresh();
  const g = fresh();
  const tryOpen = (cp: string) => () => openFilePaymentJournal(f.dir, { checkpoint: { path: cp, requireAppendOnly: false } }).close();
  assert.throws(tryOpen(join(f.d, "nope.log")), /CHECKPOINT_MISSING/);
  const empty = join(f.d, "empty.log");
  writeFileSync(empty, "");
  assert.throws(tryOpen(empty), /CHECKPOINT_UNSEALED/);
  assert.throws(tryOpen(g.cp), /CHECKPOINT_DOMAIN_MISMATCH/, "another journal's checkpoint");
  const lines = readFileSync(f.cp, "utf8").split("\n");
  const tampered = join(f.d, "tampered.log");
  writeFileSync(tampered, `${lines[0]}\n${JSON.stringify({ ...JSON.parse(lines[0]!), seq: 1 })}\n`);
  assert.throws(tryOpen(tampered), /CHECKPOINT_CORRUPT/);
  assert.throws(() => openFilePaymentJournal(f.dir, { checkpoint: { path: f.cp, mode: "seal", requireAppendOnly: false } }), /CHECKPOINT_ALREADY_SEALED/);
  assert.throws(() => parseCheckpoint(`${JSON.stringify({ seq: 0, kind: "CONSUME", prev: "0".repeat(64), hash: "x" })}\n`), /CHECKPOINT_CORRUPT/);
});

test("CK7 recover re-imports lost facts: rejected and abandoned consumptions, a paid claim (UNKNOWN, never NOT_EXECUTED), final states, resolutions", () => {
  const f = fresh();
  const snap = f.snapshot();
  const j = f.open();
  j.consume({ auth_id: "rej", intent_hash: H("a"), disposition: "REJECTED_BEFORE_EXECUTION", detail: "drift" });
  j.reserve({ intent_hash: H("b"), auth_id: "aband", request: REQ, claim_id: C("b") });
  j.record(H("b"), "CLAIM_ABANDONED", "auth unreachable");
  j.reserve({ intent_hash: H("c"), auth_id: "paid", request: REQ, claim_id: C("c") }); // killed after pay: no final state
  j.reserve({ intent_hash: H("d"), auth_id: "resolved", request: REQ, claim_id: C("d") });
  const ev: SettlementEvidence = { kind: "MOCK_LEDGER_MAC", reference: "mock-x", mac: "ab", amount: "9000" };
  j.resolve(H("d"), ev, "ledger checked");
  f.close(j);
  f.restore(snap);
  assert.throws(() => f.open(), /JOURNAL_ROLLBACK_DETECTED:5 /);
  const r = f.open("recover");
  assert.equal(r.rolledBack.length, 5, "4 consumptions and 1 final state");
  assert.throws(() => r.consume({ auth_id: "x", intent_hash: H("e"), disposition: "REJECTED_BEFORE_EXECUTION" }), /JOURNAL_RECOVERY_REQUIRED/, "no other write before recovery");
  const { restored } = r.recoverFromCheckpoint("operator ticket 42");
  assert.equal(restored.length, 7, restored.join("; "));
  assert.equal(r.auth("rej")?.disposition, "REJECTED_BEFORE_EXECUTION");
  assert.equal(r.inspect(H("b"))?.state, "CLAIM_ABANDONED");
  assert.deepEqual([r.inspect(H("c"))?.state, r.inspect(H("c"))?.claim_id], ["UNKNOWN", C("c")], "a lost outcome is UNKNOWN (may have paid), with its claim");
  assert.deepEqual(r.inspect(H("d"))?.resolution?.evidence, ev);
  assert.equal(f.entries().find((e) => e.kind === "RECOVERED")?.kind, "RECOVERED", "the recovery decision is checkpointed");
  f.close(r);
  const k = f.open();
  assert.deepEqual(k.rolledBack, []);
  assert.deepEqual(k.reserve({ intent_hash: H("f"), auth_id: "rej", request: REQ, claim_id: C("f") }), { ok: false, reason: "AUTH_REPLAY" }, "the rejected authorization stays consumed");
  assert.deepEqual(k.reserve({ intent_hash: H("0"), auth_id: "paid", request: REQ, claim_id: C("0") }), { ok: false, reason: "AUTH_REPLAY" });
});

test("CK8 a regressed intent (final in the checkpoint, STARTED in the journal) is detected and restored to its final state", () => {
  const f = fresh();
  const j = f.open();
  j.reserve({ intent_hash: H("9"), auth_id: "a9", request: REQ, claim_id: C("9") });
  const snap = f.snapshot();
  j.record(H("9"), "REFUSED_BEFORE_SIGNING", "mock refused");
  f.close(j);
  f.restore(snap);
  assert.throws(() => f.open(), /INTENT_REGRESSED/);
  const r = f.open("recover");
  r.recoverFromCheckpoint("restore");
  assert.equal(r.inspect(H("9"))?.state, "REFUSED_BEFORE_SIGNING");
});

test("CK9 recover is explicit: normal mode cannot recover; a clean journal recovers nothing", () => {
  const f = fresh();
  const j = f.open();
  assert.throws(() => j.recoverFromCheckpoint("x"), /JOURNAL_RECOVERY_NOT_ENABLED/);
  f.close(j);
  const r = f.open("recover");
  assert.deepEqual(r.rolledBack, []);
});

test("CK10 a damaged (unreadable) journal record is corruption, not rollback: it is never reported missing and stays consumed", () => {
  const f = fresh();
  const j = f.open();
  j.consume({ auth_id: "dmg", intent_hash: H("5"), disposition: "REJECTED_BEFORE_EXECUTION" });
  f.close(j);
  writeFileSync(join(f.dir, "auths", authKey("dmg")), "garbage");
  const k = f.open();
  assert.deepEqual(k.rolledBack, []);
  assert.deepEqual(k.reserve({ intent_hash: H("6"), auth_id: "dmg", request: REQ, claim_id: C("6") }), { ok: false, reason: "AUTH_REPLAY" });
});

// ── 0007: independent-review findings (each test expects the fixed behaviour) ──

test("CK11 F-LOCK: the checkpoint itself is locked; a journal directory swapped under a writer cannot admit a second writer (recover, seal, or another executor)", () => {
  const f = fresh();
  const j = f.open();
  // The journal directory is replaced by an identical copy: journal.lock is now a different inode.
  const snap = f.snapshot();
  f.restore(snap);
  assert.throws(() => f.open(), /CHECKPOINT_LOCKED/, "a second normal writer");
  assert.throws(() => f.open("recover"), /CHECKPOINT_LOCKED/, "journal-cli recover while the executor runs");
  // The first writer still holds it and keeps working; nothing forked.
  j.consume({ auth_id: "after-swap", intent_hash: H("1"), disposition: "REJECTED_BEFORE_EXECUTION" });
  f.close(j);
  const k = f.open();
  assert.deepEqual(k.rolledBack, []);
  assert.equal(f.entries().at(-1)!.kind, "CONSUME");
});

test("CK12 F-LOCK: the checkpoint lock is released when its holder closes, and a crashed holder (process exit) frees it", async () => {
  const f = fresh();
  f.close(f.open());
  const k = f.open();
  f.close(k);
  // A holder that dies: a child process opens the journal and is killed.
  const { spawn } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const mod = new URL("../../src/executor/payment-journal.ts", import.meta.url);
  const code = `import { openFilePaymentJournal } from ${JSON.stringify(fileURLToPath(mod))};
const j = openFilePaymentJournal(${JSON.stringify(f.dir)}, { checkpoint: { path: ${JSON.stringify(f.cp)}, requireAppendOnly: false } });
process.stdout.write("held\\n"); setInterval(() => {}, 1000);`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise<void>((r) => child.stdout!.once("data", () => r()));
  assert.throws(() => f.open(), /JOURNAL_LOCKED|CHECKPOINT_LOCKED/, "held by the child");
  child.kill("SIGKILL");
  await new Promise((r) => child.once("exit", r));
  const after = f.open();
  assert.deepEqual(after.rolledBack, [], "the kernel released both locks");
});

test("CK13 F-NOCK: a journal can no longer be opened for writing without its checkpoint", () => {
  const f = fresh();
  assert.throws(() => openFilePaymentJournal(f.dir, undefined as never), /CHECKPOINT_REQUIRED/);
  assert.throws(() => openFilePaymentJournal(f.dir, {} as never), /CHECKPOINT_REQUIRED/);
  assert.throws(() => openFilePaymentJournal(f.dir, { checkpoint: { path: "" } }), /CHECKPOINT_REQUIRED/);
});

test("CK14 F-TORN2: a crash while acknowledging an earlier torn line (two consecutive torn lines) is recovered, and detection still works", () => {
  const f = fresh();
  appendFileSync(f.cp, '{"seq":1,"kind":"CONS'); // first crash
  appendFileSync(f.cp, '\n{"seq":1,"kind":"TOR'); // second crash, during the TORN acknowledgement
  const j = f.open();
  const t = f.entries().at(-1)!;
  assert.equal(t.kind, "TORN");
  assert.equal(t.kind === "TORN" && t.torn_sha256s?.length, 2, "one TORN names both torn lines");
  const snap = f.snapshot();
  j.consume({ auth_id: "t2", intent_hash: H("2"), disposition: "REJECTED_BEFORE_EXECUTION" });
  f.close(j);
  f.restore(snap);
  assert.throws(() => f.open(), /JOURNAL_ROLLBACK_DETECTED/);
  // A torn line in the middle that nothing acknowledges is still corruption.
  const lines = readFileSync(f.cp, "utf8").split("\n").filter(Boolean);
  assert.throws(() => parseCheckpoint([lines[0], "garbage", lines.at(-1), ""].join("\n")), /CHECKPOINT_CORRUPT/);
});

test("CK15 F-TORN-GENESIS: a crash during seal (only a torn genesis on disk) is UNSEALED, and seal completes it", () => {
  const d = mkdtempSync(join(tmpdir(), "oxdeai-anchor-test-"));
  dirs.push(d);
  mkdirSync(join(d, "executor"));
  const dir = join(d, "executor", "journal");
  initFilePaymentJournal(dir);
  const cp = join(d, "cp.log");
  writeFileSync(cp, '{"seq":0,"kind":"GENE');
  assert.throws(() => openFilePaymentJournal(dir, { checkpoint: { path: cp, requireAppendOnly: false } }).close(), /CHECKPOINT_UNSEALED:.*interrupted seal/);
  openFilePaymentJournal(dir, { checkpoint: { path: cp, mode: "seal", requireAppendOnly: false } }).close();
  const g = readCheckpoint(cp).entries[0]!;
  assert.equal(g.kind, "GENESIS");
  assert.equal(g.kind === "GENESIS" && g.torn_prefix?.length, 1);
  const j = openFilePaymentJournal(dir, { checkpoint: { path: cp, requireAppendOnly: false } });
  assert.deepEqual(j.rolledBack, []);
  j.close();
  assert.throws(() => openFilePaymentJournal(dir, { checkpoint: { path: cp, mode: "seal", requireAppendOnly: false } }), /CHECKPOINT_ALREADY_SEALED/);
});

test("CK16 F-LEGACY: a legacy intent (no claim id) sealed at migration and lost by a rollback is fully recovered from the checkpoint's request", () => {
  const d = mkdtempSync(join(tmpdir(), "oxdeai-anchor-test-"));
  dirs.push(d);
  mkdirSync(join(d, "executor"));
  const dir = join(d, "executor", "journal");
  initFilePaymentJournal(dir);
  // A pre-Phase-2D (legacy) record: consumed, intent without claim_id, final UNKNOWN.
  const at = 1;
  writeFileSync(join(dir, "auths", authKey("legacy")), JSON.stringify({ auth_id: "legacy", intent_hash: H("7"), disposition: "RESERVED", at }));
  writeFileSync(join(dir, "intents", H("7")), JSON.stringify({ intent_hash: H("7"), auth_id: "legacy", state: "UNKNOWN", request: REQ, started_at: at, updated_at: at }));
  const snap = join(d, "snap");
  cpSync(dir, snap, { recursive: true });
  const cp = join(d, "cp.log");
  writeFileSync(cp, "");
  openFilePaymentJournal(dir, { checkpoint: { path: cp, mode: "seal", requireAppendOnly: false } }).close(); // migration seal
  const c = readCheckpoint(cp).consumes.get("legacy")!;
  assert.deepEqual(c.request, REQ, "the request is checkpointed although there is no claim id");
  // Rollback that loses the intent record only.
  rmSync(join(dir, "intents", H("7")));
  assert.throws(() => openFilePaymentJournal(dir, { checkpoint: { path: cp, requireAppendOnly: false } }), /INTENT_MISSING/);
  const r = openFilePaymentJournal(dir, { checkpoint: { path: cp, mode: "recover", requireAppendOnly: false } });
  r.recoverFromCheckpoint("legacy");
  const rec = r.inspect(H("7"))!;
  assert.deepEqual([rec.state, rec.claim_id, rec.request], ["UNKNOWN", undefined, REQ], "restored as it was: legacy, held, never released");
  r.close();
  void snap;
  const k = openFilePaymentJournal(dir, { checkpoint: { path: cp, requireAppendOnly: false } });
  assert.deepEqual(k.rolledBack, []);
  k.close();
});

// SPDX-License-Identifier: MIT
/** J1-J9: durable payment journal and its use by the executor. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import { createMockBuyAdapter } from "../../src/adapters/mock-buy/mock-buy.ts";
import { createPaymentExecutor } from "../../src/executor/executor.ts";
import type { PaymentAdapter } from "../../src/executor/payment-adapter.ts";
import { initFilePaymentJournal, openFilePaymentJournal, type FilePaymentJournal } from "../../src/executor/payment-journal.ts";
import { createLocalSystem } from "../../src/system.ts";
import { authorize, requestFor, SERVICES } from "../helpers.ts";

const H1 = "1".repeat(64);
const H2 = "2".repeat(64);
const REQ = requestFor(SERVICES.weather);

const dirs: string[] = [];
const open: FilePaymentJournal[] = [];
function freshDir(): string {
  // Under /tmp, whose default ACL grants "other" rw- on new files.
  const d = mkdtempSync(join(tmpdir(), "oxdeai-journal-test-"));
  dirs.push(d);
  // Phase 2C: a journal is created once, explicitly, and never implicitly by open.
  initFilePaymentJournal(join(d, "journal"));
  return join(d, "journal");
}
function openJ(dir: string): FilePaymentJournal {
  const j = openFilePaymentJournal(dir);
  open.push(j);
  return j;
}
afterEach(() => {
  for (const j of open.splice(0)) j.close();
  for (const d of dirs.splice(0)) {
    spawnSync("chmod", ["-R", "u+rwx", d]);
    rmSync(d, { recursive: true, force: true });
  }
});


test("J1 records survive close and reopen; a reserved intent is never reserved again", () => {
  const dir = freshDir();
  const j = openJ(dir);
  assert.deepEqual(j.reserve({ intent_hash: H1, auth_id: "a1", request: REQ }), { ok: true });
  j.record(H1, "SETTLED", undefined, { settled: true });
  j.close();
  open.pop();

  const k = openJ(dir);
  assert.deepEqual(k.get(H1), { state: "SETTLED" });
  assert.deepEqual(k.inspect(H1)?.receipt, { settled: true });
  assert.deepEqual(k.reserve({ intent_hash: H1, auth_id: "a9", request: REQ }), { ok: false, reason: "DUPLICATE_INTENT", prior: "SETTLED" });
});

test("J2 an auth_id is consumed durably: reusing it for another intent is AUTH_REPLAY, also after reopen", () => {
  const dir = freshDir();
  const j = openJ(dir);
  j.reserve({ intent_hash: H1, auth_id: "a1", request: REQ });
  j.close();
  open.pop();
  assert.deepEqual(openJ(dir).reserve({ intent_hash: H2, auth_id: "a1", request: REQ }), { ok: false, reason: "AUTH_REPLAY" });
});

test("J3 single writer: a second open fails while the first holds the lock; released on close", () => {
  // Phase 2C (B6): the lock is a kernel flock on the holder's own descriptor;
  // there is no pid file and no stale-lock takeover. Cross-process cases
  // (crash, simultaneous start) are in tests/isolation/financial-integrity.test.ts.
  const dir = freshDir();
  const j = openJ(dir);
  assert.throws(() => openFilePaymentJournal(dir), /JOURNAL_LOCKED/);
  j.close();
  open.pop();
  const k = openJ(dir);
  assert.throws(() => openFilePaymentJournal(dir), /JOURNAL_LOCKED/);
  k.close();
  open.pop();
});

test("J4 crash recovery: STARTED stays STARTED and is listed for reconciliation; never auto-converted", () => {
  const dir = freshDir();
  const j = openJ(dir);
  j.reserve({ intent_hash: H1, auth_id: "a1", request: REQ });
  j.reserve({ intent_hash: H2, auth_id: "a2", request: REQ });
  j.record(H2, "UNKNOWN", "settle_uncertain");
  // Simulated crash: the descriptor (and so the kernel lock) goes away without close().
  open.pop();
  j.close();

  const k = openJ(dir);
  assert.deepEqual(k.get(H1), { state: "STARTED" });
  assert.deepEqual(
    k.needsReconciliation.map((r) => [r.intent_hash, r.state]),
    [
      [H1, "STARTED"],
      [H2, "UNKNOWN"],
    ],
  );
  assert.deepEqual(k.reserve({ intent_hash: H1, auth_id: "a3", request: REQ }), { ok: false, reason: "DUPLICATE_INTENT", prior: "STARTED" });
});

test("J5 only STARTED can move to a final state, once", () => {
  const j = openJ(freshDir());
  assert.throws(() => j.record(H1, "SETTLED"), /JOURNAL_NO_SUCH_INTENT/);
  j.reserve({ intent_hash: H1, auth_id: "a1", request: REQ });
  j.record(H1, "SETTLED");
  assert.throws(() => j.record(H1, "UNKNOWN"), /JOURNAL_ILLEGAL_TRANSITION:SETTLED->UNKNOWN/);
  assert.throws(() => j.reserve({ intent_hash: "../x", auth_id: "a2", request: REQ }), /JOURNAL_INVALID_INTENT_HASH/);
});

test("J6 storage permissions: directories 0700 and files 0600 despite the parent's default ACL", () => {
  const dir = freshDir();
  const j = openJ(dir);
  j.reserve({ intent_hash: H1, auth_id: "a1", request: REQ });
  j.record(H1, "SETTLED");
  for (const d of [dir, join(dir, "intents"), join(dir, "auths")]) assert.equal(statSync(d).mode & 0o777, 0o700, d);
  const files = [
    join(dir, "journal.lock"),
    join(dir, "JOURNAL.json"),
    join(dir, "journal.log"),
    join(dir, "intents", H1),
    ...readdirSync(join(dir, "auths")).map((n) => join(dir, "auths", n)),
  ];
  for (const f of files) assert.equal(statSync(f).mode & 0o777, 0o600, f);
});

test("J7 an unreadable record is reported UNKNOWN, never as absent", () => {
  const dir = freshDir();
  const j = openJ(dir);
  j.reserve({ intent_hash: H1, auth_id: "a1", request: REQ });
  writeFileSync(join(dir, "intents", H1), "{ truncated");
  assert.deepEqual(j.get(H1), { state: "UNKNOWN", detail: "JOURNAL_RECORD_UNREADABLE" });
  assert.deepEqual(j.reserve({ intent_hash: H1, auth_id: "a2", request: REQ }), { ok: false, reason: "DUPLICATE_INTENT", prior: "UNKNOWN" });
});

test("J8 operator resolution: only for STARTED/UNKNOWN, once, and the state is kept", () => {
  const j = openJ(freshDir());
  j.reserve({ intent_hash: H1, auth_id: "a1", request: REQ });
  j.reserve({ intent_hash: H2, auth_id: "a2", request: REQ });
  j.record(H2, "SETTLED");
  const r = j.resolve(H1, "NOT_SETTLED", "ledger has no entry");
  assert.equal(r.state, "STARTED");
  assert.equal(r.resolution?.verdict, "NOT_SETTLED");
  assert.throws(() => j.resolve(H1, "SETTLED", "again"), /JOURNAL_ALREADY_RESOLVED/);
  assert.throws(() => j.resolve(H2, "NOT_SETTLED", "x"), /JOURNAL_NOT_RECONCILABLE:SETTLED/);
});

// ── Executor with the durable journal ─────────────────────────────────────

async function executorWithFileJournal(dir: string, wrap: (a: PaymentAdapter) => PaymentAdapter = (a) => a) {
  const sys = createLocalSystem();
  const mock = createMockBuyAdapter(Object.values(SERVICES));
  const { keySet, authority, audience } = sys.harness.authService.trustMaterial;
  const journal = openJ(dir);
  const executor = createPaymentExecutor({
    internalToken: "t".repeat(64),
    adapter: wrap(mock.adapter),
    verification: { expectedAudience: audience, trustedKeySets: [keySet], trustedAuthorizationAuthorities: [authority], now: sys.harness.clock.now },
    journal,
  });
  const auth = await authorize(sys, requestFor(SERVICES.weather));
  const body = { action: { request: auth.request, intent_ref: auth.intent_ref }, authorization: auth.authorization };
  return { executor, journal, mock: mock.inspect, body, intentHash: auth.authorization.intent_hash, headers: { [INTERNAL_EXECUTOR_TOKEN_HEADER]: "t".repeat(64) } };
}

test("J9a journal unwritable at reservation: NOT_EXECUTED before pay, no payment", async () => {
  const dir = freshDir();
  const x = await executorWithFileJournal(dir);
  chmodSync(join(dir, "auths"), 0o500);
  const res = await x.executor.handle(x.body, x.headers);
  assert.equal(res.executed, false);
  assert.match((res.body as { error: string }).error, /^EXECUTOR_JOURNAL_UNAVAILABLE:.*EACCES/);
  assert.equal(x.mock.counters.payments, 0);
});

test("J9b journal unwritable after settlement: PAYMENT_UNKNOWN, journal still STARTED", async () => {
  const dir = freshDir();
  const x = await executorWithFileJournal(dir, (inner) => ({
    quote: (r) => inner.quote(r),
    pay: async (p) => {
      const receipt = await inner.pay(p);
      chmodSync(join(dir, "intents"), 0o500);
      return receipt;
    },
  }));
  const res = await x.executor.handle(x.body, x.headers);
  assert.equal(res.executed, "unknown");
  assert.match((res.body as { error: string }).error, /^EXECUTOR_JOURNAL_WRITE_FAILED:/);
  assert.equal(x.mock.counters.payments, 1);
  chmodSync(join(dir, "intents"), 0o700);
  assert.deepEqual(x.journal.get(x.intentHash), { state: "STARTED" });
});

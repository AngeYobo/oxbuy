// SPDX-License-Identifier: MIT
/**
 * Remediation of AUD-02 / AUD-03 / AUD-04 (executor journal rollback), process level: real processes
 * under the four service identities, the append-only consumption checkpoint
 * (src/executor/executor-anchor.ts), mock payments only, synthetic keys, disposable state roots.
 *
 *   RB2-*  AUD-02  an authorization consumed (rejected or abandoned) while the auth service was down never
 *                  becomes payable again: not after an executor restart, a journal rollback, a gateway
 *                  restart, repeated submissions, or repeated/delayed outcome reports
 *   RB3-*  AUD-03  journal rollback is detected (at startup and while running) and blocks every payment
 *                  until an operator recovery; no false positives on restart, crash, torn checkpoint line
 *   RB4-*  AUD-04  a paid claim whose journal record was lost is recovered and confirmed only with
 *                  verified settlement evidence; forged, mismatched, duplicated, ambiguous or missing
 *                  evidence never moves the reservation, and unresolved outcomes stay fully charged
 *
 * Every test checks the mock ledger (ground truth of payments) and the budget, not only responses.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { canonicalJson } from "../../src/executor/outcome-report.ts";
import { identitiesUnavailableReason } from "../../src/isolation/identity.ts";
import type { IsolatedSystem } from "../../src/isolation/launcher.ts";
import { AGENT_ID, SERVICES } from "../../src/system.ts";
import { freshExecutorState, freshPolicyState, REPO_ROOT, removeStateRoot, trustedArtifact } from "./trusted-artifact.ts";

const BLOCKED = identitiesUnavailableReason();
const opts = BLOCKED === null ? {} : { skip: `BLOCKED: ${BLOCKED}` };
const PROBE = join(REPO_ROOT, "tests", "isolation", "agent-probe.ts");
const NODE = realpathSync(process.execPath);
const PRICE = BigInt(SERVICES.weather.price);

let trusted: Awaited<ReturnType<typeof trustedArtifact>>;
const roots: string[] = [];
const systems: IsolatedSystem[] = [];
before(async () => {
  if (BLOCKED === null) trusted = await trustedArtifact();
});
after(async () => {
  for (const s of systems.splice(0)) await s.stop();
  for (const r of roots.splice(0)) removeStateRoot(r);
  trusted?.cleanup();
});

const sudo = (args: string[], input?: string) => spawnSync("sudo", ["-n", ...args], { encoding: "utf8", input });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const request = () => ({
  service_id: SERVICES.weather.service_id,
  method: "POST",
  url: `${SERVICES.weather.resource}?city=lagos`,
  body: JSON.stringify({ units: "metric", days: 3 }),
  network: SERVICES.weather.network,
  asset: SERVICES.weather.asset,
  recipient: SERVICES.weather.pay_to,
  max_amount: SERVICES.weather.price.toString(),
});
type Reservation = { state: string; charged: string; claim?: { claim_id: string }; dead_claims?: string[]; history: { outcome?: string; reason?: string; claim_id?: string }[] };
const policyFile = (s: IsolatedSystem) =>
  JSON.parse(s.privileged.read(join(s.paths.authStateDir, "state.json")).toString("utf8")) as {
    state: { budget: { spent_in_period: Record<string, { $bigint: string }> } };
    reservations: Record<string, Reservation>;
  };
const spent = (s: IsolatedSystem) => BigInt(policyFile(s).state.budget.spent_in_period[AGENT_ID]?.$bigint ?? "0");
const reservation = (s: IsolatedSystem, id: string) => policyFile(s).reservations[id]!;
const authorizeAsAgent = async (s: IsolatedSystem) => (await s.runAgent(PROBE, ["authorize-only", s.paths.publicSocket])).result as any;
const submit = async (s: IsolatedSystem, a: { authorization: any; intent_ref: any }) =>
  (await s.runAgent(PROBE, ["submit", s.paths.publicSocket, JSON.stringify({ request: request(), intent_ref: a.intent_ref, authorization: a.authorization })])).result as any;
const buy = async (s: IsolatedSystem) => ((await s.runAgent(PROBE, ["buy", s.paths.publicSocket, "weather"])).result as any)?.result?.decision as string;
async function waitFor<T>(what: string, fn: () => T | undefined | false, timeoutMs = 20_000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await sleep(250);
  }
}
async function launch(budget: bigint, ttlSeconds = 60, extra: Record<string, unknown> = {}) {
  const policyStateRoot = freshPolicyState({ budget: String(budget), ttlSeconds });
  const executorStateRoot = freshExecutorState();
  roots.push(policyStateRoot, executorStateRoot);
  const s = await trusted.launch({ policyStateRoot, executorStateRoot, ttlSeconds, reconcileIntervalMs: 300, expiryReleaseIntervalMs: 300, ...extra });
  systems.push(s);
  return s;
}
const snapshotJournal = (s: IsolatedSystem) => {
  const parent = mkdtempSync(join(tmpdir(), "oxdeai-journal-snap-"));
  const snap = join(parent, "journal");
  roots.push(snap); // removeStateRoot removes dirname(snap): this mkdtemp parent only (guarded)
  assert.equal(sudo(["cp", "-a", s.paths.journalDir, snap]).status, 0);
  return snap;
};
const restoreJournal = (s: IsolatedSystem, snap: string) => {
  assert.equal(sudo(["mv", "-T", s.paths.journalDir, `${s.paths.journalDir}.newer-${Date.now()}`]).status, 0);
  assert.equal(sudo(["cp", "-a", snap, s.paths.journalDir]).status, 0);
};
const cli = (s: IsolatedSystem, ...args: string[]) => s.runAsSync("executor", [NODE, join(s.paths.apps.executor, "src/isolation/journal-cli.ts"), s.paths.journalDir, ...args]);
const verify = (s: IsolatedSystem) => JSON.parse(cli(s, "verify").stdout) as { outcome: string; rolled_back: unknown[] };
const recover = (s: IsolatedSystem) => {
  const r = cli(s, "recover", "audit: executor state restored from a snapshot");
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout) as { outcome: string; found: string[]; restored: string[] };
};
const checkpointKinds = (s: IsolatedSystem) =>
  s.privileged
    .read(s.paths.executorAnchorPath)
    .toString("utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      try {
        return (JSON.parse(l) as { kind: string }).kind;
      } catch {
        return "TORN-LINE";
      }
    });
const executorLogs = (s: IsolatedSystem) =>
  s.privileged
    .list(s.paths.logsDir)
    .filter((n) => n.startsWith("executor-"))
    .map((n) => s.privileged.read(join(s.paths.logsDir, n)).toString("utf8"))
    .join("\n");
/** No intent record means `pay` was never reached for it (pay runs only after a STARTED record and its checkpoint). */
const neverReachedPay = (s: IsolatedSystem, a: { authorization: any }) => assert.equal(s.journal().inspect(a.authorization.intent_hash), undefined, "the payment adapter was never reached");

// ── AUD-02 ────────────────────────────────────────────────────────────────

test("RB2-a AUD-02 original sequence: auth outage, pre-payment rejection, VOID lost, executor restart + journal rollback + gateway restart, repeated submissions: never paid, no incorrect release", opts, async () => {
  const s = await launch(PRICE, 10);
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id as string;
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  await s.startExecutor({ quoteDrift: true });
  await s.stopAuth(); // the authorization service is unreachable: the synchronous VOID is lost
  const r1 = await submit(s, a);
  assert.notEqual(r1.decision, "ALLOW", JSON.stringify(r1));
  assert.equal(s.journal().auth(id)?.disposition, "REJECTED_BEFORE_EXECUTION");
  await s.startAuth();
  assert.equal(reservation(s, id).state, "RESERVED", "precondition: the VOID never reached the auth service");
  // Executor restart with the journal rolled back to before the consumption.
  await s.stopExecutor();
  restoreJournal(s, snap);
  await assert.rejects(s.startExecutor(), /JOURNAL_ROLLBACK_DETECTED/, "the executor refuses to serve a rolled-back journal");
  await s.restartGateway();
  for (let i = 0; i < 2; i++) assert.notEqual((await submit(s, a)).decision, "ALLOW", "nothing executes while the executor refuses");
  assert.equal(s.ledger().length, 0);
  // Operator recovery from the checkpoint, then everything restarted and the authorization resubmitted twice.
  const rec = recover(s);
  assert.deepEqual(rec.restored, [`auth ${id} REJECTED_BEFORE_EXECUTION`]);
  await s.startExecutor();
  await s.restartGateway();
  for (let i = 0; i < 2; i++) {
    const r = await submit(s, a);
    assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
    assert.match(JSON.stringify(r), /REPLAY/);
  }
  assert.equal(s.ledger().length, 0, "the previously rejected authorization never paid");
  neverReachedPay(s, a);
  // No incorrect release: unclaimed, it stays charged until it expires on the auth service's clock.
  const rel = await waitFor("released at expiry", () => reservation(s, id).state === "RELEASED" && reservation(s, id), 30_000);
  assert.deepEqual([rel.claim, rel.history.at(-1)!.reason], [undefined, "EXPIRED_UNCLAIMED"]);
  assert.equal(spent(s), 0n);
});

test("RB2-b AUD-02 abandoned variant: claim unreachable (CLAIM_ABANDONED), abandonment report and VOID lost, rollback: never paid; the restored positive record is redelivered without releasing a claimed reservation", opts, async () => {
  const s = await launch(PRICE, 10);
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id as string;
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  await s.startExecutor();
  await s.stopAuth();
  const r1 = await submit(s, a);
  assert.notEqual(r1.decision, "ALLOW", JSON.stringify(r1));
  assert.equal(s.journal().inspect(a.authorization.intent_hash)?.state, "CLAIM_ABANDONED");
  await s.stopExecutor(); // before the auth service is back: the abandonment report is never delivered
  restoreJournal(s, snap);
  await s.startAuth();
  await assert.rejects(s.startExecutor(), /JOURNAL_ROLLBACK_DETECTED/);
  recover(s);
  assert.equal(s.journal().inspect(a.authorization.intent_hash)?.state, "CLAIM_ABANDONED", "the positive record is back");
  await s.startExecutor();
  await s.restartGateway();
  assert.match(JSON.stringify(await submit(s, a)), /AUTH_REPLAY|DUPLICATE_PAYMENT_ATTEMPT/);
  // Repeated / delayed delivery of the restored report: the claim never committed, so nothing moves.
  await s.stopExecutor();
  await s.startExecutor();
  await sleep(1_000);
  const r = reservation(s, id);
  assert.equal(r.state, "RESERVED", "a report about a claim that never committed releases nothing");
  assert.ok(r.dead_claims?.includes(s.journal().inspect(a.authorization.intent_hash)!.claim_id!), "that claim can never be granted later");
  assert.equal(s.ledger().length, 0);
  const rel = await waitFor("released at expiry", () => reservation(s, id).state === "RELEASED" && reservation(s, id), 30_000);
  assert.equal(rel.history.at(-1)!.reason, "EXPIRED_UNCLAIMED");
  assert.equal(spent(s), 0n);
});

test("RB2-c AUD-02/03 rollback while the executor keeps running: the replay is refused before any claim; the executor stops writing and reports the rollback", opts, async () => {
  const s = await launch(2n * PRICE);
  const a = await authorizeAsAgent(s);
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  await s.startExecutor({ quoteDrift: true });
  await s.stopAuth();
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  await s.startAuth();
  await s.stopExecutor();
  await s.startExecutor(); // normal executor, then the journal is replaced under it
  restoreJournal(s, snap);
  await s.restartGateway();
  const r = await submit(s, a);
  assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
  assert.match(JSON.stringify(r), /JOURNAL_ROLLBACK_DETECTED/);
  assert.equal(s.ledger().length, 0);
  neverReachedPay(s, a);
  assert.match(executorLogs(s), /journal_rollback_detected/);
  assert.notEqual(await buy(s), "ALLOW", "fail closed: no further payment until recovery");
  assert.equal(s.ledger().length, 0);
  assert.equal(reservation(s, a.authorization.auth_id).state, "RESERVED");
});

// ── AUD-03 ────────────────────────────────────────────────────────────────

test("RB3-a normal operation and restarts: no false positive; checkpoint follows the journal", opts, async () => {
  const s = await launch(3n * PRICE);
  assert.equal(await buy(s), "ALLOW");
  for (let i = 0; i < 2; i++) {
    await s.stopExecutor();
    await s.startExecutor();
  }
  await s.restartAuth();
  await s.restartGateway();
  assert.equal(await buy(s), "ALLOW");
  assert.equal(s.ledger().length, 2);
  assert.equal(verify(s).outcome, "SAFE_TO_RESUME");
  const kinds = checkpointKinds(s);
  assert.equal(kinds[0], "GENESIS");
  assert.deepEqual([kinds.filter((k) => k === "CONSUME").length, kinds.filter((k) => k === "FINAL").length], [2, 2]);
});

test("RB3-b truncated journal (a record deleted) is a rollback and refused; a corrupted record is corruption, handled fail-closed as before", opts, async () => {
  const s = await launch(3n * PRICE);
  assert.equal(await buy(s), "ALLOW");
  const [p1] = s.journal().list();
  await s.stopExecutor();
  // Corruption: unreadable intent record. Not a rollback; the executor starts; the record is never released or re-paid.
  const intentFile = join(s.paths.journalDir, "intents", p1!.intent_hash);
  const original = s.privileged.read(intentFile).toString("utf8");
  sudo(["sh", "-c", `printf 'garbage' > '${intentFile}'`]);
  await s.startExecutor();
  assert.equal(verify(s).outcome, "SAFE_TO_RESUME");
  await s.stopExecutor();
  sudo(["tee", intentFile], original);
  // Truncation: the record is gone.
  sudo(["rm", "-f", intentFile]);
  await assert.rejects(s.startExecutor(), /JOURNAL_ROLLBACK_DETECTED:.*INTENT_MISSING/);
  assert.equal(verify(s).outcome, "ROLLBACK_DETECTED");
  assert.equal(s.ledger().length, 1);
});

test("RB3-c a valid older journal snapshot restored: detected at startup, refused until recovery, nothing paid in between", opts, async () => {
  const s = await launch(3n * PRICE);
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  await s.startExecutor();
  assert.equal(await buy(s), "ALLOW");
  await s.stopExecutor();
  restoreJournal(s, snap);
  await assert.rejects(s.startExecutor(), /JOURNAL_ROLLBACK_DETECTED/);
  const v = verify(s);
  assert.equal(v.outcome, "ROLLBACK_DETECTED");
  assert.ok(v.rolled_back.length >= 2, JSON.stringify(v));
  assert.notEqual(await buy(s), "ALLOW", "no payment while refused");
  assert.equal(s.ledger().length, 1);
  recover(s);
  assert.equal(verify(s).outcome, "SAFE_TO_RESUME");
  await s.startExecutor();
  assert.equal(s.journal().list()[0]!.state, "SETTLED", "the settled record is restored from the checkpoint");
  assert.equal(await buy(s), "ALLOW");
  assert.equal(s.ledger().length, 2);
});

test("RB3-d crash during the checkpoint update: killed between the journal write and its checkpoint entry (nothing paid), and a torn checkpoint line: both recover without a false rollback", opts, async () => {
  const s = await launch(2n * PRICE, 10);
  const a = await authorizeAsAgent(s);
  await s.stopExecutor();
  await s.startExecutor({ crashBeforeCheckpoint: true });
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  await s.executorExited();
  assert.equal(s.ledger().length, 0, "killed before the checkpoint entry: no claim, no payment");
  assert.equal(s.journal().inspect(a.authorization.intent_hash)?.state, "STARTED");
  await s.startExecutor(); // catch-up: the journal is ahead of the checkpoint
  assert.equal(verify(s).outcome, "SAFE_TO_RESUME");
  assert.equal(checkpointKinds(s).at(-1), "CONSUME");
  await s.restartGateway();
  assert.match(JSON.stringify(await submit(s, a)), /AUTH_REPLAY|DUPLICATE_PAYMENT_ATTEMPT/);
  // Torn final line (crash during an append), written as root: acknowledged at the next start.
  await s.stopExecutor();
  sudo(["sh", "-c", `printf '{"seq":99,"kind":"CONS' >> '${s.paths.executorAnchorPath}'`]);
  await s.startExecutor();
  assert.deepEqual(checkpointKinds(s).slice(-2), ["TORN-LINE", "TORN"]);
  assert.equal(await buy(s), "ALLOW");
  assert.equal(s.ledger().length, 1);
  const rel = await waitFor("unclaimed one released at expiry", () => reservation(s, a.authorization.auth_id).state === "RELEASED" && reservation(s, a.authorization.auth_id), 30_000);
  assert.equal(rel.history.at(-1)!.reason, "EXPIRED_UNCLAIMED");
});

test("RB3-e checkpoint unavailable: missing, not append-only, or unsealed: the executor refuses to start; agent and gateway cannot touch it", opts, async () => {
  const s = await launch(2n * PRICE);
  const cp = s.paths.executorAnchorPath;
  for (const role of ["agent", "gateway"] as const) {
    const w = (await s.runAs(role, PROBE, ["write", cp])).result as Record<string, { ok: boolean }>;
    const u = (await s.runAs(role, PROBE, ["unlink", cp])).result as Record<string, { ok: boolean }>;
    assert.equal(w[cp]!.ok, false, `${role} appended to the checkpoint`);
    assert.equal(u[cp]!.ok, false, `${role} deleted the checkpoint`);
  }
  const t = s.runAsSync("executor", ["/usr/bin/truncate", "-s", "0", cp]);
  assert.notEqual(t.status, 0, "even its owner cannot truncate it (append-only)");
  assert.match(t.stderr, /Operation not permitted/);
  await s.stopExecutor();
  sudo(["chattr", "-a", cp]);
  sudo(["mv", cp, `${cp}.away`]);
  await assert.rejects(s.startExecutor(), /CHECKPOINT_MISSING/);
  sudo(["mv", `${cp}.away`, cp]);
  await assert.rejects(s.startExecutor(), /CHECKPOINT_NOT_APPEND_ONLY/);
  const saved = s.privileged.read(cp).toString("utf8");
  sudo(["truncate", "-s", "0", cp]);
  sudo(["chattr", "+a", cp]);
  await assert.rejects(s.startExecutor(), /CHECKPOINT_UNSEALED/);
  sudo(["chattr", "-a", cp]);
  sudo(["tee", cp], saved);
  sudo(["chattr", "+a", cp]);
  await s.startExecutor();
  assert.equal(await buy(s), "ALLOW");
  assert.equal(s.ledger().length, 1);
});

test("RB3-f restoration across execution domains: another domain's journal or checkpoint is refused", opts, async () => {
  const s = await launch(2n * PRICE);
  const other = await launch(2n * PRICE);
  assert.equal(await buy(other), "ALLOW");
  await s.stopExecutor();
  await other.stopExecutor();
  // Another domain's (valid) journal restored in place of this one.
  const mine = snapshotJournal(s);
  sudo(["rm", "-rf", "--", s.paths.journalDir]);
  assert.equal(sudo(["cp", "-a", other.paths.journalDir, s.paths.journalDir]).status, 0);
  await assert.rejects(s.startExecutor(), /EXECUTION_DOMAIN_MISMATCH:journal/);
  sudo(["rm", "-rf", "--", s.paths.journalDir]);
  assert.equal(sudo(["cp", "-a", mine, s.paths.journalDir]).status, 0);
  // Another domain's checkpoint in place of this one's.
  const cp = s.paths.executorAnchorPath;
  const saved = s.privileged.read(cp).toString("utf8");
  sudo(["chattr", "-a", cp]);
  sudo(["tee", cp], other.privileged.read(other.paths.executorAnchorPath).toString("utf8"));
  sudo(["chattr", "+a", cp]);
  await assert.rejects(s.startExecutor(), /CHECKPOINT_DOMAIN_MISMATCH/);
  sudo(["chattr", "-a", cp]);
  sudo(["tee", cp], saved);
  sudo(["chattr", "+a", cp]);
  await s.startExecutor();
  assert.equal(s.ledger().length, 0);
});

// ── AUD-04 ────────────────────────────────────────────────────────────────

test("RB4 paid claim with a lost journal record: recovered as UNKNOWN and fully charged; only exact, MAC-verified evidence confirms it; forged, foreign, mismatched, ambiguous, missing and duplicate evidence are refused; replay never pays", opts, async () => {
  const s = await launch(2n * PRICE);
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id as string;
  const h = a.authorization.intent_hash as string;
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  await s.startExecutor({ crashAfterPay: true });
  await submit(s, a);
  await s.executorExited();
  assert.equal(s.ledger().length, 1, "precondition: paid under its claim");
  const entry = s.ledger()[0]!;
  const claimId = entry.claim_id!;
  restoreJournal(s, snap);
  await assert.rejects(s.startExecutor(), /JOURNAL_ROLLBACK_DETECTED/);
  assert.match(cli(s, "resolve", h, "SETTLED", "too early").stderr, /JOURNAL_ROLLBACK_DETECTED/, "no resolution on a rolled-back journal");
  recover(s);
  const rec = s.journal().inspect(h)!;
  assert.deepEqual([rec.state, rec.claim_id], ["UNKNOWN", claimId], "unresolved, bound to its claim; never NOT_EXECUTED");
  await s.startExecutor();
  await waitFor("reported UNCERTAIN", () => reservation(s, id).state === "UNCERTAIN");
  assert.equal(reservation(s, id).charged, String(PRICE), "full charge while unresolved");
  await s.stopExecutor();

  // Adversarial evidence, crafted by root with the real wallet key where a valid MAC is needed.
  const ledgerPath = s.paths.ledgerPath;
  const originalLedger = s.privileged.read(ledgerPath).toString("utf8");
  const key = s.privileged.read(s.paths.walletKeyPath);
  const mac = (e: { intent_hash: string; claim_id?: string; journal_id?: string; receipt: unknown }) =>
    createHmac("sha256", key).update(canonicalJson({ intent_hash: e.intent_hash, claim_id: e.claim_id, journal_id: e.journal_id, receipt: e.receipt })).digest("hex");
  const line = (patch: Record<string, unknown>, receiptPatch: Record<string, unknown> = {}, valid = true) => {
    const e = { intent_hash: entry.intent_hash, claim_id: entry.claim_id, journal_id: entry.journal_id, receipt: { ...entry.receipt, ...receiptPatch }, ...patch };
    return `${JSON.stringify({ ...e, mac: valid ? mac(e) : "00".repeat(32) })}\n`;
  };
  const cases: [string, string, RegExp][] = [
    ["forged MAC", line({}, {}, false), /EVIDENCE_INVALID:mac/],
    ["another claim", line({ claim_id: "f".repeat(32) }), /EVIDENCE_INVALID:claim_id/],
    ["another domain", line({ journal_id: "0".repeat(32) }), /EVIDENCE_INVALID:journal_id/],
    ["wrong recipient", line({}, { pay_to: "0x9999999999999999999999999999999999999999" }), /EVIDENCE_INVALID:outside the authorized binding/],
    ["wrong network", line({}, { network: "celo-mainnet" }), /EVIDENCE_INVALID:outside the authorized binding/],
    ["wrong asset", line({}, { asset: "mock-other" }), /EVIDENCE_INVALID:outside the authorized binding/],
    ["amount above the authorization", line({}, { amount: String(PRICE + 1n) }), /EVIDENCE_INVALID:amount exceeds/],
    ["not settled", line({}, { settled: false }), /EVIDENCE_INVALID:receipt/],
    ["ambiguous (two entries)", originalLedger + line({}), /CONFLICTING_EVIDENCE/],
    ["unavailable (no entry)", "", /NO_SETTLEMENT_EVIDENCE/],
  ];
  for (const [label, text, err] of cases) {
    sudo(["tee", ledgerPath], text);
    const r = cli(s, "resolve", h, "SETTLED", `audit: ${label}`);
    assert.notEqual(r.status, 0, `${label} accepted`);
    assert.match(r.stderr, err, label);
    assert.equal(s.journal().inspect(h)!.resolution, undefined, `${label}: nothing attached`);
  }
  assert.match(cli(s, "resolve", h, "NOT_SETTLED", "audit").stderr, /RESOLUTION_REFUSED/, "absence is never evidence of non-execution");
  sudo(["tee", ledgerPath], originalLedger);
  await s.startExecutor();
  await sleep(1_000);
  assert.deepEqual([reservation(s, id).state, reservation(s, id).charged], ["UNCERTAIN", String(PRICE)], "refused evidence moved nothing");
  await s.stopExecutor();

  // The legitimate recovery, then a duplicate of it.
  const ok = cli(s, "resolve", h, "SETTLED", "audit: ledger entry verified");
  assert.equal(ok.status, 0, ok.stderr);
  const dup = cli(s, "resolve", h, "SETTLED", "audit: duplicate");
  assert.notEqual(dup.status, 0);
  assert.match(dup.stderr, /JOURNAL_ALREADY_RESOLVED/);
  assert.ok(checkpointKinds(s).includes("RESOLVED"), "the recovery decision is in the append-only checkpoint");
  await s.startExecutor();
  const conf = await waitFor("CONFIRMED", () => reservation(s, id).state === "CONFIRMED" && reservation(s, id));
  assert.equal(conf.charged, entry.receipt.amount, "charged exactly the evidenced amount");
  assert.equal(conf.claim?.claim_id, claimId);

  // Restart everything and replay: never paid twice, the confirmation stands.
  await s.restartAuth();
  await s.stopExecutor();
  await s.startExecutor();
  await s.restartGateway();
  assert.match(JSON.stringify(await submit(s, a)), /AUTH_REPLAY|DUPLICATE_PAYMENT_ATTEMPT/);
  assert.equal(s.ledger().length, 1, "no duplicate payment");
  assert.equal(reservation(s, id).state, "CONFIRMED");
  assert.equal(spent(s), BigInt(entry.receipt.amount));
  assert.equal(verify(s).outcome, "SAFE_TO_RESUME");
});

// ── 0007: independent-review findings, each expecting the fixed behaviour ──

const executorCli = (...args: string[]) => spawnSync(NODE, [join(REPO_ROOT, "src/isolation/executor-cli.ts"), ...args], { encoding: "utf8", timeout: 60_000 });

test("RB5-a F-LOCK (review P-S1a inverted): journal restored under a running executor, then recover WITHOUT stopping it: refused (CHECKPOINT_LOCKED); no fork; after a proper stop the rollback is detected and recovered; nothing paid", opts, async () => {
  const s = await launch(3n * PRICE);
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id as string;
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  await s.startExecutor({ quoteDrift: true });
  await s.stopAuth();
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  await s.startAuth();
  assert.equal(reservation(s, id).state, "RESERVED", "VOID lost");
  await s.stopExecutor();
  await s.startExecutor();
  restoreJournal(s, snap); // rollback under the running executor
  const rec = cli(s, "recover", "operator did not stop the executor");
  assert.notEqual(rec.status, 0, "recover must not run beside a live writer");
  assert.match(rec.stderr, /CHECKPOINT_LOCKED/);
  await s.restartGateway();
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  assert.equal(s.ledger().length, 0);
  assert.equal(verify(s).outcome, "ROLLBACK_DETECTED", "the chain did not fork");
  await s.stopExecutor();
  await assert.rejects(s.startExecutor(), /JOURNAL_ROLLBACK_DETECTED/);
  recover(s);
  await s.startExecutor();
  await s.restartGateway();
  assert.match(JSON.stringify(await submit(s, a)), /AUTH_REPLAY|DUPLICATE_PAYMENT_ATTEMPT/);
  assert.equal(s.ledger().length, 0, "the rejected authorization never paid");
  assert.equal(verify(s).outcome, "SAFE_TO_RESUME");
});

test("RB5-b F-LOCK (review P-S1b inverted): journal directory replaced by an identical copy while the executor runs: a second executor is refused (exit 75, CHECKPOINT_LOCKED); exactly one writer", opts, async () => {
  const s = await launch(3n * PRICE);
  const first = s.pids().executor!;
  await assert.rejects(s.startExecutor(), /JOURNAL_LOCKED|code 75/, "control: the journal lock works while the directory is untouched");
  const snap = snapshotJournal(s);
  restoreJournal(s, snap);
  await assert.rejects(s.startExecutor(), /CHECKPOINT_LOCKED/, "the swapped journal.lock no longer admits a second writer");
  // (other tests' systems are still running in this file, so the check is on this system's process only)
  assert.equal(s.pids().executor, first, "the first executor is still the only writer of this journal");
  assert.equal(spawnSync("sudo", ["-n", "kill", "-0", String(first)]).status, 0, "and it is alive");
  assert.equal(await buy(s), "ALLOW");
  assert.equal(s.ledger().length, 1);
  assert.equal(spent(s), PRICE);
  assert.equal(verify(s).outcome, "SAFE_TO_RESUME");
});

test("RB5-c S2 (review P-RUNBOOK-UNSEALED inverted): an empty (unsealed) checkpoint is completed by the documented `executor-cli seal`; the executor then pays normally", opts, async () => {
  const s = await launch(2n * PRICE);
  const cp = s.paths.executorAnchorPath;
  await s.stopExecutor();
  sudo(["chattr", "-a", cp]);
  sudo(["truncate", "-s", "0", cp]);
  sudo(["chattr", "+a", cp]);
  await assert.rejects(s.startExecutor(), /CHECKPOINT_UNSEALED/);
  const r = executorCli("seal", s.paths.executorStateRoot);
  assert.equal(r.status, 0, r.stderr);
  assert.match(executorCli("seal", s.paths.executorStateRoot).stderr, /CHECKPOINT_ALREADY_SEALED/, "never sealed twice");
  await s.startExecutor();
  assert.equal(await buy(s), "ALLOW");
  assert.equal(s.ledger().length, 1);
  assert.equal(spent(s), PRICE);
});

test("RB5-d F-SIBLING mitigation: a checkpoint that lost its append-only attribute (e.g. restored by a backup tool) is never re-armed by the tooling; the executor stays refused", opts, async () => {
  const s = await launch(2n * PRICE);
  const cp = s.paths.executorAnchorPath;
  assert.equal(await buy(s), "ALLOW");
  await s.stopExecutor();
  sudo(["chattr", "-a", cp]); // what a cp -a / tar restore leaves behind
  const r = executorCli("seal", s.paths.executorStateRoot);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /CHECKPOINT_NOT_APPEND_ONLY/);
  assert.doesNotMatch(sudo(["lsattr", cp]).stdout.split(/\s+/)[0] ?? "", /a/, "the attribute was not re-added");
  await assert.rejects(s.startExecutor(), /CHECKPOINT_NOT_APPEND_ONLY/);
  assert.equal(s.ledger().length, 1);
  sudo(["chattr", "+a", cp]); // test cleanup only (the test-owned root is removed afterwards)
});

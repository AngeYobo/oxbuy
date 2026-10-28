// SPDX-License-Identifier: MIT
/**
 * Phase 2C: financial integrity under crashes, restarts, redeployment, and
 * adversarial reports. Real processes under the four service identities,
 * disposable state roots, mock payments only.
 *
 * Invariants checked by `assertConsistent`:
 *   I1  budget charge == sum of `charged` over all reservations
 *       (>= after an operator restore, which carries the newer charge forward)
 *   I2  charge <= budget limit
 *   I3  every SETTLED journal intent has exactly one ledger entry, and no
 *       intent that may have paid (SETTLED / STARTED / UNKNOWN) has a RELEASED reservation
 *   I4  every RELEASED reservation of this journal's domain has its auth_id
 *       consumed in the journal, with no payment record (it can never pay)
 *   I5  no intent paid twice
 *
 * CX1 / CX2 are the counterexamples found during Phase 2C
 * (evidence/phase-2c/counterexamples/); these are their permanent regressions.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { parseMockLedger } from "../../src/adapters/mock-buy/mock-settlement.ts";
import { parseAnchor, sha256 } from "../../src/authorization/policy-anchor.ts";
import { identitiesUnavailableReason } from "../../src/isolation/identity.ts";
import type { IsolatedSystem } from "../../src/isolation/launcher.ts";
import { restorePolicyState } from "../../src/isolation/policy-state-admin.ts";
import { AGENT_ID, SERVICES } from "../../src/system.ts";
import { freshExecutorState, freshPolicyState, REPO_ROOT, removeStateRoot, trustedArtifact, type TestLaunchOptions } from "./trusted-artifact.ts";

const BLOCKED = identitiesUnavailableReason();
const opts = BLOCKED === null ? {} : { skip: `BLOCKED: ${BLOCKED}` };
const PROBE = join(REPO_ROOT, "tests", "isolation", "agent-probe.ts");
const SETTLE = join(REPO_ROOT, "tests", "isolation", "settle-probe.ts");
const NODE = realpathSync(process.execPath);
const PRICE = BigInt(SERVICES.weather.price);

let trusted: Awaited<ReturnType<typeof trustedArtifact>>;
const roots: string[] = [];
const systems: IsolatedSystem[] = [];
const scratch: string[] = [];
before(async () => {
  if (BLOCKED === null) trusted = await trustedArtifact();
});
after(async () => {
  for (const s of systems.splice(0)) await s.stop();
  for (const r of roots.splice(0)) removeStateRoot(r);
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  trusted?.cleanup();
});

const policyRoot = (budget: string, ttlSeconds?: number) => {
  const r = freshPolicyState({ budget, ttlSeconds });
  roots.push(r);
  return r;
};
const executorRoot = () => {
  const r = freshExecutorState();
  roots.push(r);
  return r;
};
async function launch(o: TestLaunchOptions): Promise<IsolatedSystem> {
  const s = await trusted.launch({ reconcileIntervalMs: 300, cancelGraceSeconds: 1, ...o });
  systems.push(s);
  return s;
}
async function stop(s: IsolatedSystem): Promise<void> {
  await s.stop();
  systems.splice(systems.indexOf(s), 1);
}

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

type Reservation = {
  auth_id: string;
  intent_hash: string;
  state: string;
  charged: string;
  domain: { journal_id: string } | null;
  history: { state: string; outcome?: string; reason?: string }[];
};
type PolicyFile = {
  version: number;
  state: { budget: { budget_limit: Record<string, { $bigint: string }>; spent_in_period: Record<string, { $bigint: string }> } };
  reservations: Record<string, Reservation>;
};

const statePath = (s: IsolatedSystem) => join(s.paths.authStateDir, "state.json");
const policyFile = (s: IsolatedSystem): PolicyFile => JSON.parse(s.privileged.read(statePath(s)).toString("utf8"));
const spent = (f: PolicyFile) => BigInt(f.state.budget.spent_in_period[AGENT_ID]?.$bigint ?? "0");
const reservation = (s: IsolatedSystem, authId: string) => policyFile(s).reservations[authId];
const anchor = (s: IsolatedSystem) => parseAnchor(sudo(["cat", s.paths.anchorPath]).stdout);
const journalId = (s: IsolatedSystem) => JSON.parse(sudo(["cat", join(s.paths.journalDir, "JOURNAL.json")]).stdout).journal_id as string;

/** Authorization requested straight from the auth service by the gateway identity. */
async function authorizeAsGateway(s: IsolatedSystem): Promise<{ decision: string; authorization?: any; intent_ref?: any; reasons?: string[] }> {
  const r = (await s.runAs("gateway", PROBE, ["post", s.paths.authSocket, "/v1/authorize", JSON.stringify(request()), "{}"])).result as any;
  return r?.value?.body ?? { decision: "ERROR", reasons: [String(r?.code)] };
}
/** Purchase by the agent with an authorization it already holds. */
async function submit(s: IsolatedSystem, a: { authorization: any; intent_ref: any }, timeoutMs = 30_000) {
  return (await s.runAgent(PROBE, ["submit", s.paths.publicSocket, JSON.stringify({ request: request(), intent_ref: a.intent_ref, authorization: a.authorization })], timeoutMs)).result as any;
}
async function waitFor<T>(what: string, fn: () => T | undefined | false, timeoutMs = 20_000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await sleep(250);
  }
}
async function settleAs(s: IsolatedSystem, role: "executor" | "gateway" | "agent", mode: string, report: Record<string, unknown>) {
  return (await s.runAs(role, SETTLE, [s.paths.executorConfig, mode, JSON.stringify(report)])).result as any;
}

function assertConsistent(s: IsolatedSystem, label: string, o: { restored?: boolean } = {}): void {
  const f = policyFile(s);
  const rs = Object.values(f.reservations);
  const sum = rs.reduce((t, r) => t + BigInt(r.charged), 0n);
  if (o.restored) assert.ok(spent(f) >= sum, `${label} I1 charge ${spent(f)} >= reservations ${sum}`);
  else assert.equal(spent(f), sum, `${label} I1 charge equals the sum of reservation charges`);
  assert.ok(spent(f) <= BigInt(f.state.budget.budget_limit[AGENT_ID]!.$bigint), `${label} I2 charge within the limit`);
  const ledger = s.privileged.exists(s.paths.ledgerPath) ? parseMockLedger(s.privileged.read(s.paths.ledgerPath).toString("utf8")) : [];
  const paid = new Map<string, number>();
  for (const e of ledger) paid.set(e.intent_hash, (paid.get(e.intent_hash) ?? 0) + 1);
  for (const [h, n] of paid) assert.equal(n, 1, `${label} I5 intent ${h} paid ${n} times`);
  const j = s.journal();
  for (const i of j.list()) {
    if (i.state === "SETTLED") assert.equal(paid.get(i.intent_hash), 1, `${label} I3 SETTLED intent has its ledger entry`);
    const r = f.reservations[i.auth_id];
    const mayHavePaid = i.state === "SETTLED" || ((i.state === "STARTED" || i.state === "UNKNOWN") && i.resolution?.verdict !== "NOT_SETTLED");
    if (r && mayHavePaid) assert.notEqual(r.state, "RELEASED", `${label} I3 a payment that may have executed (${i.state}) was released`);
  }
  const jid = journalId(s);
  for (const r of rs.filter((x) => x.state === "RELEASED" && x.domain?.journal_id === jid)) {
    assert.ok(j.auth(r.auth_id), `${label} I4 released ${r.auth_id} is consumed in its journal`);
    const intent = j.inspect(r.intent_hash);
    assert.ok(!intent || intent.state === "REFUSED_BEFORE_SIGNING" || intent.resolution?.verdict === "NOT_SETTLED", `${label} I4 released ${r.auth_id} has payment record ${intent?.state}`);
  }
}

// ── CX1: policy-state rollback (PREPARE / DONE) ───────────────────────────

test("CX1a regression: the state from one commit earlier (after a completed DONE) is refused at startup and while running", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot("20000") });
  assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
  const oneCommitEarlier = s.privileged.read(statePath(s)).toString("utf8");
  assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
  assert.deepEqual((await authorizeAsGateway(s)).reasons, ["BUDGET_EXCEEDED"]);
  const head = anchor(s).head!;
  assert.equal(head.version, 2, "version 2 completed (DONE)");

  // Replaced while running: DENY, nothing issued.
  sudo(["tee", statePath(s)], oneCommitEarlier);
  assert.match((await authorizeAsGateway(s)).reasons!.join(), /POLICY_STATE_UNAVAILABLE:POLICY_STATE_ROLLBACK/);
  // After a restart: refused (exit 78). The original CX1 reproducer got a third ALLOW here.
  await s.stopAuth();
  const allows = () => s.privileged.read(s.paths.decisionLog).toString("utf8").split("\n").filter((l) => l.includes('"decision":"ALLOW"')).length;
  const allowsBefore = allows();
  await assert.rejects(s.startAuth(), /code 78\).*POLICY_STATE_ROLLBACK:state version 1, anchor head version 2/);
  // 1. Direct request to the auth service: no ALLOW (it refused to start, so its socket does not exist).
  const direct = await authorizeAsGateway(s);
  assert.notEqual(direct.decision, "ALLOW");
  assert.deepEqual(direct.reasons, ["ENOENT"]);
  // 2. Normal agent purchase through the gateway: DENY PDP_UNAVAILABLE.
  const buy = (await s.runAgent(PROBE, ["buy", s.paths.publicSocket, "weather"])).result as any;
  assert.deepEqual([buy.stage, buy.decision, buy.reasons], ["authorize", "DENY", ["PDP_UNAVAILABLE"]]);
  // 3-4. No payment and no authorization issued.
  assert.equal(s.ledger().length, 0);
  assert.equal(allows(), allowsBefore, "no authorization issued after the rollback was refused");
  // The initial state (version 0) is refused too.
  const v0 = anchor(s).completed[0]!;
  assert.equal(v0.version, 0);
  assert.equal(anchor(s).tip!.kind, "DONE", "nothing was appended by the refused starts");
});

for (const fault of ["crashAfterPrepare", "crashAfterRename", "crashAfterDirSync", "failDoneAppend", "crashBeforeIssue"] as const) {
  test(`CX1b commit window ${fault}: no authorization reaches the caller; recovery follows the crash-state table; never over-issued`, opts, async () => {
    const s = await launch({ policyStateRoot: policyRoot("20000", 3), ttlSeconds: 3, authFaults: { [fault]: true } });
    const before = policyFile(s);
    const r = await authorizeAsGateway(s);
    assert.notEqual(r.decision, "ALLOW", `no authorization released: ${JSON.stringify(r)}`);
    if (fault === "failDoneAppend") {
      // No crash: the store refuses everything until restart (commit not confirmed).
      assert.match(r.reasons!.join(), /POLICY_STATE_UNAVAILABLE:injected DONE append failure/);
      assert.match((await authorizeAsGateway(s)).reasons!.join(), /POLICY_STATE_UNCONFIRMED/);
      await s.stopAuth();
    } else {
      await s.authExited();
    }
    const pendingBefore = anchor(s).pending;
    await s.startAuth(); // no faults
    const log = anchor(s);
    const after = policyFile(s);
    assert.equal(log.pending, undefined, "no PREPARE left open");
    if (fault === "crashAfterPrepare") {
      assert.ok(pendingBefore, "PREPARE was open at the crash");
      assert.equal(log.tip!.kind, "ABORT", "1..3: PREPARE aborted");
      assert.equal(after.version, before.version);
      assert.equal(spent(after), 0n);
      assert.equal(Object.keys(after.reservations).length, 0);
    } else {
      if (fault === "crashBeforeIssue") assert.equal(pendingBefore, undefined, "5..6: DONE was already durable");
      else assert.ok(pendingBefore, "3..5: PREPARE open with the new state in place");
      assert.equal(after.version, before.version + 1);
      assert.equal(spent(after), PRICE, "the undelivered reservation stays charged");
      const [res] = Object.values(after.reservations);
      assert.equal(res!.state, "RESERVED");
      // Released only by its own execution domain, after expiry: consumed as CANCELLED first.
      const rel = await waitFor("cancellation by its own domain", () => reservation(s, res!.auth_id)?.state === "RELEASED" && reservation(s, res!.auth_id), 30_000);
      assert.equal(rel.history.at(-1)!.reason, "CANCELLED");
      assert.equal(s.journal().auth(res!.auth_id)?.disposition, "CANCELLED");
    }
    assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
    assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
    assert.deepEqual((await authorizeAsGateway(s)).reasons, ["BUDGET_EXCEEDED"]);
    assertConsistent(s, fault);
  });
}

test("CX1c operator restore: only a completed past state, spending carried forward, open reservations frozen", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot("30000") });
  const a1 = await authorizeAsGateway(s);
  assert.equal(a1.decision, "ALLOW");
  const dir = mkdtempSync(join(tmpdir(), "oxdeai-backup-"));
  scratch.push(dir);
  chmodSync(dir, 0o700);
  const backup = join(dir, "state.json");
  writeFileSync(backup, s.privileged.read(statePath(s)), { mode: 0o600 });
  assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
  assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
  assert.equal(spent(policyFile(s)), 3n * PRICE);

  await assert.rejects(restorePolicyState({ stateRoot: s.paths.policyStateRoot, backupPath: backup }), /POLICY_STATE_LOCKED/, "refused while auth runs");
  await s.stopAuth();
  // A forged "backup" (charge edited down) was never a completed state.
  const forged = join(dir, "forged.json");
  writeFileSync(forged, s.privileged.read(statePath(s)).toString("utf8").replace(/"spent_in_period":\{"agent-celo-poc-1":\{"\$bigint":"30000"\}\}/, '"spent_in_period":{"agent-celo-poc-1":{"$bigint":"0"}}'));
  await assert.rejects(restorePolicyState({ stateRoot: s.paths.policyStateRoot, backupPath: forged }), /POLICY_RESTORE_UNVERIFIED/);

  const result = await restorePolicyState({ stateRoot: s.paths.policyStateRoot, backupPath: backup });
  assert.deepEqual(result.carried_spent, { [AGENT_ID]: (3n * PRICE).toString() }, "the newer charge is carried forward");
  assert.equal(result.frozen, 1, "the backup's open reservation is frozen");
  assert.equal(anchor(s).tip!.kind, "DONE");
  await s.startAuth();
  assert.deepEqual((await authorizeAsGateway(s)).reasons, ["BUDGET_EXCEEDED"], "no capacity came back");
  assert.equal(reservation(s, a1.authorization.auth_id)!.state, "UNCERTAIN");
  assertConsistent(s, "restore", { restored: true });
});

test("CX1d anchor damage fails closed: torn final line recovered; not append-only or missing refused", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot("20000") });
  assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
  await s.stopAuth();
  // Torn final line (crash during an append): terminated by an ABORT naming it.
  sudo(["sh", "-c", `printf '{"seq":9,"kind":"PREP' >> '${s.paths.anchorPath}'`]);
  await s.startAuth();
  assert.ok(anchor(s).tip!.torn_sha256, "torn tail acknowledged");
  assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
  await s.stopAuth();
  // Not append-only.
  sudo(["chattr", "-a", s.paths.anchorPath]);
  await assert.rejects(s.startAuth(), /code 78\).*POLICY_ANCHOR_NOT_APPEND_ONLY/);
  // Missing.
  sudo(["mv", s.paths.anchorPath, `${s.paths.anchorPath}.moved`]);
  await assert.rejects(s.startAuth(), /code 78\).*POLICY_ANCHOR_MISSING/);
  sudo(["mv", `${s.paths.anchorPath}.moved`, s.paths.anchorPath]);
  sudo(["chattr", "+a", s.paths.anchorPath]);
  await s.startAuth();
  assert.deepEqual((await authorizeAsGateway(s)).reasons, ["BUDGET_EXCEEDED"]);
});

// ── CX2: execution-domain binding ────────────────────────────────────────

test("CX2a regression: a new deployment on another journal never releases a reservation an older executor is still paying", opts, async () => {
  const P = policyRoot("10000", 3);
  const E1 = executorRoot();
  // Worst case: the old executor sends no EXECUTING report before its auth dies.
  const d1 = await launch({ policyStateRoot: P, executorStateRoot: E1, ttlSeconds: 3, executorFaults: { delayPayMs: 9000 }, gatewayTimeoutMs: 20_000, reconcileIntervalMs: 600_000 });
  const a = (await d1.runAgent(PROBE, ["authorize-only", d1.paths.publicSocket])).result as any;
  const id = a.authorization.auth_id;
  const purchase = submit(d1, a, 60_000);
  await sleep(800);
  await d1.crashAuth();

  const d2 = await launch({ policyStateRoot: P, executorStateRoot: executorRoot(), ttlSeconds: 3 });
  await sleep(4_500); // past expiry + grace, while the old executor is still paying
  assert.equal(reservation(d2, id)!.state, "RESERVED", "not released by another domain");
  assert.equal(spent(policyFile(d2)), 10000n);
  assert.deepEqual((await authorizeAsGateway(d2)).reasons, ["BUDGET_EXCEEDED"], "no budget reuse");
  const done = await purchase;
  assert.equal(done.decision, "ALLOW", "the old executor completed its delayed payment");
  assert.equal(d1.ledger().length, 1);
  assert.equal(reservation(d2, id)!.state, "RESERVED", "still held after the old payment completed");
  assertConsistent(d2, "d2");
  await stop(d2);
  await stop(d1);

  // Verified reconciliation: a deployment on the reservation's OWN journal reports the payment.
  const d3 = await launch({ policyStateRoot: P, executorStateRoot: E1, ttlSeconds: 3 });
  const confirmed = await waitFor("CONFIRMED by its own domain", () => reservation(d3, id)?.state === "CONFIRMED" && reservation(d3, id));
  assert.equal(confirmed.charged, "10000");
  assertConsistent(d3, "d3");
});

test("CX2b across three journals: an earlier deployment's authorization cannot execute elsewhere and is reconciled only by its own journal", opts, async () => {
  const P = policyRoot("30000", 3);
  const E1 = executorRoot();
  const E2 = executorRoot();
  const d1 = await launch({ policyStateRoot: P, executorStateRoot: E1, ttlSeconds: 3 });
  const x = (await d1.runAgent(PROBE, ["authorize-only", d1.paths.publicSocket])).result as any;
  await stop(d1);
  const d2 = await launch({ policyStateRoot: P, executorStateRoot: E2, ttlSeconds: 3 });
  const y = (await d2.runAgent(PROBE, ["authorize-only", d2.paths.publicSocket])).result as any;
  const rx = await submit(d2, x);
  assert.equal(rx.decision, "DENY", JSON.stringify(rx));
  assert.match(rx.reason, /AUTH_/);
  await stop(d2);

  // A third journal releases neither X (E1) nor Y (E2).
  const d3 = await launch({ policyStateRoot: P, executorStateRoot: executorRoot(), ttlSeconds: 3 });
  for (const a of [x, y]) assert.equal((await submit(d3, a)).decision, "DENY");
  await sleep(4_500);
  for (const a of [x, y]) assert.equal(reservation(d3, a.authorization.auth_id)!.state, "RESERVED");
  assert.equal(d3.ledger().length, 0);
  await stop(d3);

  // Each journal's own deployment cancels (consumes) its own authorization, and only that.
  const back1 = await launch({ policyStateRoot: P, executorStateRoot: E1, ttlSeconds: 3 });
  await waitFor("X released by E1", () => reservation(back1, x.authorization.auth_id)?.state === "RELEASED");
  assert.equal(reservation(back1, y.authorization.auth_id)!.state, "RESERVED", "Y untouched by E1");
  assert.equal(back1.journal().auth(x.authorization.auth_id)?.disposition, "CANCELLED");
  assertConsistent(back1, "E1");
  await stop(back1);
  const back2 = await launch({ policyStateRoot: P, executorStateRoot: E2, ttlSeconds: 3 });
  await waitFor("Y released by E2", () => reservation(back2, y.authorization.auth_id)?.state === "RELEASED");
  assertConsistent(back2, "E2");
});

test("CX2c an executor refuses to start when its journal or audience does not match its execution domain", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot("20000"), executorStateRoot: executorRoot() });
  const other = executorRoot();
  await s.stopExecutor();
  const cfg = JSON.parse(s.privileged.read(s.paths.executorConfig).toString("utf8"));
  const run = (c: unknown) => {
    const staging = mkdtempSync(join(tmpdir(), "oxdeai-cfg-"));
    chmodSync(staging, 0o700);
    const p = join(staging, "c.json");
    writeFileSync(p, JSON.stringify(c), { mode: 0o600 });
    const dest = join(s.paths.executorDir, "alt-config.json");
    sudo(["install", "-o", "oxdeai-executor", "-g", "oxdeai-executor", "-m", "0600", p, dest]);
    rmSync(staging, { recursive: true, force: true });
    return s.runAsSync("executor", [NODE, join(s.paths.apps.executor, "src/isolation/executor-main.ts"), dest], 15_000);
  };
  const otherJournal = run({ ...cfg, journalDir: join(other, "journal") });
  assert.equal(otherJournal.status, 78, otherJournal.stderr);
  assert.match(otherJournal.stderr, /EXECUTION_DOMAIN_MISMATCH:journal/);
  const otherAudience = run({ ...cfg, verification: { ...cfg.verification, expectedAudience: "oxdeai-celo-poc.gateway" } });
  assert.equal(otherAudience.status, 78, otherAudience.stderr);
  assert.match(otherAudience.stderr, /EXECUTION_DOMAIN_MISMATCH:audience/);
  const otherDomain = run({ ...cfg, domain: { ...cfg.domain, journal_id: "0".repeat(32) } });
  assert.equal(otherDomain.status, 78, otherDomain.stderr);
  await s.startExecutor();
  assert.equal(((await s.runAgent(PROBE, ["buy", s.paths.publicSocket, "weather"])).result as any).result.decision, "ALLOW");
});

test("CX2d forged, foreign-domain, unknown, out-of-binding, and unproven reports never move budget", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot("30000"), executorStateRoot: executorRoot() });
  const a = await authorizeAsGateway(s);
  const id = a.authorization.auth_id;
  const base = { type: "oxdeai-celo-poc/outcome-report/v1", auth_id: id, intent_hash: a.authorization.intent_hash, journal_id: journalId(s) };
  const cancel = { ...base, outcome: "NOT_EXECUTED", reason: "CANCELLED" };
  const before = spent(policyFile(s));
  const body = async (mode: string, report: Record<string, unknown>) => (await settleAs(s, "executor", mode, report))?.body;

  assert.match((await body("valid", { ...cancel, journal_id: "f".repeat(32) })).reason, /DOMAIN_NOT_CURRENT/);
  assert.match((await body("valid", { ...cancel, auth_id: "synthetic-unknown-auth" })).reason, /UNKNOWN_RESERVATION/);
  assert.match((await body("valid", { ...cancel, intent_hash: "e".repeat(64) })).reason, /INTENT_HASH_MISMATCH/);
  assert.match((await body("valid", { ...base, outcome: "SETTLED", amount: "99999999" })).reason, /AMOUNT_EXCEEDS_RESERVATION/);
  assert.match((await body("wrong-key", cancel)).reason, /REPORT_INVALID:signature/);
  assert.match((await body("no-proof", cancel)).reason, /PEER_PROOF_INVALID:missing/);
  assert.match((await body("bad-proof", cancel)).reason, /PEER_PROOF_INVALID:content/);
  for (const role of ["gateway", "agent"] as const) {
    assert.equal((await settleAs(s, role, "valid", cancel)).error, "EACCES", `${role} cannot read the executor config or reach the settle socket`);
    const c = (await s.runAs(role, PROBE, ["connect", s.paths.settleSocket])).result as Record<string, { code?: string }>;
    assert.equal(c[s.paths.settleSocket]!.code, "EACCES", `${role} cannot connect to the settle socket`);
  }
  assert.equal(spent(policyFile(s)), before, "none of these changed the budget");
  assert.equal(reservation(s, id)!.state, "RESERVED");
  assertConsistent(s, "CX2d");
});

// ── Mandate §6: remaining process-level adversarial cases (FI-nn = case number) ──

const bought = (r: any) => r?.result?.decision ?? r?.decision;
const buyAsAgent = async (s: IsolatedSystem) => bought((await s.runAgent(PROBE, ["buy", s.paths.publicSocket, "weather"])).result);
const authorizeAsAgent = async (s: IsolatedSystem) => (await s.runAgent(PROBE, ["authorize-only", s.paths.publicSocket])).result as any;
const intentOf = (s: IsolatedSystem, authId: string) => s.journal().auth(authId)?.intent_hash;
const resolveAs = (s: IsolatedSystem, intentHash: string, verdict: "SETTLED" | "NOT_SETTLED") =>
  s.runAsSync("executor", [NODE, join(s.paths.apps.executor, "src/isolation/journal-cli.ts"), s.paths.journalDir, "resolve", intentHash, verdict, "synthetic out-of-band reconciliation"]);
const sha = (paths: string[]) => sudo(["sha256sum", ...paths]).stdout;
const filesUnder = (...dirs: string[]) => sudo(["find", ...dirs, "-type", "f"]).stdout.split("\n").filter(Boolean).sort();

for (const [fault, reason] of [
  [{ quoteDrift: true }, "REJECTED_BEFORE_EXECUTION"],
  [{ refuseBeforeSigning: true }, "REFUSED_BEFORE_SIGNING"],
] as const) {
  test(`FI-02 payment rejected before execution (${Object.keys(fault)[0]}): no payment; released by its own domain; the authorization can never pay`, opts, async () => {
    const s = await launch({ policyStateRoot: policyRoot(String(PRICE)), executorStateRoot: executorRoot() });
    const a = await authorizeAsAgent(s);
    const id = a.authorization.auth_id;
    await s.stopExecutor();
    await s.startExecutor(fault);
    const r = await submit(s, a);
    assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
    assert.equal(s.ledger().length, 0);
    const rel = await waitFor("released", () => reservation(s, id)?.state === "RELEASED" && reservation(s, id));
    assert.equal(rel.history.at(-1)!.reason, reason);
    assert.equal(spent(policyFile(s)), 0n);
    assertConsistent(s, `FI-02 ${reason}`);
    // The released authorization stays consumed, even with the fault removed.
    await s.stopExecutor();
    await s.startExecutor();
    const again = await submit(s, a);
    assert.notEqual(again.decision, "ALLOW", JSON.stringify(again));
    assert.match(JSON.stringify(again), /REPLAY/);
    assert.equal(s.ledger().length, 0);
    // The released capacity is usable exactly once by a new authorization.
    assert.equal(await buyAsAgent(s), "ALLOW");
    assert.equal(await buyAsAgent(s), "DENY");
    assert.equal(s.ledger().length, 1);
    await waitFor("CONFIRMED", () => Object.values(policyFile(s).reservations).some((x) => x.state === "CONFIRMED"));
    assertConsistent(s, `FI-02 ${reason} after reuse`);
  });
}

test("FI-03 crash after the reservation is consumed, before the intent record (crashAfterAuthRecord): no payment; released as NOT_STARTED after restart; never payable", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(PRICE)), executorStateRoot: executorRoot() });
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  await s.stopExecutor();
  await s.startExecutor({ crashAfterAuthRecord: true });
  const r = await submit(s, a);
  assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
  await s.executorExited();
  assert.equal(s.ledger().length, 0);
  assert.equal(spent(policyFile(s)), PRICE, "still charged while the executor is down");
  assert.notEqual(reservation(s, id)!.state, "RELEASED");
  await s.startExecutor();
  const rel = await waitFor("released", () => reservation(s, id)?.state === "RELEASED" && reservation(s, id));
  assert.equal(rel.history.at(-1)!.reason, "NOT_STARTED");
  const j = s.journal();
  assert.equal(j.auth(id)!.disposition, "RESERVED");
  assert.equal(j.inspect(a.authorization.intent_hash), undefined, "pay was never reached");
  const again = await submit(s, a);
  assert.notEqual(again.decision, "ALLOW", JSON.stringify(again));
  assert.equal(s.ledger().length, 0);
  assertConsistent(s, "FI-03");
});

for (const [fault, paid, verdict, final] of [
  ["crashBeforePay", 0, "NOT_SETTLED", "RELEASED"],
  ["crashAfterPay", 1, "SETTLED", "CONFIRMED"],
] as const) {
  test(`FI-04/08 crash after the payment started (${fault}): UNCERTAIN and fully charged across executor, auth, and deployment restarts; no retry; only an operator resolution moves it`, opts, async () => {
    const P = policyRoot(String(2n * PRICE));
    const E = executorRoot();
    const s = await launch({ policyStateRoot: P, executorStateRoot: E });
    const a = await authorizeAsAgent(s);
    const id = a.authorization.auth_id;
    await s.stopExecutor();
    await s.startExecutor({ [fault]: true });
    const r = await submit(s, a);
    assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
    await s.executorExited();
    assert.equal(s.ledger().length, paid);
    await s.startExecutor();
    const u = await waitFor("UNCERTAIN", () => reservation(s, id)?.state === "UNCERTAIN" && reservation(s, id));
    assert.equal(u.charged, String(PRICE));
    await s.restartAuth();
    await stop(s);
    const d2 = await launch({ policyStateRoot: P, executorStateRoot: E });
    await sleep(1_500); // several reporter passes
    assert.equal(reservation(d2, id)!.state, "UNCERTAIN", "never released automatically");
    assert.equal(spent(policyFile(d2)), PRICE);
    assert.equal(d2.ledger().length, paid, "no automatic retry");
    assert.notEqual((await submit(d2, a)).decision, "ALLOW", "the uncertain authorization cannot be resubmitted");
    assert.equal(d2.ledger().length, paid);
    // Only the remaining capacity is available.
    assert.equal((await authorizeAsGateway(d2)).decision, "ALLOW");
    assert.deepEqual((await authorizeAsGateway(d2)).reasons, ["BUDGET_EXCEEDED"]);
    assertConsistent(d2, `FI-04 ${fault}`);
    // Operator reconciliation (executor stopped: resolve takes the journal lock).
    await d2.stopExecutor();
    const res = resolveAs(d2, a.authorization.intent_hash, verdict);
    assert.equal(res.status, 0, res.stderr);
    await d2.startExecutor();
    await waitFor(final, () => reservation(d2, id)?.state === final);
    assert.equal(d2.ledger().length, paid);
    assertConsistent(d2, `FI-04 ${fault} resolved`);
  });
}

test("FI-05a duplicate result delivery: executor killed after the auth service applied SETTLED, before its ack; the redelivery is ALREADY_APPLIED and nothing moves twice", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE)), executorStateRoot: executorRoot(), reconcileIntervalMs: 600_000 });
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  await s.stopExecutor();
  await s.startExecutor({ crashBeforeAck: true });
  await submit(s, a);
  await s.executorExited();
  assert.equal(s.ledger().length, 1);
  assert.equal(reservation(s, id)!.state, "CONFIRMED", "applied before the crash");
  const acks = () => sudo(["ls", join(s.paths.journalDir, "acks")]).stdout.split("\n").filter(Boolean);
  assert.deepEqual(acks(), [], "the ack was never journaled");
  await s.startExecutor(); // startup pass redelivers
  await waitFor("ack recorded", () => acks().length === 1);
  const r = reservation(s, id)!;
  assert.equal(r.state, "CONFIRMED");
  assert.equal(r.history.filter((h) => h.state === "CONFIRMED").length, 1, "applied once");
  assert.equal(spent(policyFile(s)), PRICE);
  assert.equal(s.ledger().length, 1);
  assertConsistent(s, "FI-05a");
});

test("FI-05b duplicate result delivery: auth service killed after committing a report, before answering; redelivery and forged repeats change nothing", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(PRICE)), executorStateRoot: executorRoot() });
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  await s.restartAuth({ crashAfterSettleCommit: true });
  const r = await submit(s, a);
  assert.equal(r.decision, "ALLOW", JSON.stringify(r));
  await s.authExited();
  assert.equal(s.ledger().length, 1);
  await s.startAuth();
  const c = await waitFor("CONFIRMED", () => reservation(s, id)?.state === "CONFIRMED" && reservation(s, id));
  assert.equal(c.history.filter((h) => h.state === "CONFIRMED").length, 1);
  // The same SETTLED report again, and a contradictory NOT_EXECUTED, from the executor identity.
  const base = { type: "oxdeai-celo-poc/outcome-report/v1", auth_id: id, intent_hash: a.authorization.intent_hash, journal_id: journalId(s) };
  assert.equal((await settleAs(s, "executor", "valid", { ...base, outcome: "SETTLED", amount: String(PRICE) }))?.body?.status, "ALREADY_APPLIED");
  const conflict = (await settleAs(s, "executor", "valid", { ...base, outcome: "NOT_EXECUTED", reason: "CANCELLED" }))?.body;
  assert.notEqual(conflict?.status, "APPLIED", JSON.stringify(conflict));
  assert.equal(reservation(s, id)!.state, "CONFIRMED");
  assert.equal(spent(policyFile(s)), PRICE, "nothing released twice or by a contradiction");
  assert.deepEqual((await authorizeAsGateway(s)).reasons, ["BUDGET_EXCEEDED"]);
  assertConsistent(s, "FI-05b");
});

test("FI-07a restart with a pending reservation, same deployment: auth, executor, and gateway restart; the reservation stays charged and pays exactly once", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE)), executorStateRoot: executorRoot() });
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  await s.restartAuth();
  await s.stopExecutor();
  await s.startExecutor();
  await s.restartGateway();
  assert.equal(reservation(s, id)!.state, "RESERVED");
  assert.equal(spent(policyFile(s)), PRICE);
  assert.equal((await submit(s, a)).decision, "ALLOW");
  assert.notEqual((await submit(s, a)).decision, "ALLOW", "replay after the restart");
  assert.equal(s.ledger().length, 1);
  await waitFor("CONFIRMED", () => reservation(s, id)?.state === "CONFIRMED");
  assert.equal(await buyAsAgent(s), "ALLOW");
  assert.equal(await buyAsAgent(s), "DENY");
  assert.equal(s.ledger().length, 2);
  assertConsistent(s, "FI-07a");
});

test("FI-07b restart with a pending reservation, new deployment (new PDP key): the old authorization is refused, stays charged until its own domain cancels it, never pays", opts, async () => {
  // TTL 15 s: the authorization must still be temporally valid when the new deployment verifies it
  // (a redeployment takes ~2-3 s), so that only the key can refuse it; it expires later for the cancellation.
  const P = policyRoot(String(PRICE), 15);
  const E = executorRoot();
  const d1 = await launch({ policyStateRoot: P, executorStateRoot: E, ttlSeconds: 15 });
  const a = await authorizeAsAgent(d1);
  const id = a.authorization.auth_id;
  await stop(d1);
  const d2 = await launch({ policyStateRoot: P, executorStateRoot: E, ttlSeconds: 15 });
  assert.equal(reservation(d2, id)!.state, "RESERVED");
  assert.equal(spent(policyFile(d2)), PRICE);
  const r = await submit(d2, a);
  assert.equal(r.decision, "DENY", JSON.stringify(r));
  assert.equal(r.reason, "AUTH_KID_UNKNOWN", "a deployment's authorizations verify only under its own PDP key (T9e)");
  assert.deepEqual((await authorizeAsGateway(d2)).reasons, ["BUDGET_EXCEEDED"], "still charged");
  const rel = await waitFor("cancelled by its own domain", () => reservation(d2, id)?.state === "RELEASED" && reservation(d2, id), 30_000);
  assert.equal(rel.history.at(-1)!.reason, "CANCELLED");
  assert.equal(d2.journal().auth(id)!.disposition, "CANCELLED");
  assert.equal(d2.ledger().length, 0);
  assert.equal(await buyAsAgent(d2), "ALLOW");
  assert.equal(d2.ledger().length, 1);
  assertConsistent(d2, "FI-07b");
});

test("FI-09 journal corruption and truncation: damaged structure refuses to start; damaged records are never released, never re-paid", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(3n * PRICE), 3), executorStateRoot: executorRoot(), ttlSeconds: 3 });
  const p1 = await authorizeAsAgent(s);
  assert.equal((await submit(s, p1)).decision, "ALLOW");
  await waitFor("CONFIRMED", () => reservation(s, p1.authorization.auth_id)?.state === "CONFIRMED");
  // Two payments left STARTED by a crash before pay.
  const p2 = await authorizeAsAgent(s);
  const p3 = await authorizeAsAgent(s);
  for (const p of [p2, p3]) {
    await s.stopExecutor();
    await s.startExecutor({ crashBeforePay: true });
    await submit(s, p);
    await s.executorExited();
  }
  const J = s.paths.journalDir;
  const authFile = (id: string) => join(J, "auths", sha256(id));
  // Damage: p1 intent record garbled, p2 auth record truncated to zero, p3 intent record truncated mid-JSON.
  sudo(["sh", "-c", `printf 'garbage' > '${join(J, "intents", p1.authorization.intent_hash)}'`]);
  sudo(["truncate", "-s", "0", authFile(p2.authorization.auth_id)]);
  sudo(["truncate", "-s", "20", join(J, "intents", p3.authorization.intent_hash)]);
  await s.startExecutor();
  await sleep(6_000); // past expiry + grace: several cancel and delivery passes
  const j = s.journal();
  assert.equal(j.inspect(p1.authorization.intent_hash)!.state, "UNKNOWN", "an unreadable record is UNKNOWN, never absent");
  assert.equal(j.inspect(p3.authorization.intent_hash)!.state, "UNKNOWN");
  assert.equal(reservation(s, p1.authorization.auth_id)!.state, "CONFIRMED", "never moved backwards");
  for (const p of [p2, p3]) {
    assert.notEqual(reservation(s, p.authorization.auth_id)!.state, "RELEASED", "a payment that may have started is never released");
    assert.equal(reservation(s, p.authorization.auth_id)!.charged, String(PRICE));
  }
  for (const p of [p1, p2, p3]) assert.notEqual((await submit(s, p)).decision, "ALLOW", "a damaged record never makes an authorization payable again");
  assert.equal(s.ledger().length, 1);
  assert.equal(spent(policyFile(s)), 3n * PRICE);
  assert.deepEqual((await authorizeAsGateway(s)).reasons, ["BUDGET_EXCEEDED"]);
  assertConsistent(s, "FI-09 records");

  // Structural damage: the executor refuses to start (exit 78); nothing is recreated.
  await s.stopExecutor();
  const marker = join(J, "JOURNAL.json");
  const original = sudo(["cat", marker]).stdout;
  sudo(["sh", "-c", `printf '{"format":"oxdeai' > '${marker}'`]);
  await assert.rejects(s.startExecutor(), /code 78\).*JOURNAL_CORRUPT/);
  sudo(["tee", marker], original);
  sudo(["mv", join(J, "auths"), join(J, "auths.moved")]);
  await assert.rejects(s.startExecutor(), /code 78\).*JOURNAL_CORRUPT:missing/);
  assert.notEqual(sudo(["test", "-e", join(J, "auths")]).status, 0, "not recreated");
  sudo(["mv", join(J, "auths.moved"), join(J, "auths")]);
  await s.startExecutor();
  assert.notEqual((await submit(s, p2)).decision, "ALLOW");
  assert.equal(s.ledger().length, 1);
  assertConsistent(s, "FI-09 structure");
});

test("FI-10 missing journal: the executor refuses to start (exit 78), never recreates it, and no purchase pays", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE)), executorStateRoot: executorRoot() });
  const a = await authorizeAsAgent(s);
  assert.equal((await submit(s, a)).decision, "ALLOW");
  await s.stopExecutor();
  const J = s.paths.journalDir;
  sudo(["mv", J, `${J}.moved`]);
  await assert.rejects(s.startExecutor(), /code 78\).*JOURNAL_MISSING/);
  assert.notEqual(sudo(["test", "-e", J]).status, 0, "not recreated");
  assert.notEqual(await buyAsAgent(s), "ALLOW");
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  assert.equal(s.ledger().length, 1);
  sudo(["mv", `${J}.moved`, J]);
  await s.startExecutor();
  assert.notEqual((await submit(s, a)).decision, "ALLOW", "the restored journal still holds the consumed authorization");
  assert.equal(s.ledger().length, 1);
  assertConsistent(s, "FI-10");
});

test("FI-12/13 simultaneous executor startup: exactly one journal writer; the loser exits 75 before serving; a SIGKILLed holder's lock is released", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE)), executorStateRoot: executorRoot() });
  // A second executor while the first runs.
  const main = join(s.paths.apps.executor, "src/isolation/executor-main.ts");
  const second = s.runAsSync("executor", [NODE, main, s.paths.executorConfig], 15_000);
  assert.equal(second.status, 75, second.stderr);
  assert.match(second.stderr, /JOURNAL_LOCKED/);
  assert.doesNotMatch(second.stdout, /"event":"ready"/);
  // Two executors started at the same moment.
  await s.stopExecutor();
  const both = await Promise.all([0, 1].map(() => s.runAs("executor", main, [s.paths.executorConfig], { timeoutMs: 6_000 })));
  const ready = both.filter((r) => /"event":"ready"/.test(r.stdout));
  const locked = both.filter((r) => r.code === 75 && /JOURNAL_LOCKED/.test(r.stderr));
  assert.equal(ready.length, 1, JSON.stringify(both.map((r) => [r.code, r.stderr.slice(-200)])));
  assert.equal(locked.length, 1);
  assert.doesNotMatch(locked[0]!.stdout, /"event":"ready"/);
  // Holder killed while holding the lock: the next start acquires it.
  await s.startExecutor();
  assert.equal(await buyAsAgent(s), "ALLOW");
  await s.crashExecutor();
  await s.executorExited();
  await s.startExecutor();
  assert.equal(await buyAsAgent(s), "ALLOW");
  assert.equal(await buyAsAgent(s), "DENY");
  assert.equal(s.ledger().length, 2);
  await waitFor("both CONFIRMED", () => Object.values(policyFile(s).reservations).filter((x) => x.state === "CONFIRMED").length === 2);
  assertConsistent(s, "FI-12/13");
});

test("FI-15 the agent and gateway identities cannot create, modify, or delete any financial state (policy state, anchor, journal, ledger, locks)", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE)), executorStateRoot: executorRoot() });
  assert.equal(await buyAsAgent(s), "ALLOW");
  const anchorDir = s.paths.anchorPath.slice(0, s.paths.anchorPath.lastIndexOf("/"));
  const files = filesUnder(s.paths.authStateDir, anchorDir, s.paths.executorStateRoot);
  for (const must of [statePath(s), s.paths.anchorPath, s.paths.writerLock, s.paths.ledgerPath, join(s.paths.journalDir, "JOURNAL.json")]) {
    assert.ok(files.includes(must), `${must} is under test`);
  }
  const created = [
    join(s.paths.authStateDir, "state.json.agent"),
    `${s.paths.anchorPath}.agent`,
    join(s.paths.journalDir, "auths", "a".repeat(64)),
    join(s.paths.journalDir, "intents", "b".repeat(64)),
    join(s.paths.journalDir, "acks", `${"c".repeat(64)}.SETTLED`),
  ];
  const before = sha(files);
  for (const role of ["agent", "gateway"] as const) {
    const writes = (await s.runAs(role, PROBE, ["write", ...files, ...created])).result as Record<string, { ok: boolean; code?: string }>;
    const unlinks = (await s.runAs(role, PROBE, ["unlink", ...files])).result as Record<string, { ok: boolean; code?: string }>;
    for (const p of [...files, ...created]) assert.equal(writes[p]!.ok, false, `${role} wrote ${p}`);
    for (const p of files) assert.equal(unlinks[p]!.ok, false, `${role} deleted ${p}`);
  }
  assert.equal(sha(files), before, "every financial-state file is byte-identical");
  for (const p of created) assert.notEqual(sudo(["test", "-e", p]).status, 0, `${p} was not created`);
  assert.equal(await buyAsAgent(s), "ALLOW");
  assert.equal(await buyAsAgent(s), "DENY");
  assert.equal(s.ledger().length, 2);
  await waitFor("both CONFIRMED", () => Object.values(policyFile(s).reservations).filter((x) => x.state === "CONFIRMED").length === 2);
  assertConsistent(s, "FI-15");
});

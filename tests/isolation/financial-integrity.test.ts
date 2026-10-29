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
 *   I4  (Phase 2D) a RELEASED reservation never financed a payment: no ledger
 *       entry for its intent, and it was released while unclaimed (VOID or
 *       expiry) or by a positive record of its own claim (refused before
 *       signing, claim abandoned) that this journal holds
 *   I5  no intent paid twice
 *   I6  (Phase 2D) every payment was made under the claim its reservation
 *       committed, and that reservation is not RELEASED
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
import { parseAnchor, sealEntry, sha256 } from "../../src/authorization/policy-anchor.ts";
import { identitiesUnavailableReason } from "../../src/isolation/identity.ts";
import type { IsolatedSystem } from "../../src/isolation/launcher.ts";
import { restorePolicyState } from "../../src/isolation/policy-state-admin.ts";
import { AGENT_ID, SERVICES } from "../../src/system.ts";
import { freshExecutorState, freshPolicyState, REPO_ROOT, removeStateRoot, removeTestDir, trustedArtifact, type TestLaunchOptions } from "./trusted-artifact.ts";

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
  for (const d of scratch.splice(0)) removeTestDir(d);
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
  const s = await trusted.launch({ reconcileIntervalMs: 300, expiryReleaseIntervalMs: 300, ...o });
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
  claim?: { claim_id: string };
  history: { state: string; outcome?: string; reason?: string; claim_id?: string }[];
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
    const mayHavePaid = i.state === "SETTLED" || i.state === "STARTED" || i.state === "UNKNOWN";
    if (r && mayHavePaid && r.claim?.claim_id === i.claim_id) assert.notEqual(r.state, "RELEASED", `${label} I3 a payment that may have executed (${i.state}) was released`);
  }
  const jid = journalId(s);
  for (const r of rs.filter((x) => x.state === "RELEASED")) {
    assert.equal(paid.get(r.intent_hash) ?? 0, 0, `${label} I4 released ${r.auth_id} financed a payment`);
    const last = r.history.at(-1)!;
    const unclaimedRelease = r.claim === undefined && (last.outcome === "VOID" || last.outcome === "EXPIRED");
    const claimRelease = r.claim !== undefined && last.claim_id === r.claim.claim_id && (last.outcome === "VOID" || last.outcome === "NOT_EXECUTED");
    assert.ok(unclaimedRelease || claimRelease, `${label} I4 released ${r.auth_id} by ${JSON.stringify(last)}`);
    if (r.claim && last.outcome === "NOT_EXECUTED" && r.domain?.journal_id === jid) {
      const intent = j.inspect(r.intent_hash);
      assert.ok(intent && intent.claim_id === r.claim.claim_id && (intent.state === "REFUSED_BEFORE_SIGNING" || intent.state === "CLAIM_ABANDONED"), `${label} I4 released claim ${r.auth_id} has record ${intent?.state}`);
    }
  }
  for (const e of ledger) {
    const r = rs.find((x) => x.intent_hash === e.intent_hash);
    if (!r && o.restored) continue;
    assert.ok(r && r.claim && r.claim.claim_id === e.claim_id, `${label} I6 payment ${e.intent_hash} was not made under its reservation's claim`);
    assert.notEqual(r!.state, "RELEASED", `${label} I6 paid reservation released`);
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
      // Phase 2D: never claimed (the authorization never reached anyone), so the auth service releases
      // it itself once it has expired on its own clock; no claim can be granted for it from then on.
      const rel = await waitFor("released at expiry, unclaimed", () => reservation(s, res!.auth_id)?.state === "RELEASED" && reservation(s, res!.auth_id), 30_000);
      assert.equal(rel.history.at(-1)!.reason, "EXPIRED_UNCLAIMED");
      assert.equal(rel.claim, undefined);
      assert.equal(s.journal().auth(res!.auth_id), undefined, "nothing was ever consumed or paid for it");
      assert.equal(s.ledger().length, 0);
    }
    assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
    assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
    assert.deepEqual((await authorizeAsGateway(s)).reasons, ["BUDGET_EXCEEDED"]);
    assertConsistent(s, fault);
  });
}

const policyCli = (s: IsolatedSystem, ...args: string[]) => spawnSync(NODE, [join(REPO_ROOT, "src/isolation/policy-cli.ts"), ...args, s.paths.policyStateRoot], { encoding: "utf8", timeout: 60_000 });
const policyCliJson = (s: IsolatedSystem, cmd: string) => {
  const r = policyCli(s, cmd);
  return { status: r.status, out: JSON.parse(r.stdout || "null"), stderr: r.stderr };
};

test("CX1c-rebuild (Phase 2D, D2) supported recovery: a rolled-back or lost state file is rebuilt exactly from the anchor; backup restore is refused; no capacity comes back, nothing is frozen", opts, async () => {
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
  const headBytes = s.privileged.read(statePath(s)).toString("utf8");
  assert.equal(spent(policyFile(s)), 3n * PRICE);

  await assert.rejects(restorePolicyState({ stateRoot: s.paths.policyStateRoot, backupPath: backup }), /POLICY_STATE_LOCKED/, "refused while auth runs");
  assert.notEqual(policyCli(s, "rebuild").status, 0, "rebuild refused while auth runs (writer lock)");
  await s.stopAuth();
  // The anchor can rebuild the head exactly, so a backup restore is refused outright.
  await assert.rejects(restorePolicyState({ stateRoot: s.paths.policyStateRoot, backupPath: backup }), /POLICY_RESTORE_SUPERSEDED/);
  // Rollback: an older genuine state put back in place.
  sudo(["tee", statePath(s)], s.privileged.read(backup).toString("utf8"));
  await assert.rejects(s.startAuth(), /code 78\).*POLICY_STATE_ROLLBACK/);
  assert.equal(policyCliJson(s, "verify").out.outcome, "ROLLBACK_DETECTED");
  const rb = policyCliJson(s, "rebuild");
  assert.equal(rb.status, 0, rb.stderr);
  assert.deepEqual([rb.out.outcome, rb.out.rebuilt, rb.out.version], ["SAFE_TO_RESUME", true, 3]);
  assert.equal(s.privileged.read(statePath(s)).toString("utf8"), headBytes, "bit-exact head");
  assert.equal(policyCliJson(s, "rebuild").out.rebuilt, false, "idempotent: already the head");
  // Loss: the state file removed.
  sudo(["rm", "-f", statePath(s)]);
  assert.equal(policyCliJson(s, "rebuild").out.outcome, "SAFE_TO_RESUME");
  assert.equal(s.privileged.read(statePath(s)).toString("utf8"), headBytes);
  assert.equal(policyCliJson(s, "verify").out.outcome, "SAFE_TO_RESUME");
  await s.startAuth();
  assert.deepEqual((await authorizeAsGateway(s)).reasons, ["BUDGET_EXCEEDED"], "no capacity came back");
  assert.equal(reservation(s, a1.authorization.auth_id)!.state, "RESERVED", "exact: not frozen");
  assertConsistent(s, "rebuild"); // exact I1 (equality), not the relaxed restore form
});

test("CX1c-legacy (Phase 2D, L-2/L-3) legacy restore, only for an anchor that cannot be rebuilt: a completed past state only, spending carried forward, open reservations frozen and never claimable, issuance quarantined", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot("30000") });
  const a1 = await authorizeAsAgent(s);
  assert.equal(a1.decision ?? "ALLOW", "ALLOW");
  const dir = mkdtempSync(join(tmpdir(), "oxdeai-backup-"));
  scratch.push(dir);
  chmodSync(dir, 0o700);
  const backup = join(dir, "state.json");
  writeFileSync(backup, s.privileged.read(statePath(s)), { mode: 0o600 });
  assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
  assert.equal((await authorizeAsGateway(s)).decision, "ALLOW");
  await s.stopAuth();
  // Make the anchor a Phase 2C (legacy) history: strip every payload and re-seal the chain as root.
  const legacy = anchor(s).entries.map(({ hash: _h, payload: _p, ...body }) => body);
  let text = "";
  let prev = "0".repeat(64);
  for (const body of legacy) {
    const sealed = sealEntry({ ...body, prev });
    text += `${JSON.stringify(sealed)}\n`;
    prev = sealed.hash;
  }
  sudo(["chattr", "-a", s.paths.anchorPath]);
  sudo(["tee", s.paths.anchorPath], text);
  sudo(["chattr", "+a", s.paths.anchorPath]);
  assert.match(policyCliJson(s, "verify").out.rebuild, /^UNAVAILABLE/);
  assert.equal(policyCliJson(s, "rebuild").out.outcome, "RECOVERY_REQUIRED");
  // A forged "backup" (charge edited down) was never a completed state.
  const forged = join(dir, "forged.json");
  writeFileSync(forged, s.privileged.read(statePath(s)).toString("utf8").replace(/"spent_in_period":\{"agent-celo-poc-1":\{"\$bigint":"30000"\}\}/, '"spent_in_period":{"agent-celo-poc-1":{"$bigint":"0"}}'));
  await assert.rejects(restorePolicyState({ stateRoot: s.paths.policyStateRoot, backupPath: forged }), /POLICY_RESTORE_UNVERIFIED/);
  const result = await restorePolicyState({ stateRoot: s.paths.policyStateRoot, backupPath: backup });
  assert.deepEqual(result.carried_spent, { [AGENT_ID]: (3n * PRICE).toString() }, "the newer charge is carried forward");
  assert.equal(result.frozen, 1, "the backup's open reservation is frozen");
  assert.ok(result.quarantine_until > Math.floor(Date.now() / 1000), "issuance quarantined");
  assert.equal(anchor(s).tip!.kind, "DONE");
  assert.equal(policyCliJson(s, "verify").out.rebuild, "AVAILABLE", "the RESTORE carried a full payload: rebuildable from now on");
  await s.startAuth();
  assert.deepEqual((await authorizeAsGateway(s)).reasons, ["POLICY_STATE_QUARANTINED"], "no issuance on restored rate state");
  const frozen = reservation(s, a1.authorization.auth_id)!;
  assert.equal(frozen.state, "UNCERTAIN");
  // The frozen authorization is still unexpired (60 s TTL) but can never be claimed: no payment.
  await s.restartGateway();
  const r = await submit(s, a1);
  assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
  assert.equal(s.ledger().length, 0);
  assert.equal(reservation(s, a1.authorization.auth_id)!.state, "UNCERTAIN");
  assert.equal(s.journal().inspect(a1.authorization.intent_hash)?.state, "CLAIM_REFUSED");
  assertConsistent(s, "legacy restore", { restored: true });
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
  // Phase 2D: the old executor pays only after its claim committed; crash the auth service while it pays.
  await waitFor("claimed by the old executor", () => reservation(d1, id)?.state === "EXECUTING");
  await d1.crashAuth();

  const d2 = await launch({ policyStateRoot: P, executorStateRoot: executorRoot(), ttlSeconds: 3 });
  await sleep(4_500); // past expiry, while the old executor is still paying
  assert.equal(reservation(d2, id)!.state, "EXECUTING", "claimed: never released by another domain or by expiry");
  assert.equal(spent(policyFile(d2)), 10000n);
  assert.deepEqual((await authorizeAsGateway(d2)).reasons, ["BUDGET_EXCEEDED"], "no budget reuse");
  const done = await purchase;
  assert.equal(done.decision, "ALLOW", "the old executor completed its delayed payment");
  assert.equal(d1.ledger().length, 1);
  assert.equal(reservation(d2, id)!.state, "EXECUTING", "still held after the old payment completed");
  assertConsistent(d2, "d2");
  await stop(d2);
  await stop(d1);

  // Verified reconciliation: a deployment on the reservation's OWN journal reports the payment.
  const d3 = await launch({ policyStateRoot: P, executorStateRoot: E1, ttlSeconds: 3 });
  const confirmed = await waitFor("CONFIRMED by its own domain", () => reservation(d3, id)?.state === "CONFIRMED" && reservation(d3, id));
  assert.equal(confirmed.charged, "10000");
  assertConsistent(d3, "d3");
});

test("CX2b across three journals: an earlier deployment's authorization cannot execute elsewhere; unclaimed, it is released only at expiry and never pays", opts, async () => {
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

  // A third journal executes neither X (E1) nor Y (E2).
  const d3 = await launch({ policyStateRoot: P, executorStateRoot: executorRoot(), ttlSeconds: 3 });
  for (const a of [x, y]) assert.equal((await submit(d3, a)).decision, "DENY");
  assert.equal(d3.ledger().length, 0);
  // Phase 2D: neither was ever claimed, and no claim can be granted after expiry (on the auth
  // service's clock), so the auth service releases both itself; no executor is needed.
  for (const a of [x, y]) {
    const r = await waitFor("released at expiry, unclaimed", () => reservation(d3, a.authorization.auth_id)?.state === "RELEASED" && reservation(d3, a.authorization.auth_id), 20_000);
    assert.deepEqual([r.history.at(-1)!.reason, r.claim], ["EXPIRED_UNCLAIMED", undefined]);
  }
  assert.equal(spent(policyFile(d3)), 0n);
  assertConsistent(d3, "d3");
  await stop(d3);

  // Their own journals still refuse them (expired), consume nothing, and pay nothing.
  const back1 = await launch({ policyStateRoot: P, executorStateRoot: E1, ttlSeconds: 3 });
  assert.equal((await submit(back1, x)).decision, "DENY");
  assert.equal(back1.ledger().length, 0);
  assert.equal(back1.journal().auth(x.authorization.auth_id), undefined);
  assertConsistent(back1, "E1");
  await stop(back1);
  const back2 = await launch({ policyStateRoot: P, executorStateRoot: E2, ttlSeconds: 3 });
  assert.equal((await submit(back2, y)).decision, "DENY");
  assert.equal(back2.ledger().length, 0);
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
  const base = { type: "oxdeai-celo-poc/outcome-report/v2", auth_id: id, intent_hash: a.authorization.intent_hash, journal_id: journalId(s), claim_id: "c".repeat(32) };
  const cancel = { ...base, outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING" };
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

test("FI-03 crash after the reservation is consumed, before the intent record (crashAfterAuthRecord): no payment; never claimed, released at expiry; never payable", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(PRICE), 3), executorStateRoot: executorRoot(), ttlSeconds: 3 });
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
  // Phase 2D: no claim was ever requested; released by the auth service at expiry, not from the journal.
  const rel = await waitFor("released", () => reservation(s, id)?.state === "RELEASED" && reservation(s, id));
  assert.deepEqual([rel.history.at(-1)!.reason, rel.claim], ["EXPIRED_UNCLAIMED", undefined]);
  const j = s.journal();
  assert.equal(j.auth(id)!.disposition, "RESERVED");
  assert.equal(j.inspect(a.authorization.intent_hash), undefined, "pay was never reached");
  const again = await submit(s, a);
  assert.notEqual(again.decision, "ALLOW", JSON.stringify(again));
  assert.equal(s.ledger().length, 0);
  assertConsistent(s, "FI-03");
});

for (const [fault, paid, final] of [
  ["crashBeforePay", 0, "UNCERTAIN"],
  ["crashAfterPay", 1, "CONFIRMED"],
] as const) {
  test(`FI-04/08 crash after the payment started (${fault}): UNCERTAIN and fully charged across executor, auth, and deployment restarts; no retry; only verified settlement evidence moves it`, opts, async () => {
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
    // Operator reconciliation (executor stopped: resolve takes the journal lock). Phase 2D (D5): no
    // non-execution resolution exists, and a settlement needs the MAC'd ledger entry for this claim.
    await d2.stopExecutor();
    const notSettled = resolveAs(d2, a.authorization.intent_hash, "NOT_SETTLED");
    assert.notEqual(notSettled.status, 0);
    assert.match(notSettled.stderr, /RESOLUTION_REFUSED/);
    const settled = resolveAs(d2, a.authorization.intent_hash, "SETTLED");
    if (paid === 0) {
      assert.notEqual(settled.status, 0, "no ledger entry: no settlement evidence");
      assert.match(settled.stderr, /NO_SETTLEMENT_EVIDENCE/);
    } else {
      assert.equal(settled.status, 0, settled.stderr);
      assert.equal(JSON.parse(settled.stdout).resolution.evidence.kind, "MOCK_LEDGER_MAC");
    }
    await d2.startExecutor();
    if (final === "CONFIRMED") await waitFor(final, () => reservation(d2, id)?.state === final);
    else await sleep(1_500); // several reporter passes
    const after = reservation(d2, id)!;
    assert.equal(after.state, final);
    assert.equal(after.charged, String(PRICE), final === "CONFIRMED" ? "confirmed at the evidenced amount" : "unproven: stays fully charged");
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
  const claimId = s.journal().inspect(a.authorization.intent_hash)!.claim_id;
  assert.equal(c.claim?.claim_id, claimId, "the payment's claim");
  const base = { type: "oxdeai-celo-poc/outcome-report/v2", auth_id: id, intent_hash: a.authorization.intent_hash, journal_id: journalId(s), claim_id: claimId };
  assert.equal((await settleAs(s, "executor", "valid", { ...base, outcome: "SETTLED", amount: String(PRICE) }))?.body?.status, "ALREADY_APPLIED");
  const conflict = (await settleAs(s, "executor", "valid", { ...base, outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING" }))?.body;
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

test("FI-07b restart with a pending reservation, new deployment (new PDP key): the old authorization is refused, stays charged until it expires unclaimed, never pays", opts, async () => {
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
  // Phase 2D: never claimed; released by the auth service at expiry (no claim possible after it).
  const rel = await waitFor("released at expiry, unclaimed", () => reservation(d2, id)?.state === "RELEASED" && reservation(d2, id), 30_000);
  assert.deepEqual([rel.history.at(-1)!.reason, rel.claim], ["EXPIRED_UNCLAIMED", undefined]);
  assert.equal(d2.journal().auth(id), undefined, "the refused authorization was never consumed");
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

// ── Phase 2D (architecture C): execution claims at the authorization service ──
//
// Every test below checks actual mock payments (the ledger) and budget
// accounting (assertConsistent: I1-I6), not only response codes.

const snapshotJournal = (s: IsolatedSystem) => {
  const parent = mkdtempSync(join(tmpdir(), "oxdeai-journal-snap-"));
  const snap = join(parent, "journal");
  roots.push(snap); // removeStateRoot removes dirname(snap) = this temp parent only
  assert.equal(sudo(["cp", "-a", s.paths.journalDir, snap]).status, 0);
  return snap;
};
/** Replace the journal with an older snapshot (executor stopped); the newer one is kept aside, not deleted. */
const restoreJournal = (s: IsolatedSystem, snap: string) => {
  assert.equal(sudo(["mv", "-T", s.paths.journalDir, `${s.paths.journalDir}.newer-${Date.now()}`]).status, 0);
  assert.equal(sudo(["cp", "-a", snap, s.paths.journalDir]).status, 0);
};
const paidTotal = (s: IsolatedSystem) => s.ledger().reduce((t, e) => t + BigInt(e.receipt.amount), 0n);

test("M1-a regression (review finding M-1): journal rollback after a pre-execution rejection, plus a gateway restart, never makes the authorization payable again", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot("10000"), executorStateRoot: executorRoot() });
  // 1-2. Budget 10 000; authorize and reserve.
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  assert.equal(reservation(s, id)!.state, "RESERVED");
  assert.equal(spent(policyFile(s)), 10000n);
  // 3. Snapshot the journal before the authorization is consumed.
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  // 4-5. Pre-execution rejection: released only by the durable, acknowledged VOID (synchronous).
  await s.startExecutor({ quoteDrift: true });
  const r1 = await submit(s, a);
  assert.notEqual(r1.decision, "ALLOW", JSON.stringify(r1));
  const rel = reservation(s, id)!;
  assert.equal(rel.state, "RELEASED", "released by the time the rejection was answered");
  assert.deepEqual([rel.history.at(-1)!.outcome, rel.history.at(-1)!.reason, rel.claim], ["VOID", "REJECTED_BEFORE_EXECUTION", undefined]);
  assert.equal(spent(policyFile(s)), 0n);
  assert.equal(s.ledger().length, 0);
  // 6-7. Restore the older journal; restart the executor (no fault) and the gateway (its replay cache is gone).
  await s.stopExecutor();
  restoreJournal(s, snap);
  await s.startExecutor();
  await s.restartGateway();
  assert.equal(s.journal().auth(id), undefined, "the restored journal no longer knows the authorization");
  assert.ok(Math.floor(Date.now() / 1000) < a.authorization.expiry, "the authorization is still valid");
  // 8. Replay the original authorization: the auth service refuses the claim; nothing is paid.
  const r2 = await submit(s, a);
  assert.notEqual(r2.decision, "ALLOW", JSON.stringify(r2));
  assert.match(JSON.stringify(r2), /CLAIM_REFUSED/);
  assert.equal(s.ledger().length, 0, "the replayed authorization paid nothing");
  assert.equal(s.journal().inspect(a.authorization.intent_hash)?.state, "CLAIM_REFUSED");
  assert.equal(reservation(s, id)!.state, "RELEASED");
  assertConsistent(s, "M1-a after replay");
  // 9. Further payment activity: the released capacity is spent exactly once, never beyond the budget.
  assert.equal(await buyAsAgent(s), "ALLOW");
  assert.equal(await buyAsAgent(s), "DENY");
  await waitFor("CONFIRMED", () => Object.values(policyFile(s).reservations).some((x) => x.state === "CONFIRMED"));
  assert.equal(s.ledger().length, 1);
  assert.ok(paidTotal(s) <= 10000n, `paid ${paidTotal(s)} within the 10000 budget`);
  assertConsistent(s, "M1-a final");
});

test("M1-b journal rollback after a successful claim, before the outcome report (payment made, executor killed): the replay cannot pay a second time; the claim stays charged", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE)), executorStateRoot: executorRoot(), reconcileIntervalMs: 600_000 });
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  // Claim committed, payment settled, executor killed before the journal records it or anything is reported.
  await s.startExecutor({ crashAfterPay: true });
  const r1 = await submit(s, a);
  assert.notEqual(r1.decision, "ALLOW", JSON.stringify(r1));
  await s.executorExited();
  assert.equal(s.ledger().length, 1, "the first attempt paid");
  const claimed = reservation(s, id)!;
  assert.equal(claimed.state, "EXECUTING");
  assert.equal(claimed.claim?.claim_id, s.ledger()[0]!.claim_id, "paid under its committed claim");
  // Roll the journal back to before the consumption; restart everything the executor side owns, and the gateway.
  restoreJournal(s, snap);
  await s.startExecutor();
  await s.restartGateway();
  const r2 = await submit(s, a);
  assert.notEqual(r2.decision, "ALLOW", JSON.stringify(r2));
  assert.match(JSON.stringify(r2), /CLAIM_REFUSED.*EXECUTING/);
  assert.equal(s.ledger().length, 1, "no second payment");
  assert.equal(reservation(s, id)!.state, "EXECUTING", "still charged under the original claim");
  assert.equal(reservation(s, id)!.charged, String(PRICE));
  // Replay after an auth-service restart too.
  await s.restartAuth();
  await s.restartGateway();
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  assert.equal(s.ledger().length, 1);
  assertConsistent(s, "M1-b");
});

test("M1-c claim persistence and supported recovery: a claim survives auth restarts and a rolled-back state file rebuilt from the anchor; it is never claimable again", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE)), executorStateRoot: executorRoot() });
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  const beforeClaim = s.privileged.read(statePath(s)).toString("utf8");
  await s.stopExecutor();
  const snap = snapshotJournal(s);
  await s.startExecutor({ crashBeforePay: true }); // claim committed, killed after the acknowledgement, before pay
  await submit(s, a);
  await s.executorExited();
  assert.equal(s.ledger().length, 0);
  assert.equal(reservation(s, id)!.state, "EXECUTING");
  await s.restartAuth();
  assert.equal(reservation(s, id)!.state, "EXECUTING", "the claim survives an auth restart");
  // Supported recovery: the state file rolled back to before the claim is refused, then rebuilt from the anchor.
  await s.stopAuth();
  sudo(["tee", statePath(s)], beforeClaim);
  await assert.rejects(s.startAuth(), /POLICY_STATE_ROLLBACK/);
  assert.equal(policyCliJson(s, "rebuild").out.outcome, "SAFE_TO_RESUME");
  await s.startAuth();
  assert.equal(reservation(s, id)!.state, "EXECUTING", "the rebuilt state still holds the claim");
  // Journal rolled back too, gateway restarted: the replay is refused by the claim.
  restoreJournal(s, snap);
  await s.startExecutor();
  await s.restartGateway();
  const r = await submit(s, a);
  assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
  assert.match(JSON.stringify(r), /CLAIM_REFUSED/);
  assert.equal(s.ledger().length, 0, "never paid");
  assert.notEqual(reservation(s, id)!.state, "RELEASED", "a claim that may have paid is never released");
  assert.equal(spent(policyFile(s)), PRICE);
  assertConsistent(s, "M1-c");
});

test("CL1 crash windows of the claim: before its commit, after its commit before the acknowledgement; no payment, no unsafe release, no lock", opts, async () => {
  // a. Auth killed after the claim's PREPARE: the restart aborts it; the executor abandoned the attempt.
  // TTL 10 s: the authorization must still be valid at the (delayed) claim, so the fault fires on the claim's commit.
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE), 10), executorStateRoot: executorRoot(), ttlSeconds: 10 });
  const a = await authorizeAsAgent(s);
  await s.restartAuth({ crashAfterPrepare: true });
  const ra = await submit(s, a);
  assert.notEqual(ra.decision, "ALLOW", JSON.stringify(ra));
  await s.authExited();
  assert.equal(s.ledger().length, 0);
  assert.equal(s.journal().inspect(a.authorization.intent_hash)?.state, "CLAIM_ABANDONED");
  await s.startAuth();
  const ea = await waitFor("released at expiry", () => reservation(s, a.authorization.auth_id)?.state === "RELEASED" && reservation(s, a.authorization.auth_id), 20_000);
  assert.deepEqual([ea.claim, ea.history.at(-1)!.reason], [undefined, "EXPIRED_UNCLAIMED"], "never claimed: released only at expiry, not from the journal");
  assertConsistent(s, "CL1a");
  // b. Auth killed after the claim committed, before answering: the executor never pays it and reports the abandonment.
  const b = await authorizeAsAgent(s);
  await s.restartAuth({ crashAfterClaimCommit: true });
  const rb = await submit(s, b);
  assert.notEqual(rb.decision, "ALLOW", JSON.stringify(rb));
  await s.authExited();
  assert.equal(s.ledger().length, 0);
  await s.startAuth();
  const eb = await waitFor("released by the positive abandon record", () => reservation(s, b.authorization.auth_id)?.state === "RELEASED" && reservation(s, b.authorization.auth_id));
  assert.ok(eb.claim, "the claim had committed");
  assert.deepEqual([eb.history.at(-1)!.outcome, eb.history.at(-1)!.reason, eb.history.at(-1)!.claim_id], ["NOT_EXECUTED", "CLAIM_ABANDONED", eb.claim!.claim_id]);
  await s.restartGateway();
  assert.notEqual((await submit(s, b)).decision, "ALLOW", "never claimable again");
  assert.equal(s.ledger().length, 0);
  assertConsistent(s, "CL1b");
});

test("CL2 VOID: acknowledgement lost after its commit still burns the authorization; an undeliverable VOID releases nothing until expiry; an auth outage prevents any payment", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(3n * PRICE), 10), executorStateRoot: executorRoot(), ttlSeconds: 10 });
  // a. VOID committed, auth killed before answering.
  const a = await authorizeAsAgent(s);
  await s.restartAuth({ crashAfterVoidCommit: true });
  await s.stopExecutor();
  await s.startExecutor({ quoteDrift: true });
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  await s.authExited();
  await s.startAuth();
  const va = reservation(s, a.authorization.auth_id)!;
  assert.deepEqual([va.state, va.history.at(-1)!.outcome], ["RELEASED", "VOID"], "the VOID was durable before the crash");
  // b. Auth down: the rejection cannot be voided; the reservation stays charged until it expires.
  const b = await authorizeAsAgent(s);
  await s.stopAuth();
  assert.notEqual((await submit(s, b)).decision, "ALLOW");
  await s.startAuth();
  assert.equal(reservation(s, b.authorization.auth_id)!.state, "RESERVED", "not released from the journal alone");
  const eb = await waitFor("released at expiry", () => reservation(s, b.authorization.auth_id)?.state === "RELEASED" && reservation(s, b.authorization.auth_id), 20_000);
  assert.equal(eb.history.at(-1)!.reason, "EXPIRED_UNCLAIMED");
  // c. Auth down while a valid payment is attempted: no claim, no payment.
  await s.stopExecutor();
  await s.startExecutor();
  const c = await authorizeAsAgent(s);
  await s.stopAuth();
  const rc = await submit(s, c);
  assert.notEqual(rc.decision, "ALLOW", JSON.stringify(rc));
  assert.equal(s.ledger().length, 0, "an auth-service outage prevents the payment");
  await s.startAuth();
  assertConsistent(s, "CL2");
});

test("CL3 expiry during a slow quote (L-4): the claim is refused (expired, or already released at expiry); nothing is paid; the authorization is never reusable", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(PRICE), 3), executorStateRoot: executorRoot(), ttlSeconds: 3, gatewayTimeoutMs: 20_000 });
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  await s.stopExecutor();
  await s.startExecutor({ delayQuoteMs: 4_000 }); // valid when the executor verified it, expired at the claim
  const r = await submit(s, a);
  assert.equal(r.decision, "DENY", JSON.stringify(r));
  assert.equal(r.executed, false);
  // Exactly two fail-closed reasons are possible: the claim arrived after expiry on the auth service's clock,
  // or the auth service's expiry release had already (durably) released the unclaimed reservation.
  const reason = /CLAIM_REFUSED:(AUTH_EXPIRED_AT_CLAIM|NOT_ELIGIBLE:RELEASED)/.exec(String(r.detail))?.[1];
  assert.ok(reason, `refusal reason ${r.detail}`);
  assert.equal(s.ledger().length, 0, "no mock payment");
  assert.equal(s.journal().inspect(a.authorization.intent_hash)?.state, "CLAIM_REFUSED", "pay was never reached");
  const rel = await waitFor("released at expiry", () => reservation(s, id)?.state === "RELEASED" && reservation(s, id));
  assert.deepEqual([rel.claim, rel.history.at(-1)!.outcome, rel.history.at(-1)!.reason], [undefined, "EXPIRED", "EXPIRED_UNCLAIMED"], "released only by expiry, never claimed");
  assert.equal(spent(policyFile(s)), 0n);
  // The expired authorization cannot be reused, even after a gateway restart.
  await s.restartGateway();
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  assert.equal(s.ledger().length, 0);
  assert.equal(reservation(s, id)!.state, "RELEASED");
  assertConsistent(s, "CL3");
});

test("CL5 expiry boundary at the claim (L-4, deterministic): with no expiry release running, the claim is refused AUTH_EXPIRED_AT_CLAIM; the reservation stays charged and is never payable", opts, async () => {
  // The auth service's expiry release is effectively off, so only the claim-time clock check can refuse.
  const s = await launch({ policyStateRoot: policyRoot(String(PRICE), 3), executorStateRoot: executorRoot(), ttlSeconds: 3, gatewayTimeoutMs: 20_000, expiryReleaseIntervalMs: 600_000 });
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id;
  await s.stopExecutor();
  await s.startExecutor({ delayQuoteMs: 4_000 });
  const r = await submit(s, a);
  assert.equal(r.decision, "DENY", JSON.stringify(r));
  assert.match(String(r.detail), /CLAIM_REFUSED:AUTH_EXPIRED_AT_CLAIM/);
  assert.ok(Math.floor(Date.now() / 1000) >= a.authorization.expiry, "the authorization had expired at the claim");
  assert.equal(s.ledger().length, 0);
  assert.equal(s.journal().inspect(a.authorization.intent_hash)?.state, "CLAIM_REFUSED");
  const res = reservation(s, id)!;
  assert.deepEqual([res.state, res.claim, res.charged], ["RESERVED", undefined, String(PRICE)], "unclaimed and still charged (no release ran)");
  // Not reusable: a later claim for it is refused too (expired), and nothing is paid.
  await s.stopExecutor();
  await s.startExecutor();
  await s.restartGateway();
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  assert.equal(s.ledger().length, 0);
  assert.equal(reservation(s, id)!.claim, undefined, "never claimed");
  assertConsistent(s, "CL5");
});

test("CL4 forged and foreign claims: wrong key, unknown authorization, other domain, and non-executor identities never claim", opts, async () => {
  const s = await launch({ policyStateRoot: policyRoot(String(2n * PRICE)), executorStateRoot: executorRoot() });
  const a = await authorizeAsGateway(s);
  const claim = { type: "oxdeai-celo-poc/execution-claim/v1", auth_id: a.authorization.auth_id, intent_hash: a.authorization.intent_hash, journal_id: journalId(s), claim_id: "c".repeat(32) };
  const body = async (mode: string, c: Record<string, unknown>) => (await settleAs(s, "executor", mode, c))?.body;
  assert.match((await body("claim-wrong-key", claim)).reason, /REPORT_INVALID:signature/);
  assert.match((await body("claim-valid", { ...claim, auth_id: "synthetic-unknown" })).reason, /UNKNOWN_RESERVATION/);
  assert.match((await body("claim-valid", { ...claim, journal_id: "f".repeat(32) })).reason, /DOMAIN_NOT_CURRENT/);
  assert.match((await body("claim-valid", { ...claim, intent_hash: "e".repeat(64) })).reason, /INTENT_HASH_MISMATCH/);
  for (const role of ["gateway", "agent"] as const) assert.equal((await settleAs(s, role, "claim-valid", claim)).error, "EACCES");
  assert.equal(reservation(s, a.authorization.auth_id)!.state, "RESERVED", "no forged claim was granted");
  assert.equal(s.ledger().length, 0);
  assertConsistent(s, "CL4");
});

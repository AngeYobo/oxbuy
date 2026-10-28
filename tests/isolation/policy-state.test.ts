// SPDX-License-Identifier: MIT
/**
 * Phase 2B-R3: durable budget integrity (review findings F1, F2, F4).
 *
 * Real processes under the four service identities. Policy state lives in
 * disposable, operator-provisioned state roots; tampering with it (deleting,
 * corrupting, locking) is done by the operator through sudo, on those
 * disposable roots only, to simulate loss and operator error.
 *
 *   F1  missing / corrupt / unreadable state fails closed; init happens once
 *   F2  a new deployment reuses the persistent budget of the same policy identity
 *   F4  one writer at a time, enforced by a kernel lock (flock), with crash recovery
 *
 * Phase 2C: the auth service takes the lock itself on its own descriptor
 * (N1), so the contenders below are started as plain `node auth-main.ts`; the
 * Phase 2B "unlocked contender refuses with 78" case is replaced by the
 * stronger N1 case: a process that only has the lock file open is refused
 * (75) while a writer runs. Outcome reports now also commit policy state, so
 * F1b checks the budget and reservations instead of a bare version count.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { commandAs, identitiesUnavailableReason } from "../../src/isolation/identity.ts";
import type { IsolatedSystem } from "../../src/isolation/launcher.ts";
import { initPolicyState, policyBinding, policyStateDir } from "../../src/isolation/policy-state-admin.ts";
import { AGENT_ID, SERVICES } from "../../src/system.ts";
import { freshPolicyState, REPO_ROOT, removeStateRoot, trustedArtifact } from "./trusted-artifact.ts";

const BLOCKED = identitiesUnavailableReason();
const opts = BLOCKED === null ? {} : { skip: `BLOCKED: ${BLOCKED}` };
const PROBE = join(REPO_ROOT, "tests", "isolation", "agent-probe.ts");
const NODE = realpathSync(process.execPath);
const PRICE = Number(SERVICES.weather.price);

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

function stateRoot(budget: string): string {
  const r = freshPolicyState({ budget });
  roots.push(r);
  return r;
}
async function launch(policyStateRoot: string, extra: { ttlSeconds?: number } = {}): Promise<IsolatedSystem> {
  const s = await trusted.launch({ policyStateRoot, ...extra });
  systems.push(s);
  return s;
}

/** Full agent purchase (quote -> authorize -> purchase). */
async function buy(sys: IsolatedSystem): Promise<string> {
  const r = (await sys.runAgent(PROBE, ["buy", sys.paths.publicSocket, "weather"])).result as any;
  return r.stage === "purchase" ? r.result.decision : `DENY:${r.reasons.join(",")}`;
}

/** One authorization request made by the gateway identity straight to the auth service. */
async function authorizeAsGateway(sys: IsolatedSystem): Promise<string> {
  const req = {
    service_id: SERVICES.weather.service_id,
    method: "POST",
    url: `${SERVICES.weather.resource}?city=lagos`,
    body: JSON.stringify({ units: "metric", days: 3 }),
    network: SERVICES.weather.network,
    asset: SERVICES.weather.asset,
    recipient: SERVICES.weather.pay_to,
    max_amount: SERVICES.weather.price.toString(),
  };
  const r = (await sys.runAs("gateway", PROBE, ["post", sys.paths.authSocket, "/v1/authorize", JSON.stringify(req), "{}"])).result as any;
  const b = r.value?.body;
  return b ? (b.decision === "ALLOW" ? "ALLOW" : `DENY:${b.reasons.join(",")}`) : `ERR:${r.code}`;
}

const statePath = (sys: IsolatedSystem) => join(sys.paths.authStateDir, "state.json");
const stateFile = (sys: IsolatedSystem) => JSON.parse(sys.privileged.read(statePath(sys)).toString("utf8"));
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const sudo = (args: string[], input?: string) => spawnSync("sudo", ["-n", ...args], { input, encoding: "utf8" }).status;
const allowsInLog = (sys: IsolatedSystem) =>
  sys.privileged.exists(sys.paths.decisionLog)
    ? sys.privileged.read(sys.paths.decisionLog).toString().split("\n").filter((l) => l.includes('"decision":"ALLOW"')).length
    : 0;

async function assertAuthRefuses(sys: IsolatedSystem, reason: RegExp): Promise<void> {
  await assert.rejects(sys.startAuth(), (err: Error) => {
    assert.match(err.message, /auth exited during startup \(code 78\)/);
    assert.match(err.message, reason);
    return true;
  });
}

// ── F1: missing policy state must fail closed ─────────────────────────────

test("R3-F1a initialization is explicit and happens once; re-init cannot overwrite", opts, () => {
  const root = stateRoot("20000");
  const dir = policyStateDir(root, policyBinding());
  const before = spawnSync("sudo", ["-n", "cat", join(dir, "state.json")]).stdout;
  assert.ok(before.length > 0);
  assert.throws(() => initPolicyState({ stateRoot: root, budget: "999999999" }), /POLICY_STATE_EXISTS/);
  const afterBytes = spawnSync("sudo", ["-n", "cat", join(dir, "state.json")]).stdout;
  assert.equal(sha(afterBytes), sha(before), "existing state untouched by the refused re-init");
});

test("R3-F1b restart and crash with existing state preserve the budget", opts, async () => {
  const sys = await launch(stateRoot("20000"));
  assert.deepEqual([await buy(sys), await buy(sys), await buy(sys)], ["ALLOW", "ALLOW", "DENY:BUDGET_EXCEEDED"]);
  await sys.restartGateway();
  assert.equal(await buy(sys), "DENY:BUDGET_EXCEEDED");
  await sys.restartAuth();
  assert.equal(await buy(sys), "DENY:BUDGET_EXCEEDED");
  await sys.crashAuth();
  await sys.startAuth();
  assert.equal(await buy(sys), "DENY:BUDGET_EXCEEDED");
  assert.equal(sys.ledger().length, 2);
  const st = stateFile(sys);
  assert.deepEqual(st.state.budget.spent_in_period, { [AGENT_ID]: { $bigint: "20000" } }, "both payments still charged");
  assert.deepEqual(Object.values(st.reservations as Record<string, { state: string }>).map((r) => r.state).sort(), ["CONFIRMED", "CONFIRMED"]);
});

for (const [name, damage, reason] of [
  ["missing", (p: string) => sudo(["rm", "-f", p]), /POLICY_STATE_MISSING/],
  ["corrupt", (p: string) => sudo(["tee", p], "{ not json"), /POLICY_STATE_CORRUPT/],
  ["unreadable", (p: string) => sudo(["chmod", "000", p]), /POLICY_STATE_UNREADABLE:EACCES/],
] as const) {
  test(`R3-F1c restart with ${name} policy state: auth refuses to start, no authorization, no payment, state not recreated`, opts, async () => {
    const sys = await launch(stateRoot("20000"));
    assert.deepEqual([await buy(sys), await buy(sys), await buy(sys)], ["ALLOW", "ALLOW", "DENY:BUDGET_EXCEEDED"]);
    const ledger = sys.ledger().length;
    const allows = allowsInLog(sys);

    // While running: damage is detected on the next request (fail closed).
    assert.equal(damage(statePath(sys)), 0);
    assert.match(await authorizeAsGateway(sys), /^DENY:POLICY_STATE_UNAVAILABLE:POLICY_STATE_(MISSING|CORRUPT|UNREADABLE)/);

    // After a restart: the service refuses to start; it never re-creates a budget.
    await sys.stopAuth();
    await assertAuthRefuses(sys, reason);
    assert.equal(await buy(sys), "DENY:PDP_UNAVAILABLE");
    assert.equal(sys.ledger().length, ledger, "no payment while policy state is unavailable");
    assert.equal(allowsInLog(sys), allows, "no authorization issued");
    if (name === "missing") assert.equal(sys.privileged.exists(statePath(sys)), false, "state was not silently recreated");
  });
}

// ── F2: persistent budget across deployments ──────────────────────────────

test("R3-F2a a new deployment of the same policy identity keeps the exhausted budget", opts, async () => {
  const root = stateRoot("20000");
  const a = await launch(root);
  assert.deepEqual([await buy(a), await buy(a), await buy(a)], ["ALLOW", "ALLOW", "DENY:BUDGET_EXCEEDED"]);
  const stateA = stateFile(a);
  await a.stop();

  const b = await launch(root);
  assert.notEqual(b.paths.root, a.paths.root, "a genuinely new runtime directory");
  assert.equal(b.paths.authStateDir, a.paths.authStateDir, "same persistent state");
  assert.equal(await buy(b), "DENY:BUDGET_EXCEEDED");
  assert.equal(await authorizeAsGateway(b), "DENY:BUDGET_EXCEEDED");
  assert.equal(b.ledger().length, 0);
  const stateB = stateFile(b);
  assert.equal(stateB.version, stateA.version, "state continued, not recreated (version not reset to 0)");
  assert.deepEqual(stateB.binding, stateA.binding);
});

test("R3-F2b a different policy identity cannot reuse or reset the original budget", opts, async () => {
  const root = stateRoot("20000");
  const a = await launch(root);
  assert.equal(await buy(a), "ALLOW");
  await a.stop();
  // Snapshot after the deployment stopped (Phase 2C: its outcome report also commits state).
  const original = spawnSync("sudo", ["-n", "cat", statePath(a)]).stdout;

  // Different policy identity (ttl is part of policy_id): it was never initialized,
  // so its state directory does not exist and the lock cannot even be taken
  // (flock exit 66): the service never starts, and nothing is created for it.
  const other = policyBinding({ ttlSeconds: 30 });
  assert.notEqual(other.policyId, policyBinding().policyId);
  const otherDir = policyStateDir(root, other);
  await assert.rejects(launch(root, { ttlSeconds: 30 }), /auth exited during startup \(code 66\).*writer\.lock: ENOENT/);
  assert.notEqual(sudo(["test", "-e", otherDir]), 0, "no state was created for the other identity");

  // Operator mistake: the original state copied into the other identity's directory.
  assert.equal(sudo(["install", "-d", "-o", "oxdeai-auth", "-g", "oxdeai-auth", "-m", "0700", otherDir]), 0);
  const staging = mkdtempSync(join(tmpdir(), "oxdeai-copy-"));
  writeFileSync(join(staging, "state.json"), original, { mode: 0o600 });
  assert.equal(sudo(["install", "-o", "oxdeai-auth", "-g", "oxdeai-auth", "-m", "0600", join(staging, "state.json"), join(otherDir, "state.json")]), 0);
  rmSync(staging, { recursive: true, force: true });
  await assert.rejects(launch(root, { ttlSeconds: 30 }), /code 78\).*POLICY_STATE_BINDING_MISMATCH/);

  const unchanged = spawnSync("sudo", ["-n", "cat", join(policyStateDir(root, policyBinding()), "state.json")]).stdout;
  assert.equal(sha(unchanged), sha(original), "original budget state untouched");
});

// ── F4: single writer, kernel lock, crash recovery ────────────────────────

/**
 * Start an extra auth instance as the auth identity; resolve on ready or exit.
 * "plain": as the launcher starts it (it takes the lock itself);
 * "open-fd": it first opens the lock file WITHOUT locking it (the N1 attack).
 */
function contender(sys: IsolatedSystem, mode: "plain" | "open-fd" = "plain"): Promise<{ ready: boolean; pid?: number; code?: number | null; out: string }> {
  const main = [NODE, join(sys.paths.apps.auth, "src", "isolation", "auth-main.ts"), sys.paths.authConfig];
  const argv = mode === "plain" ? main : ["/bin/bash", "-c", `exec 9<'${sys.paths.writerLock}'; exec "$@"`, "contender", ...main];
  const [cmd, args] = commandAs("auth", argv);
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    const onData = (c: Buffer) => {
      out += c.toString("utf8");
      const line = out.split(/\r?\n/).find((l) => l.includes('"event":"ready"'));
      if (line) resolve({ ready: true, pid: JSON.parse(line.trim()).pid, out });
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", (c: Buffer) => (out += c.toString("utf8")));
    child.on("exit", (code) => resolve({ ready: false, code, out }));
  });
}

test("R3-F4a two auth processes starting at once: exactly one owns the writer lock", opts, async () => {
  const sys = await launch(stateRoot("50000"));
  await sys.stopAuth();
  const [x, y] = await Promise.all([contender(sys), contender(sys)]);
  const winners = [x, y].filter((c) => c.ready);
  const losers = [x, y].filter((c) => !c.ready);
  assert.equal(winners.length, 1, JSON.stringify([x, y]));
  assert.equal(losers[0]!.code, 75, "the loser never started: lock conflict");
  assert.match(losers[0]!.out, /POLICY_STATE_LOCKED/);

  // While the winner runs, a third instance is refused too, including one that
  // already has the lock file open (N1: an open descriptor is not ownership).
  assert.equal((await contender(sys)).code, 75);
  const openFd = await contender(sys, "open-fd");
  assert.equal(openFd.code, 75, openFd.out);
  assert.match(openFd.out, /POLICY_STATE_LOCKED/);

  // The winner serves authorizations; then it is killed and a normal start recovers at once.
  assert.equal(await authorizeAsGateway(sys), "ALLOW");
  assert.equal(sudo(["kill", "-KILL", String(winners[0]!.pid)]), 0);
  await new Promise((r) => setTimeout(r, 300));
  await sys.startAuth(); // kernel released the lock with the dead process: no stale lock to remove
  assert.equal(await authorizeAsGateway(sys), "ALLOW");
});

test("R3-F4b (2C, N1) an auth process that only has the lock file open never becomes a second writer", opts, async () => {
  const sys = await launch(stateRoot("50000"));
  // Running writer + open-descriptor contender: refused before touching state.
  const versionBefore = stateFile(sys).version;
  const openFd = await contender(sys, "open-fd");
  assert.equal(openFd.code, 75, openFd.out);
  assert.equal(stateFile(sys).version, versionBefore, "no state change by the refused process");
  assert.equal(await authorizeAsGateway(sys), "ALLOW", "the real writer still serves");
  // No writer running: the same process takes the lock itself and is then the only writer.
  await sys.stopAuth();
  const sole = await contender(sys, "open-fd");
  assert.equal(sole.ready, true, sole.out);
  assert.equal((await contender(sys)).code, 75, "and nobody else can join it");
  assert.equal(sudo(["kill", "-KILL", String(sole.pid)]), 0);
});

test("R3-F4c crash during contention: after SIGKILL, still at most one writer", opts, async () => {
  const sys = await launch(stateRoot("50000"));
  await sys.crashAuth();
  const [x, y, z] = await Promise.all([contender(sys), contender(sys), contender(sys)]);
  const winners = [x, y, z].filter((c) => c.ready);
  assert.equal(winners.length, 1, JSON.stringify([x, y, z]));
  assert.ok([x, y, z].filter((c) => !c.ready).every((c) => c.code === 75));
  assert.equal(sudo(["kill", "-KILL", String(winners[0]!.pid)]), 0);
});

test("R3-F4d lock cannot be taken (lock file unopenable): auth refuses, no authorization, no payment", opts, async () => {
  const sys = await launch(stateRoot("50000"));
  const ledger = sys.ledger().length;
  await sys.stopAuth();
  assert.equal(sudo(["chmod", "000", sys.paths.writerLock]), 0);
  await assert.rejects(sys.startAuth(), /auth exited during startup \(code 66\).*writer\.lock: EACCES/);
  assert.equal(await buy(sys), "DENY:PDP_UNAVAILABLE");
  assert.equal(sys.ledger().length, ledger);
  assert.equal(sudo(["chmod", "644", sys.paths.writerLock]), 0);
  await sys.startAuth();
  assert.equal(await buy(sys), "ALLOW");
});

test("R3-F4e concurrent authorizations, across a restart, never exceed the budget", opts, async () => {
  const sys = await launch(stateRoot(String(5 * PRICE)));
  const first = await Promise.all(Array.from({ length: 12 }, () => authorizeAsGateway(sys)));
  await sys.restartAuth();
  const second = await Promise.all(Array.from({ length: 12 }, () => authorizeAsGateway(sys)));
  await sys.restartGateway();
  const third = await Promise.all(Array.from({ length: 4 }, () => authorizeAsGateway(sys)));
  const all = [...first, ...second, ...third];
  const allow = all.filter((d) => d === "ALLOW").length;
  assert.equal(allow, 5, JSON.stringify(all));
  assert.ok(all.every((d) => d === "ALLOW" || d === "DENY:BUDGET_EXCEEDED" || d === "DENY:POLICY_STATE_CONFLICT"), JSON.stringify(all));
  assert.ok(allow * PRICE <= 5 * PRICE, "aggregate authorized amount within the configured limit");
  assert.equal(allowsInLog(sys), 5);
});

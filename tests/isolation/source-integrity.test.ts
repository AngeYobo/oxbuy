// SPDX-License-Identifier: MIT
/**
 * SI-01..07: an untrusted agent cannot get modified source or dependencies
 * executed by the trusted processes at a later launch.
 *
 * Every attack is performed by a process running as the agent OS identity
 * (`nobody`) against a disposable, world-writable copy of the working tree
 * (mirroring this Codespace's ACL). The real repository is never modified.
 * Injected code, if it ever ran as the operator, would create a marker file.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { approveArtifact, removeTree, sealArtifact, verifyArtifact } from "../../src/isolation/artifact.ts";
import { agentCommand, agentIdentityUnavailableReason } from "../../src/isolation/identity.ts";
import { launchIsolatedSystem as launchFromCheckout } from "../../src/isolation/launcher.ts";
import { loadLauncher, newStore, REPO_ROOT } from "./trusted-artifact.ts";

const BLOCKED = agentIdentityUnavailableReason();
const opts = BLOCKED === null ? {} : { skip: `BLOCKED: ${BLOCKED}` };
const PROBE = join(REPO_ROOT, "tests", "isolation", "agent-probe.ts");
const cleanups: Array<() => void> = [];

function asAgent(script: string) {
  const [cmd, args] = agentCommand(["/bin/sh", "-c", script]);
  return spawnSync(cmd, args, { encoding: "utf8" });
}

/** Disposable working tree, writable by everyone like the Codespace checkout. */
function workingTree(): string {
  const wt = mkdtempSync(join(tmpdir(), "oxdeai-wt-"));
  for (const p of ["src", "package.json", "package-lock.json"]) cpSync(join(REPO_ROOT, p), join(wt, p), { recursive: true });
  cpSync(join(REPO_ROOT, "node_modules", "@oxdeai"), join(wt, "node_modules", "@oxdeai"), { recursive: true, dereference: true });
  spawnSync("chmod", ["-R", "a+rwX", wt]);
  chmodSync(wt, 0o777);
  cleanups.push(() => removeTree(wt));
  return wt;
}

function runtimeParent(): string {
  const d = mkdtempSync(join(tmpdir(), "oxdeai-rt-"));
  chmodSync(d, 0o755);
  cleanups.push(() => rmSync(d, { recursive: true, force: true }));
  return d;
}

/** The agent appends code that, if executed as the operator, writes `marker`. */
function plant(file: string, marker: string): void {
  const payload = `;import("node:fs").then((f) => f.writeFileSync("${marker}", "uid=" + process.getuid()));`;
  const r = asAgent(`printf '%s\\n' '${payload}' >> '${file}'`);
  assert.equal(r.status, 0, `agent could not modify ${file}: ${r.stderr}`);
  assert.ok(readFileSync(file, "utf8").includes(marker), "the agent's modification is on disk");
}

const settle = () => new Promise((r) => setTimeout(r, 400));

/** The launch must be refused; if it is not, stop what it started before failing. */
async function assertLaunchRefused(launch: () => Promise<{ stop(): Promise<void> }>, pattern: RegExp): Promise<void> {
  let sys: { stop(): Promise<void> };
  try {
    sys = await launch();
  } catch (err) {
    assert.match((err as Error).message, pattern);
    return;
  }
  await sys.stop();
  assert.fail(`launch was not refused (expected ${pattern})`);
}

let store: string;
let approved: string;
before(() => {
  if (BLOCKED !== null) return;
  store = newStore();
  cleanups.push(() => removeTree(store));
  approved = sealArtifact({ sourceRoot: workingTree(), store }).digest;
  approveArtifact(approved, { store, note: "SI baseline" });
});
after(() => {
  for (const c of cleanups.splice(0).reverse()) c();
});

test("SI-01 a valid protected artifact launches and pays exactly once", opts, async () => {
  const sys = await (await loadLauncher(store, approved)).launchIsolatedSystem({ agentCwd: REPO_ROOT });
  try {
    assert.equal(sys.artifact.digest, approved);
    const argv = readFileSync(`/proc/${sys.pids().executor}/cmdline`, "utf8").split("\0");
    assert.ok(argv[1]!.startsWith(join(store, "artifacts", approved) + "/"), "executor runs from the approved artifact");
    const out = (await sys.runAgent(PROBE, ["buy", sys.paths.publicSocket, "weather"])).result as any;
    assert.equal(out.result.decision, "ALLOW");
    assert.equal(sys.ledger().length, 1);
  } finally {
    await sys.stop();
  }
});

for (const target of ["src/isolation/executor-main.ts", "src/isolation/gateway-main.ts", "src/executor/executor.ts", "src/isolation/launcher.ts"]) {
  test(`SI-02 agent modifies ${target} before launch: never executed; a re-seal is a different, unapproved artifact`, opts, async () => {
    const wt = workingTree();
    const marker = join(wt, "MARKER");
    plant(join(wt, target), marker);

    // The operator launches the approved artifact: the working tree is not an input.
    const sys = await (await loadLauncher(store, approved)).launchIsolatedSystem({ agentCwd: REPO_ROOT });
    try {
      const out = (await sys.runAgent(PROBE, ["buy", sys.paths.publicSocket, "weather"])).result as any;
      assert.equal(out.result.decision, "ALLOW");
      await settle();
      assert.equal(existsSync(marker), false, "agent code did not run");
    } finally {
      await sys.stop();
    }

    // Sealing the tampered tree yields a new digest and reports the change.
    const resealed = sealArtifact({ sourceRoot: wt, store });
    assert.notEqual(resealed.digest, approved);
    assert.deepEqual(resealed.changesFromApproved, { added: [], removed: [], changed: [target] });

    // The tampered artifact is refused before any of its code is imported.
    assert.throws(() => verifyArtifact(resealed.artifactRoot), /ARTIFACT_NOT_APPROVED/);
    const parent = runtimeParent();
    await assertLaunchRefused(
      () => loadLauncher(store, resealed.digest).then((l) => l.launchIsolatedSystem({ runtimeParent: parent })),
      /ARTIFACT_NOT_APPROVED/,
    );
    assert.deepEqual(readdirSync(parent), [], "no runtime root, no processes, no ledger");
    await settle();
    assert.equal(existsSync(marker), false, "agent code never ran as the operator");
  });
}

test("SI-03 agent modifies OxDeAI dependencies in node_modules: the sealed artifact is unaffected", opts, async () => {
  const wt = workingTree();
  const marker = join(wt, "MARKER");
  const core = join(wt, "node_modules/@oxdeai/core/dist/verification/verifyAuthorization.js");
  const guard = join(wt, "node_modules/@oxdeai/guard/dist/gateway.js");
  plant(core, marker);
  plant(guard, marker);
  const r = asAgent(`sed -i 's/if (verification.status !== "ok") {/if (false) {/' '${guard}'`);
  assert.equal(r.status, 0);

  const resealed = sealArtifact({ sourceRoot: wt, store });
  assert.equal(resealed.digest, approved, "dependencies come from the verified registry tarball, not the working tree");

  const sys = await (await loadLauncher(store, approved)).launchIsolatedSystem({ agentCwd: REPO_ROOT });
  try {
    const forged = (await sys.runAgent(PROBE, ["forge", sys.paths.publicSocket])).result as Record<string, any>;
    for (const v of Object.values(forged)) assert.equal(v.decision, "DENY", "signature verification intact");
    assert.equal(sys.ledger().length, 0);
    await settle();
    assert.equal(existsSync(marker), false);
  } finally {
    await sys.stop();
  }
});

test("SI-04 agent edits the lockfile to point at other dependency bytes: seal fails closed", opts, () => {
  for (const edit of ["s#sha512-Q569TNq[^\"]*#sha512-AAAA#", 's/"version": "2.0.2"/"version": "2.0.1"/']) {
    const wt = workingTree();
    const lock = join(wt, "package-lock.json");
    const before = readFileSync(lock, "utf8");
    assert.equal(asAgent(`sed -i '${edit}' '${lock}'`).status, 0);
    assert.notEqual(readFileSync(lock, "utf8"), before, "the agent's edit is on disk");
    assert.throws(() => sealArtifact({ sourceRoot: wt, store }), /SEAL_LOCKFILE_MISMATCH:@oxdeai\/core/);
  }
});

test("SI-05 agent cannot alter the trust store, the approval, the artifact, or the runtime configuration", opts, async () => {
  const art = join(store, "artifacts", approved);
  for (const target of [join(store, "approved"), join(art, "src/isolation/executor-main.ts"), join(art, "MANIFEST.json"), join(store, "artifacts", "new")]) {
    const r = asAgent(`printf x > '${target}'`);
    assert.notEqual(r.status, 0, `agent wrote ${target}`);
    assert.match(r.stderr, /Permission denied/);
  }
  const sys = await (await loadLauncher(store, approved)).launchIsolatedSystem({ agentCwd: REPO_ROOT });
  try {
    for (const cfg of [sys.paths.executorConfig, sys.paths.gatewayConfig]) {
      const r = asAgent(`printf '{}' > '${cfg}'`);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /Permission denied/);
    }
  } finally {
    await sys.stop();
  }
  verifyArtifact(art); // still intact
});

test("SI-06 misdeployed store the agent can write: tampering and mere writability are both refused before launch", opts, async () => {
  // (a) Store tree left agent-writable; the agent modifies a launched file.
  const s1 = newStore();
  cleanups.push(() => removeTree(s1));
  const d1 = sealArtifact({ sourceRoot: workingTree(), store: s1 }).digest;
  approveArtifact(d1, { store: s1 });
  spawnSync("chmod", ["-R", "a+rwX", s1]);
  const marker = join(s1, "MARKER");
  plant(join(s1, "artifacts", d1, "src/isolation/executor-main.ts"), marker);
  const parentA = runtimeParent();
  await assertLaunchRefused(
    () => loadLauncher(s1, d1).then((l) => l.launchIsolatedSystem({ runtimeParent: parentA })),
    /ARTIFACT_HASH_MISMATCH/,
  );
  assert.deepEqual(readdirSync(parentA), []);

  // (b) Content intact, but a non-sticky ancestor is agent-writable: the agent
  //     could swap the whole store. Detected by the kernel check as the agent.
  const exposed = mkdtempSync(join(tmpdir(), "oxdeai-exposed-"));
  chmodSync(exposed, 0o777);
  cleanups.push(() => removeTree(exposed));
  const s2 = join(exposed, "store");
  const d2 = sealArtifact({ sourceRoot: workingTree(), store: s2 }).digest;
  approveArtifact(d2, { store: s2 });
  const parentB = runtimeParent();
  await assertLaunchRefused(
    () => loadLauncher(s2, d2).then((l) => l.launchIsolatedSystem({ runtimeParent: parentB })),
    new RegExp(`ARTIFACT_AGENT_WRITABLE:${exposed}$`),
  );
  assert.deepEqual(readdirSync(parentB), []);
  await settle();
  assert.equal(existsSync(marker), false);
});

test("SI-07 launcher loaded from the working tree (not an approved artifact): refused, no fallback", opts, async () => {
  // Defence in depth: the launcher re-verifies the artifact it was loaded from.
  const parent = runtimeParent();
  await assertLaunchRefused(() => launchFromCheckout({ runtimeParent: parent }), /UNTRUSTED_LAUNCHER_LOCATION/);
  assert.deepEqual(readdirSync(parent), []);
  // And the entry refuses when no artifact is approved.
  const empty = newStore();
  cleanups.push(() => removeTree(empty));
  await assertLaunchRefused(() => loadLauncher(empty, approved).then((l) => l.launchIsolatedSystem()), /ARTIFACT_NO_APPROVAL/);
});

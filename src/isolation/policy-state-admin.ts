// SPDX-License-Identifier: MIT
/**
 * Operator administration of the persistent policy state (budget, velocity,
 * nonces, reservations) used by the authorization service.
 *
 * Policy state lives outside any deployment's runtime directory, under an
 * operator-provisioned state root, with its rollback anchor (Phase 2C; N3) in
 * a separate root next to it:
 *
 *   <stateRoot>/                   oxdeai-auth:oxdeai-auth 0700   (provisionStateRoot)
 *     <binding id>/                oxdeai-auth:oxdeai-auth 0700   (initPolicyState, once)
 *       state.json                 0600  {"format","binding","version","state","reservations"}
 *       writer.lock                flock(2) target; held by the running auth service
 *       decisions.jsonl            0600  decision audit log
 *   <stateRoot>.anchor/            root:root 0755                 (provisionStateRoot)
 *     <binding id>.log             oxdeai-auth 0600, append-only (chattr +a): hash-chained commits
 *
 * The binding id is a hash of (issuer, policy_id, policy_version, agent_id),
 * so a deployment with a different policy identity looks in a different
 * directory and finds no state: it refuses to start rather than reusing or
 * resetting another policy's budget.
 *
 * Every operation here is explicit, refuses rather than overwrites, and never
 * resets spending capacity:
 *   init      first time only (POLICY_STATE_EXISTS otherwise)
 *   migrate   format v1 -> v2: verified backup, deterministic and resumable
 *   restore   from a backup that the anchor proves was a real past state;
 *             spending is carried forward from the anchor head and open
 *             reservations are frozen as UNCERTAIN
 *   verify    state.json against the anchor
 * The operator runs them as itself, using sudo only for single file
 * primitives (install, mv, tee -a, chattr, flock). migrate and restore hold
 * the writer lock for their whole duration, so they refuse while an auth
 * service runs.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { nextEntry, parseAnchor, sha256, spentOf, type AnchorEntry, type AnchorLog } from "../authorization/policy-anchor.ts";
import { createInMemoryPolicyStateStore } from "../authorization/policy-state.ts";
import { initialStateFile, parseStateFile, stateFileBytes, type PolicyBinding } from "../authorization/policy-state-file.ts";
import { freezeForRestore } from "../authorization/reservations.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, initialPolicyState, PDP_ISSUER, POLICY, POLICY_VERSION } from "../system.ts";
import { identityOf } from "./identity.ts";

export type PolicySettings = { readonly ttlSeconds?: number };

/** The policy identity a deployment's authorization service will run with. */
export function policyBinding(settings: PolicySettings = {}): PolicyBinding {
  const authority = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: GATEWAY_AUDIENCE,
    agentId: AGENT_ID,
    ttlSeconds: settings.ttlSeconds ?? POLICY.ttlSeconds,
    stateStore: createInMemoryPolicyStateStore(undefined),
    now: () => Math.floor(Date.now() / 1000),
  }).trustMaterial.authority;
  return { issuer: authority.issuer, policyId: authority.policyId, policyVersion: POLICY_VERSION, agentId: AGENT_ID };
}

export function bindingId(b: PolicyBinding): string {
  return createHash("sha256").update(JSON.stringify([b.issuer, b.policyId, b.policyVersion, b.agentId])).digest("hex");
}

export function policyStateDir(stateRoot: string, b: PolicyBinding): string {
  return join(stateRoot, bindingId(b));
}

/** The anchor root lives next to the state root, never inside it. */
export function anchorRootOf(stateRoot: string): string {
  return join(dirname(stateRoot), `${basename(stateRoot)}.anchor`);
}

export function anchorPathOf(stateRoot: string, b: PolicyBinding): string {
  return join(anchorRootOf(stateRoot), `${bindingId(b)}.log`);
}

function sudo(args: readonly string[], input?: string): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("sudo", ["-n", ...args], { encoding: "utf8", input });
  return { status: r.status, stdout: r.stdout ?? "", stderr: (r.stderr ?? "").trim() };
}

function must(args: readonly string[], code: string, input?: string): string {
  const r = sudo(args, input);
  if (r.status !== 0) throw new Error(`${code}:${r.stderr}`);
  return r.stdout;
}

const exists = (p: string) => sudo(["test", "-e", p]).status === 0;

function authId() {
  const auth = identityOf("auth");
  if (!auth) throw new Error("IDENTITY_MISSING:oxdeai-auth");
  return auth;
}

/** Install `data` at `dest` as oxdeai-auth 0600 via a private operator staging file. */
function installAsAuth(dest: string, data: string, code: string): void {
  const auth = authId();
  const staging = mkdtempSync(join(tmpdir(), "oxdeai-admin-"));
  chmodSync(staging, 0o700);
  const tmp = join(staging, "f");
  try {
    writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
    chmodSync(tmp, 0o600);
    must(["install", "-o", String(auth.uid), "-g", String(auth.gid), "-m", "0600", tmp, dest], code);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

/** Atomically replace state.json: install to a temp name in the same directory, then rename. */
function replaceState(stateDir: string, data: string, code: string): void {
  const pending = join(stateDir, `state.json.admin-${randomBytes(4).toString("hex")}`);
  installAsAuth(pending, data, code);
  must(["mv", "-T", pending, join(stateDir, "state.json")], code);
  must(["sync", "-f", stateDir], code);
}

/** Append one anchor entry as root (works on an append-only file) and fsync it. */
function appendAnchorAsRoot(anchorPath: string, log: AnchorLog | undefined, body: Omit<AnchorEntry, "seq" | "prev" | "hash">, code: string): AnchorEntry {
  const { entry, text } = nextEntry(log, body);
  must(["tee", "-a", anchorPath], code, text);
  must(["sync", anchorPath], code);
  return entry;
}

function readAnchorAsRoot(anchorPath: string): AnchorLog {
  const r = sudo(["cat", anchorPath]);
  if (r.status !== 0) throw new Error(exists(anchorPath) ? `POLICY_ANCHOR_UNREADABLE:${r.stderr}` : "POLICY_ANCHOR_MISSING");
  return parseAnchor(r.stdout);
}

/** Create (or re-assert) the state root (oxdeai-auth 0700) and its anchor root (root 0755). Idempotent; never touches existing state. */
export function provisionStateRoot(stateRoot: string): void {
  const auth = authId();
  must(["install", "-d", "-o", String(auth.uid), "-g", String(auth.gid), "-m", "0700", stateRoot], "STATE_ROOT_PROVISION_FAILED");
  must(["install", "-d", "-o", "0", "-g", "0", "-m", "0755", anchorRootOf(stateRoot)], "STATE_ROOT_PROVISION_FAILED");
}

/** Create the empty anchor file (oxdeai-auth 0600), write its genesis PREPARE, and make it append-only. */
function createAnchor(anchorPath: string, genesis: Omit<AnchorEntry, "seq" | "prev" | "hash">, code: string): void {
  if (exists(anchorPath)) throw new Error(`POLICY_ANCHOR_EXISTS:${anchorPath}`);
  installAsAuth(anchorPath, "", code);
  appendAnchorAsRoot(anchorPath, undefined, genesis, code);
  must(["chattr", "+a", anchorPath], code);
}

/** Write `bytes` as the new state.json for an open PREPARE, then complete it with DONE (the commit protocol). */
function completePrepared(anchorPath: string, stateDir: string, bytes: string, code: string): void {
  replaceState(stateDir, bytes, code);
  const log = readAnchorAsRoot(anchorPath);
  const p = log.pending;
  if (!p || p.state_sha256 !== sha256(bytes)) throw new Error(`${code}:no matching PREPARE`);
  appendAnchorAsRoot(anchorPath, log, { kind: "DONE", version: p.version, state_sha256: p.state_sha256 }, code);
}

/**
 * First-time initialization of the policy state for one policy identity.
 * Throws POLICY_STATE_EXISTS if this binding was ever initialized under the root.
 */
export function initPolicyState(opts: { stateRoot: string; budget?: string; ttlSeconds?: number }): { binding: PolicyBinding; stateDir: string } {
  const binding = policyBinding({ ttlSeconds: opts.ttlSeconds });
  const stateDir = policyStateDir(opts.stateRoot, binding);
  const anchorPath = anchorPathOf(opts.stateRoot, binding);
  if (exists(anchorPath)) throw new Error(`POLICY_STATE_EXISTS:${anchorPath}`);

  // Atomic "first time" test: mkdir without -p fails if the directory exists.
  const mk = sudo(["mkdir", "-m", "0700", stateDir]);
  if (mk.status !== 0) {
    throw new Error(/exists/i.test(mk.stderr) ? `POLICY_STATE_EXISTS:${stateDir}` : `POLICY_STATE_INIT_FAILED:${mk.stderr}`);
  }
  const auth = authId();
  must(["chown", `${auth.uid}:${auth.gid}`, stateDir], "POLICY_STATE_INIT_FAILED");
  const state = initialPolicyState();
  if (opts.budget !== undefined) state.budget.budget_limit[binding.agentId] = BigInt(opts.budget);
  const bytes = initialStateFile(binding, state);
  // PREPARE first: a crash before state.json exists leaves a refusing, inspectable state
  // (POLICY_STATE_MISSING); a crash before DONE is completed by the auth service at startup.
  createAnchor(anchorPath, { kind: "PREPARE", op: "INIT", version: 0, state_sha256: sha256(bytes), spent: spentOf(state) }, "POLICY_STATE_INIT_FAILED");
  completePrepared(anchorPath, stateDir, bytes, "POLICY_STATE_INIT_FAILED");
  return { binding, stateDir };
}

/**
 * Hold the writer lock for an operator operation (refuses while an auth
 * service runs). The lock is held by a root `flock` process for the duration.
 */
async function withWriterLock<T>(lockPath: string, fn: () => T | Promise<T>): Promise<T> {
  // --close: the lock stays with flock itself (not the command); the command ends when we close its stdin.
  const holder: ChildProcess = spawn(
    "sudo",
    ["-n", "/usr/bin/flock", "--nonblock", "--close", "--conflict-exit-code", "75", lockPath, "/bin/sh", "-c", "read x"],
    { stdio: ["pipe", "ignore", "ignore"] },
  );
  const exited = new Promise<number | null>((r) => holder.once("exit", (c) => r(c)));
  // Held once a probe conflicts while our holder is still alive.
  for (let i = 0; i < 50; i++) {
    const early = await Promise.race([exited, new Promise<"running">((r) => setTimeout(() => r("running"), 100))]);
    if (early !== "running") throw new Error(early === 75 ? "POLICY_STATE_LOCKED:an auth service or another operation holds the writer lock" : `POLICY_STATE_LOCK_UNAVAILABLE:flock status ${early}`);
    if (sudo(["/usr/bin/flock", "--nonblock", "--conflict-exit-code", "75", lockPath, "/bin/true"]).status === 75) break;
    if (i === 49) throw new Error("POLICY_STATE_LOCK_UNAVAILABLE:timeout");
  }
  try {
    return await fn();
  } finally {
    // End the command; flock exits and the kernel releases the lock.
    holder.stdin!.end();
    await exited;
  }
}

export type MigrationResult = { status: "MIGRATED" | "ALREADY_MIGRATED"; stateDir: string; version: number; backup: string; state_sha256: string };

/**
 * Migrate format v1 state (Phase 2B-R3) to v2 (Phase 2C) for one policy
 * identity. Deterministic and resumable: the v2 bytes depend only on the v1
 * bytes, so an interrupted migration is completed by running it again.
 *   1. take the writer lock (refuses while auth runs);
 *   2. read and validate v1; save a verified backup next to it
 *      (state.json.v1-backup, byte-identical, hash checked after writing);
 *   3. build v2 = same budget state, version + 1, no reservations;
 *   4. create the anchor with a MIGRATE entry (from_sha256 = v1) and make it append-only;
 *   5. replace state.json with v2; read it back and check its hash and that it parses.
 * Fails closed at any step: the v1 file stays in place until step 5, and the
 * auth service refuses v1 (POLICY_STATE_MIGRATION_REQUIRED).
 */
export async function migratePolicyState(opts: { stateRoot: string; ttlSeconds?: number }): Promise<MigrationResult> {
  const binding = policyBinding({ ttlSeconds: opts.ttlSeconds });
  const stateDir = policyStateDir(opts.stateRoot, binding);
  const anchorPath = anchorPathOf(opts.stateRoot, binding);
  const statePath = join(stateDir, "state.json");
  const backup = join(stateDir, "state.json.v1-backup");
  if (!exists(anchorRootOf(opts.stateRoot))) throw new Error("POLICY_ANCHOR_ROOT_MISSING:run policy-cli provision first");
  return withWriterLock(join(stateDir, "writer.lock"), () => {
    const current = must(["cat", statePath], "POLICY_STATE_MISSING");
    const parsedNow = parseStateFile(current, binding, { allowV1: true });
    if (!JSON.parse(current).format.endsWith("/v1")) {
      // Already v2: only a completed migration is accepted (an open MIGRATE PREPARE is completed).
      const log = readAnchorAsRoot(anchorPath);
      if (log.pending?.op === "MIGRATE" && log.pending.state_sha256 === sha256(current)) {
        appendAnchorAsRoot(anchorPath, log, { kind: "DONE", version: log.pending.version, state_sha256: log.pending.state_sha256 }, "MIGRATION_ANCHOR_FAILED");
      } else if (log.head?.state_sha256 !== sha256(current)) throw new Error("POLICY_STATE_ANCHOR_MISMATCH:state is v2 but does not match the anchor");
      return { status: "ALREADY_MIGRATED", stateDir, version: parsedNow.version, backup, state_sha256: sha256(current) };
    }
    const v1 = current;
    const v1Sha = sha256(v1);
    // Verified backup (an existing one must be this exact v1).
    if (exists(backup)) {
      if (sha256(must(["cat", backup], "MIGRATION_BACKUP_UNREADABLE")) !== v1Sha) throw new Error("MIGRATION_BACKUP_CONFLICT:existing backup differs from state.json");
    } else {
      installAsAuth(backup, v1, "MIGRATION_BACKUP_FAILED");
      if (sha256(must(["cat", backup], "MIGRATION_BACKUP_UNREADABLE")) !== v1Sha) throw new Error("MIGRATION_BACKUP_VERIFY_FAILED");
    }
    const v2 = stateFileBytes({ binding, version: parsedNow.version + 1, state: parsedNow.state, reservations: {} });
    parseStateFile(v2, binding); // the result must be valid v2
    const genesis = { kind: "PREPARE" as const, op: "MIGRATE" as const, version: parsedNow.version + 1, state_sha256: sha256(v2), spent: spentOf(parsedNow.state), from_sha256: v1Sha };
    if (exists(anchorPath)) {
      // Resume: the anchor must be exactly this migration's open genesis.
      const log = readAnchorAsRoot(anchorPath);
      const g = log.entries[0]!;
      if (log.completed.length !== 0 || g.op !== "MIGRATE" || g.from_sha256 !== v1Sha || g.state_sha256 !== genesis.state_sha256 || log.pending?.seq !== g.seq) {
        throw new Error("MIGRATION_ANCHOR_CONFLICT:an anchor exists that is not this migration's");
      }
      must(["chattr", "+a", anchorPath], "MIGRATION_ANCHOR_FAILED");
    } else {
      createAnchor(anchorPath, genesis, "MIGRATION_ANCHOR_FAILED");
    }
    completePrepared(anchorPath, stateDir, v2, "MIGRATION_WRITE_FAILED");
    const readBack = must(["cat", statePath], "MIGRATION_VERIFY_FAILED");
    if (sha256(readBack) !== genesis.state_sha256) throw new Error("MIGRATION_VERIFY_FAILED:hash");
    parseStateFile(readBack, binding);
    return { status: "MIGRATED", stateDir, version: genesis.version, backup, state_sha256: genesis.state_sha256 };
  });
}

export type RestoreResult = { stateDir: string; version: number; carried_spent: Record<string, string>; frozen: number; state_sha256: string };

/**
 * Restore state.json from a backup file (operator-readable path).
 *   - The backup must be valid v2 state for this binding, and its exact hash
 *     must appear in the anchor as a state that really existed (not aborted).
 *     Anything else is refused: POLICY_RESTORE_UNVERIFIED.
 *   - Spending is carried forward: for each agent, max(backup, anchor head).
 *     A restore can never give back consumed capacity.
 *   - Reservations open in the backup are frozen as UNCERTAIN: they can only
 *     be closed by an operator-reconciled report, never released twice.
 *   - The result is a new version (head + 1), anchored as RESTORE before it
 *     is written; then read back and verified.
 */
export async function restorePolicyState(opts: { stateRoot: string; backupPath: string; ttlSeconds?: number; at?: number }): Promise<RestoreResult> {
  const binding = policyBinding({ ttlSeconds: opts.ttlSeconds });
  const stateDir = policyStateDir(opts.stateRoot, binding);
  const anchorPath = anchorPathOf(opts.stateRoot, binding);
  const backupRaw = readFileSync(opts.backupPath, "utf8");
  return withWriterLock(join(stateDir, "writer.lock"), () => {
    const backup = parseStateFile(backupRaw, binding);
    const log = readAnchorAsRoot(anchorPath);
    const backupSha = sha256(backupRaw);
    // Only a state that was durably completed (DONE) is a genuine past state.
    const genuine = log.completed.some((c) => c.state_sha256 === backupSha && c.version === backup.version);
    if (!genuine) throw new Error("POLICY_RESTORE_UNVERIFIED:the backup is not a completed state recorded in the anchor");
    if (log.pending) throw new Error("POLICY_RESTORE_REFUSED:the anchor has an open PREPARE; start and stop the auth service once to resolve it");
    const head = log.head!;
    const spent: Record<string, bigint> = {};
    const carried: Record<string, string> = {};
    for (const agent of new Set([...Object.keys(backup.state.budget.spent_in_period), ...Object.keys(head.spent)])) {
      const b = backup.state.budget.spent_in_period[agent] ?? 0n;
      const h = BigInt(head.spent[agent] ?? "0");
      spent[agent] = b > h ? b : h;
      carried[agent] = spent[agent]!.toString();
    }
    const at = opts.at ?? Math.floor(Date.now() / 1000);
    const reservations = freezeForRestore(backup.reservations, at);
    const frozen = Object.values(reservations).filter((r) => r.history.some((h) => h.reason === "RESTORED_FROM_BACKUP")).length;
    const restored = stateFileBytes({
      binding,
      version: head.version + 1,
      state: { ...backup.state, budget: { ...backup.state.budget, spent_in_period: spent } },
      reservations,
    });
    const sha = sha256(restored);
    appendAnchorAsRoot(anchorPath, log, { kind: "PREPARE", op: "RESTORE", version: head.version + 1, state_sha256: sha, spent: carried, from_sha256: backupSha }, "POLICY_RESTORE_FAILED");
    completePrepared(anchorPath, stateDir, restored, "POLICY_RESTORE_FAILED");
    const readBack = must(["cat", join(stateDir, "state.json")], "POLICY_RESTORE_VERIFY_FAILED");
    if (sha256(readBack) !== sha) throw new Error("POLICY_RESTORE_VERIFY_FAILED:hash");
    parseStateFile(readBack, binding);
    return { stateDir, version: head.version + 1, carried_spent: carried, frozen, state_sha256: sha };
  });
}

/** Check state.json against the anchor (read-only). */
export function verifyPolicyState(opts: { stateRoot: string; ttlSeconds?: number }) {
  const binding = policyBinding({ ttlSeconds: opts.ttlSeconds });
  const stateDir = policyStateDir(opts.stateRoot, binding);
  const anchorPath = anchorPathOf(opts.stateRoot, binding);
  const raw = must(["cat", join(stateDir, "state.json")], "POLICY_STATE_MISSING");
  const f = parseStateFile(raw, binding);
  const log = readAnchorAsRoot(anchorPath);
  const appendOnly = (sudo(["lsattr", "-d", anchorPath]).stdout.split(/\s+/)[0] ?? "").includes("a");
  const head = log.head!;
  return {
    stateDir,
    anchorPath,
    version: f.version,
    state_sha256: sha256(raw),
    anchor_head: { seq: head.seq, version: head.version, state_sha256: head.state_sha256 },
    pending: log.pending ? { seq: log.pending.seq, op: log.pending.op, version: log.pending.version } : null,
    matches: head.version === f.version && head.state_sha256 === sha256(raw),
    append_only: appendOnly,
    reservations: Object.values(f.reservations).reduce<Record<string, number>>((m, r) => ((m[r.state] = (m[r.state] ?? 0) + 1), m), {}),
  };
}

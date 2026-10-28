// SPDX-License-Identifier: MIT
/**
 * Durable policy state store for the authorization service process.
 *
 * Same contract as the in-memory store (`load` throws when unavailable,
 * `commit` is compare-and-set on `version`), persisted in an
 * operator-provisioned location that outlives any one deployment.
 *
 * Lifecycle (src/isolation/policy-state-admin.ts):
 *   - First-time initialization is a separate, explicit operator operation.
 *     It creates <stateRoot>/<binding id>/state.json exactly once.
 *   - `openFilePolicyStateStore` (normal startup) NEVER creates state. It
 *     refuses missing (POLICY_STATE_MISSING), unreadable
 *     (POLICY_STATE_UNREADABLE), corrupt (POLICY_STATE_CORRUPT), or
 *     foreign (POLICY_STATE_BINDING_MISMATCH) state, so a lost file can never
 *     silently restore spending capacity.
 *
 * Single writer: the launcher starts the service under flock(1), which takes
 * an exclusive kernel lock (flock(2)) on `lockPath` before the service starts
 * and passes the locked descriptor on. The kernel releases the lock when the
 * last holder exits, so there is no stale lock file to detect, delete, or
 * race on. `openFilePolicyStateStore` runs a startup self-check
 * (`assertWriterLockHeld`), but that check does not prove that this process
 * owns the lock (see there). The single-writer property holds only for
 * services started through the launcher's flock wrapper.
 *
 * File (0600, owned by the auth identity, in a 0700 directory):
 *   state.json  {"format", "binding", "version", "state"}; bigints as {"$bigint": "<decimal>"}
 * Each commit writes a temp file, fsyncs it, renames it over state.json, and
 * fsyncs the directory.
 */
import { spawnSync } from "node:child_process";
import { closeSync, fchmodSync, fsyncSync, openSync, readdirSync, readFileSync, readlinkSync, realpathSync, renameSync, writeSync } from "node:fs";
import { join } from "node:path";
import type { State } from "@oxdeai/core";
import type { PolicyStateStore, VersionedPolicyState } from "./policy-state.ts";

export const POLICY_STATE_FORMAT = "oxdeai-celo-poc/policy-state/v1";

/** What a policy state belongs to. Stored in the file and checked on every open. */
export type PolicyBinding = {
  readonly issuer: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly agentId: string;
};

type StateFile = { format: string; binding: PolicyBinding; version: number; state: State };

export const encodePolicyState = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x));
const decode = (s: string) =>
  JSON.parse(s, (_k, x) =>
    x && typeof x === "object" && !Array.isArray(x) && Object.keys(x).length === 1 && typeof x.$bigint === "string" ? BigInt(x.$bigint) : x,
  );

/** Serialized initial state file; written by the operator's init operation only. */
export function initialStateFile(binding: PolicyBinding, state: State): string {
  return encodePolicyState({ format: POLICY_STATE_FORMAT, binding, version: 0, state } satisfies StateFile);
}

function writeDurable(dir: string, name: string, data: string): void {
  const tmp = join(dir, `${name}.tmp-${process.pid}`);
  const fd = openSync(tmp, "w", 0o600);
  try {
    fchmodSync(fd, 0o600);
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, join(dir, name));
  const d = openSync(dir, "r");
  try {
    fsyncSync(d);
  } finally {
    closeSync(d);
  }
}

/**
 * Throws POLICY_STATE_LOCK_NOT_HELD unless this process has an open
 * descriptor on `lockPath` and some process currently holds an exclusive
 * flock on it (a non-blocking probe conflicts).
 *
 * This does NOT prove that this process holds the lock. A process that only
 * opened the lock file, without locking it, passes while another instance
 * holds the lock; the Phase 2B-R4 audit started a second writer this way
 * (N1). The check refuses an instance with no descriptor on the lock, or one
 * running while nobody holds it. Exclusive ownership is guaranteed only for
 * services started through the launcher's `flock --nonblock` wrapper, under
 * the assumption that no attacker can run code as oxdeai-auth. Verifying the
 * lock on the inherited descriptor itself is open hardening work.
 */
export function assertWriterLockHeld(lockPath: string): void {
  let real: string;
  try {
    real = realpathSync(lockPath);
  } catch {
    throw new Error("POLICY_STATE_LOCK_NOT_HELD:no lock file");
  }
  const ours = readdirSync("/proc/self/fd").some((fd) => {
    try {
      return readlinkSync(`/proc/self/fd/${fd}`) === real;
    } catch {
      return false;
    }
  });
  if (!ours) throw new Error("POLICY_STATE_LOCK_NOT_HELD:no inherited lock descriptor");
  const probe = spawnSync("/usr/bin/flock", ["--nonblock", "--conflict-exit-code", "75", lockPath, "/bin/true"], { timeout: 10_000 });
  if (probe.status !== 75) throw new Error(`POLICY_STATE_LOCK_NOT_HELD:probe status ${probe.status}`);
}

function sameBinding(a: PolicyBinding, b: PolicyBinding): boolean {
  return a.issuer === b.issuer && a.policyId === b.policyId && a.policyVersion === b.policyVersion && a.agentId === b.agentId;
}

function readStateFile(file: string, expected: PolicyBinding): StateFile {
  let raw: string;
  try {
    raw = readFileSync(file, "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new Error(code === "ENOENT" ? "POLICY_STATE_MISSING" : `POLICY_STATE_UNREADABLE:${code}`);
  }
  let parsed: Partial<StateFile>;
  try {
    parsed = decode(raw) as Partial<StateFile>;
  } catch {
    throw new Error("POLICY_STATE_CORRUPT");
  }
  if (
    parsed.format !== POLICY_STATE_FORMAT ||
    !Number.isSafeInteger(parsed.version) ||
    typeof parsed.state !== "object" ||
    parsed.state === null ||
    typeof parsed.binding !== "object" ||
    parsed.binding === null
  ) {
    throw new Error("POLICY_STATE_CORRUPT");
  }
  if (!sameBinding(parsed.binding, expected)) throw new Error("POLICY_STATE_BINDING_MISMATCH");
  return parsed as StateFile;
}

/**
 * Open existing, initialized policy state for writing. Never creates state.
 * Requires the writer lock (see `assertWriterLockHeld`).
 */
export function openFilePolicyStateStore(dir: string, opts: { binding: PolicyBinding; lockPath: string }): PolicyStateStore {
  assertWriterLockHeld(opts.lockPath);
  const file = join(dir, "state.json");
  readStateFile(file, opts.binding); // refuse to start on missing / unreadable / corrupt / foreign state

  const read = (): VersionedPolicyState => {
    const f = readStateFile(file, opts.binding);
    return { version: f.version, state: f.state };
  };
  return {
    async load() {
      return read();
    },
    async commit(next, expectedVersion) {
      // Synchronous read-compare-write: no interleaving inside this process.
      // No other writer process only if every writer was started under the
      // launcher's flock (N1); the read-then-rename is not atomic across processes.
      if (read().version !== expectedVersion) return false;
      writeDurable(dir, "state.json", encodePolicyState({ format: POLICY_STATE_FORMAT, binding: opts.binding, version: expectedVersion + 1, state: next }));
      return true;
    },
  };
}

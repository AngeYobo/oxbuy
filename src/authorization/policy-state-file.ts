// SPDX-License-Identifier: MIT
/**
 * Durable policy state store for the authorization service process.
 *
 * Same contract as the in-memory store (`load` throws when unavailable,
 * `commit` is compare-and-set on `version`), persisted in an
 * operator-provisioned location that outlives any one deployment.
 *
 * Lifecycle (src/isolation/policy-state-admin.ts):
 *   - First-time initialization, migration from format v1, and restore from
 *     a backup are separate, explicit operator operations.
 *   - `openFilePolicyStateStore` (normal startup) NEVER creates state. It
 *     refuses missing (POLICY_STATE_MISSING), unreadable
 *     (POLICY_STATE_UNREADABLE), corrupt (POLICY_STATE_CORRUPT), foreign
 *     (POLICY_STATE_BINDING_MISMATCH), old-format
 *     (POLICY_STATE_MIGRATION_REQUIRED), and rolled-back
 *     (POLICY_STATE_ROLLBACK) state, so a lost or restored file can never
 *     silently restore spending capacity.
 *
 * Single writer (Phase 2C; N1): the caller passes an ExclusiveLock it
 * acquired itself (src/durable/exclusive-lock.ts). Every load and commit
 * re-checks that this process still owns it.
 *
 * Rollback detection (Phase 2C; N3, CX1): every commit follows the
 * PREPARE / rename / DONE protocol of src/authorization/policy-anchor.ts, and
 * `commit` returns true (so the caller may release an authorization or
 * acknowledge a report) only after DONE is durable. Startup applies the
 * crash-state table there; every load checks the file against the anchor
 * head. See policy-anchor.ts for what this does and does not detect.
 *
 * File (0600, owned by the auth identity, in a 0700 directory):
 *   state.json  {"format", "binding", "version", "state", "reservations"}; bigints as {"$bigint": "<decimal>"}
 * Each commit: PREPARE (fsync) -> temp file (fsync) -> rename over state.json
 * -> fsync the directory -> DONE (fsync).
 */
import { readFileSync, renameSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import type { State } from "@oxdeai/core";
import { fsyncDir, writeTemp } from "../durable/durable-file.ts";
import type { ExclusiveLock } from "../durable/exclusive-lock.ts";
import { AnchorError, appendAnchor, isAppendOnly, readAnchor, reconcile, sha256, spentOf, type AnchorLog } from "./policy-anchor.ts";
import type { PolicyStateStore, VersionedPolicyState } from "./policy-state.ts";
import type { Reservations } from "./reservations.ts";

export const POLICY_STATE_FORMAT = "oxdeai-celo-poc/policy-state/v2";
export const POLICY_STATE_FORMAT_V1 = "oxdeai-celo-poc/policy-state/v1";

/** What a policy state belongs to. Stored in the file and checked on every open. */
export type PolicyBinding = {
  readonly issuer: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly agentId: string;
};

export type StateFile = { format: string; binding: PolicyBinding; version: number; state: State; reservations: Reservations };

export const encodePolicyState = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x));
export const decodePolicyState = (s: string) =>
  JSON.parse(s, (_k, x) =>
    x && typeof x === "object" && !Array.isArray(x) && Object.keys(x).length === 1 && typeof x.$bigint === "string" ? BigInt(x.$bigint) : x,
  );

/** Serialized state file (format v2). */
export function stateFileBytes(f: Omit<StateFile, "format">): string {
  return encodePolicyState({ format: POLICY_STATE_FORMAT, binding: f.binding, version: f.version, state: f.state, reservations: f.reservations } satisfies StateFile);
}

/** Serialized initial state file; written by the operator's init operation only. */
export function initialStateFile(binding: PolicyBinding, state: State): string {
  return stateFileBytes({ binding, version: 0, state, reservations: {} });
}

function sameBinding(a: PolicyBinding, b: PolicyBinding): boolean {
  return a.issuer === b.issuer && a.policyId === b.policyId && a.policyVersion === b.policyVersion && a.agentId === b.agentId;
}

/** Parse and validate state file bytes (any supported format). Throws POLICY_STATE_* codes. */
export function parseStateFile(raw: string, expected: PolicyBinding, opts: { allowV1?: boolean } = {}): StateFile {
  let parsed: Partial<StateFile>;
  try {
    parsed = decodePolicyState(raw) as Partial<StateFile>;
  } catch {
    throw new Error("POLICY_STATE_CORRUPT");
  }
  const v1 = parsed.format === POLICY_STATE_FORMAT_V1;
  if (
    (parsed.format !== POLICY_STATE_FORMAT && !v1) ||
    !Number.isSafeInteger(parsed.version) ||
    typeof parsed.state !== "object" ||
    parsed.state === null ||
    typeof parsed.binding !== "object" ||
    parsed.binding === null ||
    (!v1 && (typeof parsed.reservations !== "object" || parsed.reservations === null))
  ) {
    throw new Error("POLICY_STATE_CORRUPT");
  }
  if (!sameBinding(parsed.binding, expected)) throw new Error("POLICY_STATE_BINDING_MISMATCH");
  if (v1 && !opts.allowV1) throw new Error("POLICY_STATE_MIGRATION_REQUIRED");
  return (v1 ? { ...parsed, reservations: {} } : parsed) as StateFile;
}

function readBytes(file: string): string {
  try {
    return readFileSync(file, "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new Error(code === "ENOENT" ? "POLICY_STATE_MISSING" : `POLICY_STATE_UNREADABLE:${code}`);
  }
}

export type PolicyStateFaults = {
  /** SIGKILL after the anchor PREPARE append, before the new state is renamed into place. */
  readonly crashAfterPrepare?: boolean;
  /** SIGKILL after the rename, before the directory fsync. */
  readonly crashAfterRename?: boolean;
  /** SIGKILL after the directory fsync, before the anchor DONE append. */
  readonly crashAfterDirSync?: boolean;
  /** The DONE append fails (I/O error, no crash): the commit must not be confirmed. */
  readonly failDoneAppend?: boolean;
};

/**
 * Open existing, initialized policy state for writing. Never creates state.
 * Requires an owned writer lock and an append-only anchor that matches the
 * state file (crash-state table in policy-anchor.ts).
 */
export function openFilePolicyStateStore(
  dir: string,
  opts: { binding: PolicyBinding; lock: ExclusiveLock; anchorPath: string; requireAppendOnly?: boolean; faults?: PolicyStateFaults },
): PolicyStateStore {
  opts.lock.assertOwned();
  const file = join(dir, "state.json");
  // Refuse to start on missing / unreadable / corrupt / foreign / old-format state.
  const raw0 = readBytes(file);
  const f0 = parseStateFile(raw0, opts.binding);

  let log: AnchorLog;
  try {
    log = readAnchor(opts.anchorPath);
  } catch (err) {
    throw new Error(err instanceof AnchorError ? err.code : `POLICY_ANCHOR_UNREADABLE:${(err as Error).message}`);
  }
  if (opts.requireAppendOnly !== false && !isAppendOnly(opts.anchorPath)) throw new Error("POLICY_ANCHOR_NOT_APPEND_ONLY");
  if (log.tornTail !== undefined) {
    appendAnchor(opts.anchorPath, log, { kind: "ABORT", torn_sha256: sha256(log.tornTail) });
    log = readAnchor(opts.anchorPath);
  }
  const r = reconcile(log, { version: f0.version, state_sha256: sha256(raw0) });
  if (r.action === "REFUSE") throw new Error(r.reason);
  if (r.action === "COMPLETE_PENDING") {
    // Crash after the rename, before DONE: the state is in place; no authorization was released.
    appendAnchor(opts.anchorPath, log, { kind: "DONE", version: r.pending.version, state_sha256: r.pending.state_sha256 });
    log = readAnchor(opts.anchorPath);
  } else if (r.action === "ABORT_PENDING") {
    // Crash before the rename: that version never existed; no authorization was released.
    appendAnchor(opts.anchorPath, log, { kind: "ABORT", aborts: r.pending.seq });
    log = readAnchor(opts.anchorPath);
  }

  /** Set when a commit's outcome is not known (DONE not written): refuse everything until restart. */
  let broken: string | undefined;

  /** Current state; throws unless it is exactly the anchor head (detects replacement while running). */
  const read = (): VersionedPolicyState => {
    if (broken) throw new Error(`POLICY_STATE_UNCONFIRMED:${broken}`);
    opts.lock.assertOwned();
    const raw = readBytes(file);
    const f = parseStateFile(raw, opts.binding);
    const h = log.head;
    if (!h || f.version !== h.version || sha256(raw) !== h.state_sha256) {
      throw new Error(`POLICY_STATE_ROLLBACK:state version ${f.version} does not match anchor head ${h?.version ?? "none"}`);
    }
    return { version: f.version, state: f.state, reservations: f.reservations };
  };

  return {
    async load() {
      return read();
    },
    async commit(next, expectedVersion, reservations) {
      // Synchronous read-compare-write under an owned exclusive lock: no other
      // writer process, and no interleaving inside this one.
      const cur = read();
      if (cur.version !== expectedVersion) return false;
      const version = expectedVersion + 1;
      const bytes = stateFileBytes({ binding: opts.binding, version, state: next, reservations: reservations ?? cur.reservations });
      const sha = sha256(bytes);
      // 1. PREPARE (write-ahead).
      const prepared = appendAnchor(opts.anchorPath, log, { kind: "PREPARE", op: "COMMIT", version, state_sha256: sha, spent: spentOf(next) });
      log = readAnchor(opts.anchorPath);
      if (opts.faults?.crashAfterPrepare) process.kill(process.pid, "SIGKILL");
      // 2-4. temp + fsync, rename, directory fsync.
      try {
        const tmp = writeTemp(dir, bytes);
        try {
          renameSync(tmp, file);
        } catch (err) {
          unlinkSync(tmp);
          throw err;
        }
      } catch (err) {
        // Nothing replaced state.json: cancel the PREPARE, then fail closed for this request.
        try {
          appendAnchor(opts.anchorPath, log, { kind: "ABORT", aborts: prepared.seq });
          log = readAnchor(opts.anchorPath);
        } catch {
          broken = "PREPARE could not be aborted";
        }
        throw err;
      }
      if (opts.faults?.crashAfterRename) process.kill(process.pid, "SIGKILL");
      try {
        fsyncDir(dir);
        if (opts.faults?.crashAfterDirSync) process.kill(process.pid, "SIGKILL");
        if (opts.faults?.failDoneAppend) throw new Error("injected DONE append failure");
        // 5. DONE. Only after this may the caller release an authorization or acknowledge a report.
        appendAnchor(opts.anchorPath, log, { kind: "DONE", version, state_sha256: sha });
        log = readAnchor(opts.anchorPath);
      } catch (err) {
        // The new state may be in place without DONE: the caller must not release anything,
        // and this process must not continue; a restart applies the crash-state table.
        broken = `commit of version ${version} not confirmed: ${(err as Error).message}`;
        throw err;
      }
      return true;
    },
  };
}

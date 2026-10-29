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
 * Uncertain anchor writes (Phase 2D; L-1): any failure of an anchor append or
 * of the re-read after it leaves the anchor's content unknown to this process,
 * so the store refuses every further load and commit until a restart, which
 * applies the crash-state table (torn tail acknowledged, open PREPARE aborted
 * or completed). Independently, before every append the anchor is re-read and
 * its tip must be the tip this process last verified: no entry is ever
 * appended to a stale or unverified tip.
 *
 * Exact rebuild (Phase 2D; D2): every PREPARE carries the complete core state
 * of its version and the reservation records it changes (the full table when
 * the anchor has no coverage yet), so the anchor head can be rebuilt exactly
 * (`rebuildStateBytes`; policy-cli rebuild). At startup a covered anchor is
 * rebuilt and must hash to the head, or the store refuses to open.
 *
 * File (0600, owned by the auth identity, in a 0700 directory):
 *   state.json  {"format", "binding", "version", "state", "reservations", "quarantine_until"?}; bigints as {"$bigint": "<decimal>"}
 * Each commit: PREPARE (fsync) -> temp file (fsync) -> rename over state.json
 * -> fsync the directory -> DONE (fsync).
 */
import { appendFileSync, readFileSync, renameSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import type { State } from "@oxdeai/core";
import { fsyncDir, writeTemp } from "../durable/durable-file.ts";
import type { ExclusiveLock } from "../durable/exclusive-lock.ts";
import {
  AnchorError,
  appendAnchor,
  isAppendOnly,
  nextEntry,
  readAnchor,
  rebuildMaterial,
  reconcile,
  sha256,
  spentOf,
  type AnchorEntry,
  type AnchorLog,
  type AnchorPayload,
} from "./policy-anchor.ts";
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

export type StateFile = { format: string; binding: PolicyBinding; version: number; state: State; reservations: Reservations; quarantine_until?: number };

export const encodePolicyState = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x));
export const decodePolicyState = (s: string) =>
  JSON.parse(s, (_k, x) =>
    x && typeof x === "object" && !Array.isArray(x) && Object.keys(x).length === 1 && typeof x.$bigint === "string" ? BigInt(x.$bigint) : x,
  );

/** Serialized state file (format v2). */
export function stateFileBytes(f: Omit<StateFile, "format">): string {
  return encodePolicyState({
    format: POLICY_STATE_FORMAT,
    binding: f.binding,
    version: f.version,
    state: f.state,
    reservations: f.reservations,
    ...(f.quarantine_until !== undefined ? { quarantine_until: f.quarantine_until } : {}),
  } satisfies StateFile);
}

/** Anchor payload of a version (Phase 2D; D2): its core state, quarantine, and the given reservation records. */
export function anchorPayload(f: { state: State; quarantine_until?: number }, reservations: Reservations, full: boolean): AnchorPayload {
  const json = (v: unknown) => JSON.parse(encodePolicyState(v)) as unknown;
  return {
    state: json(f.state),
    reservations: json(reservations) as Record<string, unknown>,
    ...(full ? { full: true as const } : {}),
    ...(f.quarantine_until !== undefined ? { quarantine_until: f.quarantine_until } : {}),
  };
}

/**
 * The anchor head's state file, rebuilt from the anchor alone (Phase 2D; D2).
 * Throws POLICY_REBUILD_INCOMPLETE without coverage and POLICY_REBUILD_MISMATCH
 * unless the rebuilt bytes hash to the head.
 */
export function rebuildStateBytes(log: AnchorLog, binding: PolicyBinding): { bytes: string; version: number } {
  const m = rebuildMaterial(log);
  if (!m.covered) throw new Error(`POLICY_REBUILD_INCOMPLETE:${m.reason}`);
  const decode = (v: unknown) => decodePolicyState(JSON.stringify(v));
  const bytes = stateFileBytes({
    binding,
    version: m.version,
    state: decode(m.state) as State,
    reservations: decode(m.reservations) as Reservations,
    ...(m.quarantine_until !== undefined ? { quarantine_until: m.quarantine_until } : {}),
  });
  if (sha256(bytes) !== m.state_sha256) throw new Error(`POLICY_REBUILD_MISMATCH:rebuilt version ${m.version} does not hash to the anchor head`);
  return { bytes, version: m.version };
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
  /**
   * The PREPARE append fails (Phase 2D, L-1): "full" written then EIO, "torn" a
   * partial line then ENOSPC, "readback" written then the re-read fails. Fires
   * once, on the first commit.
   */
  readonly failPrepare?: "full" | "torn" | "readback";
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
  // Phase 2D (D2): a covered anchor must rebuild to exactly the head the state file matches.
  let covered = rebuildMaterial(log).covered;
  if (covered) {
    try {
      rebuildStateBytes(log, opts.binding);
    } catch (err) {
      throw new Error(`POLICY_ANCHOR_INCONSISTENT:${(err as Error).message}`);
    }
  }

  /** Set when the anchor's or a commit's outcome is not known: refuse everything until restart. */
  let broken: string | undefined;
  let prepareFault = opts.faults?.failPrepare;

  /**
   * Append one anchor entry and re-read the anchor, or mark the store broken.
   * The on-disk tip must still be the tip this process verified (stale-tip guard).
   */
  const append = (body: Parameters<typeof appendAnchor>[2], what: string): AnchorEntry => {
    let onDisk: AnchorLog;
    try {
      onDisk = readAnchor(opts.anchorPath);
    } catch (err) {
      broken = `anchor unreadable before ${what}: ${(err as Error).message}`;
      throw new Error(`POLICY_STATE_UNCONFIRMED:${broken}`);
    }
    if (onDisk.tip?.hash !== log.tip?.hash || onDisk.entries.length !== log.entries.length || onDisk.tornTail !== log.tornTail) {
      broken = `anchor tip changed under this process before ${what}`;
      throw new Error(`POLICY_STATE_UNCONFIRMED:${broken}`);
    }
    try {
      const fault = body.kind === "PREPARE" ? prepareFault : undefined;
      if (fault) prepareFault = undefined;
      let entry: AnchorEntry;
      if (fault === "torn") {
        const { text } = nextEntry(log, body);
        appendFileSync(opts.anchorPath, text.slice(0, Math.max(1, Math.floor(text.length / 3))));
        throw Object.assign(new Error("ENOSPC: injected short PREPARE write"), { code: "ENOSPC" });
      } else {
        entry = appendAnchor(opts.anchorPath, log, body);
      }
      if (fault === "full") throw Object.assign(new Error("EIO: injected after a complete PREPARE write"), { code: "EIO" });
      if (fault === "readback") throw Object.assign(new Error("EIO: injected anchor read-back failure"), { code: "EIO" });
      log = readAnchor(opts.anchorPath);
      if (log.tip?.hash !== entry.hash) throw new Error("anchor tip is not the entry just appended");
      return entry;
    } catch (err) {
      broken = `${what} outcome unknown: ${(err as Error).message}`;
      throw err;
    }
  };

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
    return { version: f.version, state: f.state, reservations: f.reservations, ...(f.quarantine_until !== undefined ? { quarantine_until: f.quarantine_until } : {}) };
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
      const nextReservations = reservations ?? cur.reservations;
      const q = cur.quarantine_until !== undefined ? { quarantine_until: cur.quarantine_until } : {};
      const bytes = stateFileBytes({ binding: opts.binding, version, state: next, reservations: nextReservations, ...q });
      const sha = sha256(bytes);
      // Payload: the reservation records this version changes, or all of them if the anchor has no coverage yet.
      const changed: Record<string, Reservations[string]> = {};
      for (const [id, r] of Object.entries(nextReservations)) {
        if (cur.reservations[id] === undefined || encodePolicyState(cur.reservations[id]) !== encodePolicyState(r)) changed[id] = r;
      }
      const payload = anchorPayload({ state: next, ...q }, covered ? changed : nextReservations, !covered);
      // 1. PREPARE (write-ahead). Any failure here marks the store broken (L-1).
      const prepared = append({ kind: "PREPARE", op: "COMMIT", version, state_sha256: sha, spent: spentOf(next), payload }, `PREPARE of version ${version}`);
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
          append({ kind: "ABORT", aborts: prepared.seq }, `ABORT of version ${version}`);
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
        append({ kind: "DONE", version, state_sha256: sha }, `DONE of version ${version}`);
        covered = true;
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

// SPDX-License-Identifier: MIT
/**
 * Policy-state rollback anchor (Phase 2C; N3, CX1).
 *
 * A hash-chained log of policy-state versions, kept OUTSIDE the state
 * directory, in an operator-provisioned anchor root (root-owned 0755), one
 * file per policy identity (owned by oxdeai-auth, 0600). The operator marks
 * each file append-only with `chattr +a`: the kernel then lets the auth
 * service only append; nobody, root included, can truncate, rewrite, rename,
 * or delete it without first removing the attribute (CAP_LINUX_IMMUTABLE).
 *
 * Entry kinds:
 *   PREPARE {op, version, state_sha256, spent, payload?}   a state version about to be written
 *           op: INIT | MIGRATE | RESTORE (operator) | COMMIT (auth service)
 *           payload (Phase 2D; D2): the complete core engine state of that version,
 *           its quarantine marker, and the reservation records it changes (all of them,
 *           `full`, for INIT / MIGRATE / RESTORE and for the first commit on an anchor
 *           without coverage). The chain hash authenticates it.
 *   DONE    {version, state_sha256, spent}       that version is durably in place
 *   ABORT   {aborts: seq}                        that PREPARE never took effect
 *           {torn_sha256}                         a torn final line (crash during an append)
 * Each entry: hash = sha256(prev || canonical entry without hash).
 *
 * Commit protocol (src/authorization/policy-state-file.ts):
 *   1 append PREPARE v+1 (fsync)   2 write temp state (fsync)   3 rename over state.json
 *   4 fsync directory              5 append DONE v+1 (fsync)    6 return; only then is an
 *                                                                  authorization (or a settle
 *                                                                  acknowledgement) released
 *
 * Crash-state transition table, applied at startup. "Head" is the latest DONE;
 * "pending" is a PREPARE after it that no ABORT cancelled:
 *
 *   crash point  anchor tail            state.json  action                          authorization issued?
 *   before 1     DONE v                 v           accept                          no
 *   1..3         DONE v, PREPARE v+1    v           ABORT pending, accept v         no: DONE was never written, so step 6 never ran
 *   3..5         DONE v, PREPARE v+1    v+1         append DONE v+1, accept v+1     no; its reservation stays charged (RESERVED) and is
 *                                                                                   released only by cancellation proven by its own
 *                                                                                   execution domain (src/executor/execution-domain.ts)
 *   5..6         DONE v+1               v+1         accept                          no; same as above
 *   (any)        DONE v+1               v or older  REFUSE POLICY_STATE_ROLLBACK    (stale state is never current)
 *   (any)        anything else                      REFUSE POLICY_STATE_ANCHOR_MISMATCH
 *
 * Dropping a pending PREPARE is safe ONLY because the implementation never
 * releases an authorization before DONE is durable (enforced in
 * policy-state-file.ts: `commit` returns true only after the DONE append; if
 * that append fails the store refuses all further use until restart). The
 * runtime check is stricter: while running, state.json must equal the head.
 *
 * Not protected (N3 stays CONDITIONAL; docs/ISOLATION.md): root or the
 * operator removing the attribute and rewriting both files; a rollback of the
 * whole filesystem or VM snapshot; loss of the anchor file (fails closed:
 * POLICY_ANCHOR_MISSING, never re-created automatically). A process crash is
 * tested; power loss (unflushed directory entries) is reasoned, not tested.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { appendDurable } from "../durable/durable-file.ts";

export type AnchorKind = "PREPARE" | "DONE" | "ABORT";
export type AnchorOp = "INIT" | "MIGRATE" | "RESTORE" | "COMMIT";

export type AnchorEntry = {
  readonly seq: number;
  readonly kind: AnchorKind;
  readonly op?: AnchorOp;
  readonly version?: number;
  readonly state_sha256?: string;
  /** Budget charged per agent at this version (decimal strings): carried forward on restore. */
  readonly spent?: Readonly<Record<string, string>>;
  readonly aborts?: number;
  readonly torn_sha256?: string;
  /** MIGRATE / RESTORE: sha256 of the source file. */
  readonly from_sha256?: string;
  /** Phase 2D (D2): enough to rebuild this version's state file exactly. */
  readonly payload?: AnchorPayload;
  readonly prev: string;
  readonly hash: string;
};

/**
 * Rebuild material of one version. `state` and `reservations` are JSON values
 * as written in the state file (bigints as {"$bigint": "<decimal>"}).
 */
export type AnchorPayload = {
  readonly state: unknown;
  readonly reservations: Readonly<Record<string, unknown>>;
  /** `reservations` is the complete table (else: only the records this version changed). */
  readonly full?: true;
  /** Issuance quarantine of this version (legacy restore), unix seconds. */
  readonly quarantine_until?: number;
};

/** A durably completed state version. */
export type AnchoredState = { readonly version: number; readonly state_sha256: string; readonly spent: Readonly<Record<string, string>>; readonly seq: number };

export const GENESIS = "0".repeat(64);
export const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

export function sealEntry(body: Omit<AnchorEntry, "hash">): AnchorEntry {
  return { ...body, hash: sha256(`${body.prev}${canonical(body)}`) };
}

export type AnchorLog = {
  readonly entries: readonly AnchorEntry[];
  /** The last valid entry (any kind); the chain tip for the next append. */
  readonly tip: AnchorEntry | undefined;
  /** The latest completed (DONE) state, if any. */
  readonly head: AnchoredState | undefined;
  /** A PREPARE after the head that no ABORT cancelled, if any. */
  readonly pending: AnchorEntry | undefined;
  /** Every completed state (DONE), oldest first: the only states a restore may come from. */
  readonly completed: readonly AnchoredState[];
  /** A final line that is not a complete entry (crash during append), if any. */
  readonly tornTail: string | undefined;
  /** The file does not end with a newline (crash between an entry and its newline). */
  readonly needsNewline: boolean;
};

export class AnchorError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "AnchorError";
  }
}

/** Parse and verify the whole chain. Throws POLICY_ANCHOR_MISSING / _UNREADABLE / _CORRUPT. */
export function readAnchor(path: string): AnchorLog {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new AnchorError(code === "ENOENT" ? "POLICY_ANCHOR_MISSING" : `POLICY_ANCHOR_UNREADABLE:${code}`);
  }
  return parseAnchor(raw);
}

/** Parse and verify anchor text. Throws POLICY_ANCHOR_CORRUPT. */
export function parseAnchor(raw: string): AnchorLog {
  const lines = raw.split("\n");
  const last = lines.pop(); // "" if the file ends with a newline
  const pendingLines: string[] = [...lines];
  if (last !== undefined && last !== "") pendingLines.push(last);
  const parse = (line: string): AnchorEntry | undefined => {
    try {
      return JSON.parse(line) as AnchorEntry;
    } catch {
      return undefined;
    }
  };
  const entries: AnchorEntry[] = [];
  let tornTail: string | undefined;
  /** Seqs of ABORT entries that acknowledge a torn line directly before them. */
  const tornAcks = new Set<number>();
  for (let i = 0; i < pendingLines.length; i++) {
    const line = pendingLines[i]!;
    const e = parse(line);
    if (!e) {
      // Only an incomplete final line is tolerated; a later ABORT must name it.
      if (i === pendingLines.length - 1) {
        tornTail = line;
        continue;
      }
      const next = parse(pendingLines[i + 1] ?? "");
      if (next?.kind === "ABORT" && next.torn_sha256 === sha256(line)) {
        tornAcks.add(entries.length);
        continue;
      }
      throw new AnchorError("POLICY_ANCHOR_CORRUPT:unparsable entry");
    }
    const prev = entries.length === 0 ? GENESIS : entries[entries.length - 1]!.hash;
    const { hash, ...body } = e;
    if (e.prev !== prev || e.seq !== entries.length || sealEntry(body).hash !== hash) {
      throw new AnchorError(`POLICY_ANCHOR_CORRUPT:chain broken at seq ${entries.length}`);
    }
    entries.push(e);
  }
  if (entries.length === 0) throw new AnchorError("POLICY_ANCHOR_CORRUPT:empty");
  const g = entries[0]!;
  if (g.kind !== "PREPARE" || (g.op !== "INIT" && g.op !== "MIGRATE")) throw new AnchorError("POLICY_ANCHOR_CORRUPT:no genesis");

  // Replay the protocol (CX3: strict version progression, independent of the appender's honesty):
  //   - the genesis PREPARE (INIT / MIGRATE) is the first entry and is never aborted;
  //   - every later PREPARE is a COMMIT or RESTORE for exactly the latest completed version + 1,
  //     and only when no PREPARE is open (an unfinished PREPARE cannot be bypassed);
  //   - DONE completes exactly the open PREPARE (same version and hash);
  //   - ABORT {aborts} cancels exactly the open PREPARE; ABORT {torn_sha256} only
  //     directly follows the torn line it names.
  const completed: AnchoredState[] = [];
  let open: AnchorEntry | undefined;
  for (const e of entries) {
    if (e.kind === "PREPARE") {
      if (open) throw new AnchorError(`POLICY_ANCHOR_CORRUPT:PREPARE ${e.seq} while ${open.seq} is open`);
      if (typeof e.version !== "number" || !Number.isSafeInteger(e.version) || e.version < 0 || typeof e.state_sha256 !== "string" || !e.op) {
        throw new AnchorError(`POLICY_ANCHOR_CORRUPT:PREPARE ${e.seq}`);
      }
      const head = completed[completed.length - 1];
      if (e.seq === 0) {
        // genesis: any non-negative version (MIGRATE continues the v1 numbering)
      } else if (e.op === "INIT" || e.op === "MIGRATE") {
        throw new AnchorError(`POLICY_ANCHOR_CORRUPT:PREPARE ${e.seq} ${e.op} after the genesis`);
      } else if (!head) {
        throw new AnchorError(`POLICY_ANCHOR_CORRUPT:PREPARE ${e.seq} before the genesis completed`);
      } else if (e.version !== head.version + 1) {
        throw new AnchorError(`POLICY_ANCHOR_CORRUPT:PREPARE ${e.seq} for version ${e.version}, expected ${head.version + 1}`);
      }
      open = e;
    } else if (e.kind === "DONE") {
      if (!open || open.version !== e.version || open.state_sha256 !== e.state_sha256) throw new AnchorError(`POLICY_ANCHOR_CORRUPT:DONE ${e.seq} without matching PREPARE`);
      completed.push({ version: e.version!, state_sha256: e.state_sha256!, spent: open.spent ?? {}, seq: e.seq });
      open = undefined;
    } else if (e.kind === "ABORT") {
      if (e.aborts !== undefined) {
        if (!open || open.seq !== e.aborts) throw new AnchorError(`POLICY_ANCHOR_CORRUPT:ABORT ${e.seq} of a PREPARE that is not open`);
        if (open.seq === 0) throw new AnchorError(`POLICY_ANCHOR_CORRUPT:ABORT ${e.seq} of the genesis`);
        open = undefined;
      } else if (e.torn_sha256 === undefined || !tornAcks.has(e.seq)) {
        throw new AnchorError(`POLICY_ANCHOR_CORRUPT:ABORT ${e.seq} does not follow the torn line it names`);
      }
    } else {
      throw new AnchorError(`POLICY_ANCHOR_CORRUPT:kind ${String(e.kind)}`);
    }
  }
  for (let i = 1; i < completed.length; i++) {
    if (completed[i]!.version <= completed[i - 1]!.version) throw new AnchorError("POLICY_ANCHOR_CORRUPT:versions not increasing");
  }
  return {
    entries,
    tip: entries[entries.length - 1],
    head: completed[completed.length - 1],
    pending: open,
    completed,
    tornTail,
    needsNewline: raw.length > 0 && !raw.endsWith("\n"),
  };
}

type Body = Omit<AnchorEntry, "seq" | "prev" | "hash">;

/** The next entry and the exact bytes to append for it (a missing newline is terminated first). */
export function nextEntry(log: AnchorLog | undefined, body: Body): { entry: AnchorEntry; text: string } {
  const tip = log?.tip;
  const entry = sealEntry({ ...body, seq: log ? log.entries.length : 0, prev: tip ? tip.hash : GENESIS } as Omit<AnchorEntry, "hash">);
  return { entry, text: `${log?.needsNewline ? "\n" : ""}${JSON.stringify(entry)}\n` };
}

export function appendAnchor(path: string, log: AnchorLog, body: Body): AnchorEntry {
  const { entry, text } = nextEntry(log, body);
  appendDurable(path, text, { chmod: false });
  return entry;
}

/** True if the kernel reports the append-only attribute on `path` (lsattr from e2fsprogs). */
export function isAppendOnly(path: string): boolean {
  const r = spawnSync("/usr/bin/lsattr", ["-d", path], { encoding: "utf8", timeout: 10_000 });
  if (r.status !== 0) return false;
  return (r.stdout.trim().split(/\s+/)[0] ?? "").includes("a");
}

/** Budget charged per agent, as decimal strings (the anchor's carried-forward fact). */
export function spentOf(state: { budget?: { spent_in_period?: Record<string, bigint | string | number> } }): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(state.budget?.spent_in_period ?? {})) out[k] = String(v);
  return out;
}

export type Reconciliation =
  | { readonly action: "ACCEPT" }
  | { readonly action: "COMPLETE_PENDING"; readonly pending: AnchorEntry }
  | { readonly action: "ABORT_PENDING"; readonly pending: AnchorEntry }
  | { readonly action: "REFUSE"; readonly reason: string };

/**
 * The crash-state transition table above, as a pure function of the anchor
 * and the state file. Enforces the version invariant itself (CX3), even for a
 * log that did not come from `parseAnchor`: a pending transition is completed
 * only if it is the genesis or exactly head + 1; anything else is refused.
 */
export function reconcile(log: AnchorLog, file: { version: number; state_sha256: string }): Reconciliation {
  const { head, pending } = log;
  if (pending !== undefined) {
    const valid =
      head === undefined
        ? pending.seq === 0 && (pending.op === "INIT" || pending.op === "MIGRATE")
        : pending.version === head.version + 1 && (pending.op === "COMMIT" || pending.op === "RESTORE");
    if (!valid) return { action: "REFUSE", reason: `POLICY_ANCHOR_INCONSISTENT:pending version ${pending.version}, head version ${head?.version ?? "none"}` };
  }
  if (head !== undefined && file.version < head.version) {
    return { action: "REFUSE", reason: `POLICY_STATE_ROLLBACK:state version ${file.version}, anchor head version ${head.version}` };
  }
  const isHead = head !== undefined && head.version === file.version && head.state_sha256 === file.state_sha256;
  const isPending = pending !== undefined && pending.version === file.version && pending.state_sha256 === file.state_sha256;
  if (isPending) return { action: "COMPLETE_PENDING", pending: pending! };
  if (isHead) return pending ? { action: "ABORT_PENDING", pending } : { action: "ACCEPT" };
  if (head !== undefined && (file.version < head.version || log.completed.some((c) => c.state_sha256 === file.state_sha256))) {
    return { action: "REFUSE", reason: `POLICY_STATE_ROLLBACK:state version ${file.version}, anchor head version ${head.version}` };
  }
  return { action: "REFUSE", reason: `POLICY_STATE_ANCHOR_MISMATCH:state version ${file.version}, anchor head version ${head?.version ?? "none"}` };
}

/**
 * The exact state of the anchor head, from the payloads of completed PREPAREs
 * (Phase 2D; D2): the head PREPARE's core state and quarantine, and the
 * reservation table folded from the last full table through every later
 * completed delta. Aborted and open PREPAREs are ignored. `covered` is false
 * when the head cannot be rebuilt (a completed PREPARE without a payload
 * after the last full table, or no full table at all).
 */
export type RebuildMaterial =
  | { readonly covered: true; readonly version: number; readonly state_sha256: string; readonly state: unknown; readonly reservations: Record<string, unknown>; readonly quarantine_until?: number }
  | { readonly covered: false; readonly reason: string };

export function rebuildMaterial(log: AnchorLog): RebuildMaterial {
  let table: Record<string, unknown> | undefined;
  let headPayload: AnchorPayload | undefined;
  let missing: string | undefined = "no full reservation table";
  let open: AnchorEntry | undefined;
  for (const e of log.entries) {
    if (e.kind === "PREPARE") open = e;
    else if (e.kind === "ABORT" && e.aborts !== undefined) open = undefined;
    else if (e.kind === "DONE" && open) {
      const p = open.payload;
      if (p === undefined || typeof p !== "object" || p === null || typeof p.reservations !== "object" || p.reservations === null) {
        table = undefined;
        headPayload = undefined;
        missing = `version ${open.version} has no payload`;
      } else if (p.full) {
        table = { ...p.reservations };
        headPayload = p;
        missing = undefined;
      } else if (table !== undefined) {
        table = { ...table, ...p.reservations };
        headPayload = p;
      } else {
        headPayload = undefined;
      }
      open = undefined;
    }
  }
  const head = log.head;
  if (!head) return { covered: false, reason: "no completed version" };
  if (table === undefined || headPayload === undefined || missing !== undefined) return { covered: false, reason: missing ?? "incomplete history" };
  return {
    covered: true,
    version: head.version,
    state_sha256: head.state_sha256,
    state: headPayload.state,
    reservations: table,
    ...(headPayload.quarantine_until !== undefined ? { quarantine_until: headPayload.quarantine_until } : {}),
  };
}

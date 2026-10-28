// SPDX-License-Identifier: MIT
/**
 * Payment journal: the executor's record of every intent handed to `pay`.
 *
 * States:
 *   STARTED                 reserved and about to call (or calling) `pay`;
 *   SETTLED                 `pay` returned a receipt that matched the binding;
 *   REFUSED_BEFORE_SIGNING  `pay` threw PaymentRefusedError (nothing signed);
 *   UNKNOWN                 `pay` was invoked and the outcome is not a
 *                           verified settlement.
 *
 * `reserve` is the only way to reach STARTED and it is atomic: it consumes the
 * auth_id and creates the intent record, or fails without calling `pay`. An
 * intent is never reserved twice. A record left in STARTED (for example by a
 * crash) stays STARTED: nothing here converts it to a definitive outcome. An
 * operator may attach a `resolution` to a STARTED or UNKNOWN record after
 * reconciling it out of band; the state itself is never rewritten.
 *
 * Two implementations:
 *   - `createInMemoryPaymentJournal`: in-process test harness only;
 *   - `openFilePaymentJournal`: durable, used by the executor process.
 *
 * File layout (directory mode 0700, files 0600, owned by the executor's OS
 * identity):
 *   executor.lock            single-writer lock, holds the writer's pid
 *   intents/<intent_hash>    one JSON record per intent, created O_EXCL
 *   auths/<sha256(auth_id)>  consumed auth_ids, created O_EXCL
 *   journal.log              append-only JSONL audit trail
 * Every record write is write-temp, fsync, rename, fsync(dir).
 */
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  closeSync,
  existsSync,
  fchmodSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import type { PurchaseRequest } from "../agent/purchase-request.ts";

export type PaymentJournalState = "STARTED" | "SETTLED" | "REFUSED_BEFORE_SIGNING" | "UNKNOWN";
export type PaymentJournalEntry = { readonly state: PaymentJournalState; readonly detail?: string };

export type Resolution = { readonly verdict: "SETTLED" | "NOT_SETTLED"; readonly note: string; readonly at: number };

export type PaymentJournalRecord = {
  readonly intent_hash: string;
  readonly auth_id: string;
  readonly state: PaymentJournalState;
  readonly detail?: string;
  readonly request: PurchaseRequest;
  readonly receipt?: unknown;
  readonly started_at: number;
  readonly updated_at: number;
  readonly resolution?: Resolution;
};

export type Reservation =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: "AUTH_REPLAY" }
  | { readonly ok: false; readonly reason: "DUPLICATE_INTENT"; readonly prior: PaymentJournalState };

export interface PaymentJournal {
  /**
   * Atomically consume `auth_id` and record the intent as STARTED. Synchronous
   * so two requests in one process cannot interleave. Throws on storage
   * failure; the caller must then not call `pay`.
   */
  reserve(entry: { intent_hash: string; auth_id: string; request: PurchaseRequest }): Reservation;
  /** STARTED -> final state. Throws on storage failure or an illegal transition. */
  record(intentHash: string, state: Exclude<PaymentJournalState, "STARTED">, detail?: string, receipt?: unknown): void;
  get(intentHash: string): PaymentJournalEntry | undefined;
  inspect(intentHash: string): PaymentJournalRecord | undefined;
  list(): PaymentJournalRecord[];
}

const INTENT_HASH = /^[0-9a-f]{64}$/;

function entryOf(r: PaymentJournalRecord): PaymentJournalEntry {
  return r.detail === undefined ? { state: r.state } : { state: r.state, detail: r.detail };
}

function finalRecord(
  prev: PaymentJournalRecord,
  state: Exclude<PaymentJournalState, "STARTED">,
  detail: string | undefined,
  receipt: unknown,
  at: number,
): PaymentJournalRecord {
  if (prev.state !== "STARTED") throw new Error(`JOURNAL_ILLEGAL_TRANSITION:${prev.state}->${state}`);
  const { detail: _d, receipt: _r, ...rest } = prev;
  return {
    ...rest,
    state,
    ...(detail !== undefined ? { detail } : {}),
    ...(receipt !== undefined ? { receipt } : {}),
    updated_at: at,
  };
}

/** In-process test harness only. Not durable. */
export function createInMemoryPaymentJournal(now: () => number = () => Math.floor(Date.now() / 1000)): PaymentJournal {
  const records = new Map<string, PaymentJournalRecord>();
  const auths = new Set<string>();
  return {
    reserve({ intent_hash, auth_id, request }) {
      const prior = records.get(intent_hash);
      if (prior) return { ok: false, reason: "DUPLICATE_INTENT", prior: prior.state };
      if (auths.has(auth_id)) return { ok: false, reason: "AUTH_REPLAY" };
      auths.add(auth_id);
      const at = now();
      records.set(intent_hash, { intent_hash, auth_id, state: "STARTED", request, started_at: at, updated_at: at });
      return { ok: true };
    },
    record(intentHash, state, detail, receipt) {
      const prev = records.get(intentHash);
      if (!prev) throw new Error("JOURNAL_NO_SUCH_INTENT");
      records.set(intentHash, finalRecord(prev, state, detail, receipt, now()));
    },
    get: (h) => {
      const r = records.get(h);
      return r && entryOf(r);
    },
    inspect: (h) => records.get(h),
    list: () => [...records.values()],
  };
}

// ── Durable file journal ───────────────────────────────────────────────────

function fsyncDir(dir: string): void {
  const fd = openSync(dir, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Create `path` exclusively with mode 0600 and durable contents. Throws EEXIST. */
function createExclusive(path: string, data: string): void {
  const fd = openSync(path, "wx", 0o600);
  try {
    // A default ACL on a parent directory overrides the open() mode.
    fchmodSync(fd, 0o600);
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function replaceDurable(path: string, data: string): void {
  const tmp = `${path}.tmp-${process.pid}`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    fchmodSync(fd, 0o600);
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

function privateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function isCode(err: unknown, code: string): boolean {
  return (err as NodeJS.ErrnoException | undefined)?.code === code;
}

function readRecord(path: string): PaymentJournalRecord {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as PaymentJournalRecord;
  } catch (err) {
    if (isCode(err, "ENOENT")) throw err;
    // An unreadable record is never treated as "not started".
    const hash = path.slice(-64);
    return {
      intent_hash: hash,
      auth_id: "",
      state: "UNKNOWN",
      detail: "JOURNAL_RECORD_UNREADABLE",
      request: undefined as never,
      started_at: 0,
      updated_at: 0,
    };
  }
}

function layout(dir: string) {
  return {
    lock: join(dir, "executor.lock"),
    intents: join(dir, "intents"),
    auths: join(dir, "auths"),
    log: join(dir, "journal.log"),
  };
}

function intentPath(dir: string, intentHash: string): string {
  if (!INTENT_HASH.test(intentHash)) throw new Error("JOURNAL_INVALID_INTENT_HASH");
  return join(layout(dir).intents, intentHash);
}

/** Lock-free read access, for operators. */
export function readFilePaymentJournal(dir: string): Pick<PaymentJournal, "get" | "inspect" | "list"> {
  const inspect = (h: string) => {
    try {
      return readRecord(intentPath(dir, h));
    } catch (err) {
      if (isCode(err, "ENOENT")) return undefined;
      throw err;
    }
  };
  return {
    inspect,
    get: (h) => {
      const r = inspect(h);
      return r && entryOf(r);
    },
    list: () => {
      const { intents } = layout(dir);
      if (!existsSync(intents)) return [];
      return readdirSync(intents)
        .filter((n) => INTENT_HASH.test(n))
        .sort()
        .map((n) => readRecord(join(intents, n)));
    },
  };
}

export type FilePaymentJournal = PaymentJournal & {
  /** Operator reconciliation of a STARTED or UNKNOWN record. */
  resolve(intentHash: string, verdict: Resolution["verdict"], note: string): PaymentJournalRecord;
  /** Records still STARTED or UNKNOWN with no resolution, found at open. */
  readonly needsReconciliation: readonly PaymentJournalRecord[];
  readonly staleLockRecovered: boolean;
  close(): void;
};

/**
 * Open the journal for writing. Takes the writer lock: fails with
 * JOURNAL_LOCKED if another live process holds it, and takes over a lock left
 * by a dead process (crash recovery). The takeover is check-then-delete, so
 * two processes racing on the same stale lock can both become writers
 * (observed in the Phase 2B-R4 audit; docs/ISOLATION.md B6). Per-intent
 * exclusivity then rests on the O_EXCL creation in `reserve`.
 */
export function openFilePaymentJournal(dir: string, opts: { now?: () => number } = {}): FilePaymentJournal {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const p = layout(dir);
  privateDir(dir);
  privateDir(p.intents);
  privateDir(p.auths);

  let staleLockRecovered = false;
  for (let attempt = 0; ; attempt++) {
    try {
      createExclusive(p.lock, String(process.pid));
      break;
    } catch (err) {
      if (!isCode(err, "EEXIST") || attempt > 0) throw new Error(`JOURNAL_LOCKED:${(err as Error).message}`);
      const holder = Number.parseInt(readFileSync(p.lock, "utf8"), 10);
      if (Number.isSafeInteger(holder) && holder > 0 && isAlive(holder)) throw new Error(`JOURNAL_LOCKED:pid ${holder}`);
      unlinkSync(p.lock);
      staleLockRecovered = true;
    }
  }
  fsyncDir(dir);

  function audit(event: Record<string, unknown>): void {
    const fd = openSync(p.log, "a", 0o600);
    try {
      fchmodSync(fd, 0o600);
      writeSync(fd, `${JSON.stringify({ at: now(), ...event })}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  const reader = readFilePaymentJournal(dir);
  if (staleLockRecovered) audit({ event: "STALE_LOCK_RECOVERED" });
  const needsReconciliation = reader
    .list()
    .filter((r) => (r.state === "STARTED" || r.state === "UNKNOWN") && r.resolution === undefined);
  audit({ event: "OPEN", pid: process.pid, needs_reconciliation: needsReconciliation.map((r) => r.intent_hash) });

  let closed = false;
  function writable(): void {
    if (closed) throw new Error("JOURNAL_CLOSED");
  }

  return {
    ...reader,
    needsReconciliation,
    staleLockRecovered,
    reserve({ intent_hash, auth_id, request }) {
      writable();
      const path = intentPath(dir, intent_hash);
      const existing = reader.inspect(intent_hash);
      if (existing) return { ok: false, reason: "DUPLICATE_INTENT", prior: existing.state };
      const authFile = join(p.auths, createHash("sha256").update(auth_id, "utf8").digest("hex"));
      try {
        createExclusive(authFile, JSON.stringify({ auth_id, intent_hash }));
      } catch (err) {
        if (isCode(err, "EEXIST")) return { ok: false, reason: "AUTH_REPLAY" };
        throw err;
      }
      fsyncDir(p.auths);
      const at = now();
      const record: PaymentJournalRecord = { intent_hash, auth_id, state: "STARTED", request, started_at: at, updated_at: at };
      try {
        createExclusive(path, JSON.stringify(record));
      } catch (err) {
        if (isCode(err, "EEXIST")) return { ok: false, reason: "DUPLICATE_INTENT", prior: reader.inspect(intent_hash)?.state ?? "UNKNOWN" };
        throw err;
      }
      fsyncDir(p.intents);
      audit({ event: "STARTED", intent_hash, auth_id });
      return { ok: true };
    },
    record(intentHash, state, detail, receipt) {
      writable();
      const prev = reader.inspect(intentHash);
      if (!prev) throw new Error("JOURNAL_NO_SUCH_INTENT");
      replaceDurable(intentPath(dir, intentHash), JSON.stringify(finalRecord(prev, state, detail, receipt, now())));
      fsyncDir(p.intents);
      audit({ event: state, intent_hash: intentHash, ...(detail !== undefined ? { detail } : {}) });
    },
    resolve(intentHash, verdict, note) {
      writable();
      const prev = reader.inspect(intentHash);
      if (!prev) throw new Error("JOURNAL_NO_SUCH_INTENT");
      if (prev.state !== "STARTED" && prev.state !== "UNKNOWN") throw new Error(`JOURNAL_NOT_RECONCILABLE:${prev.state}`);
      if (prev.resolution) throw new Error("JOURNAL_ALREADY_RESOLVED");
      const next: PaymentJournalRecord = { ...prev, resolution: { verdict, note, at: now() } };
      replaceDurable(intentPath(dir, intentHash), JSON.stringify(next));
      fsyncDir(p.intents);
      audit({ event: "RESOLVED", intent_hash: intentHash, verdict, note });
      return next;
    },
    close() {
      if (closed) return;
      closed = true;
      unlinkSync(p.lock);
    },
  };
}

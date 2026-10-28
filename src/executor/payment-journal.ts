// SPDX-License-Identifier: MIT
/**
 * Payment journal: the executor's record of every authorization it consumed
 * and every intent handed to `pay`.
 *
 * Per authorization (`auths/`), an immutable disposition, written once:
 *   RESERVED                   consumed for a payment attempt (an intent record follows);
 *   REJECTED_BEFORE_EXECUTION  authentic authorization refused by the executor's own
 *                              pre-payment checks; `pay` was never called;
 *   CANCELLED                  consumed unused at the authorization service's request
 *                              (e.g. expired or never delivered); `pay` was never called.
 * Once an auth_id is consumed it can never be used again (AUTH_REPLAY).
 *
 * Per intent (`intents/`), the payment state:
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
 * identity). Since Phase 2C the directory is persistent (outside any
 * deployment), created once by `initFilePaymentJournal`, and never created
 * implicitly:
 *   JOURNAL.json             format marker and immutable journal_id (execution domain,
 *                            src/executor/execution-domain.ts), written once at init
 *   journal.lock             flock(2) target (src/durable/exclusive-lock.ts)
 *   auths/<sha256(auth_id)>  per-authorization disposition, published with link(2)
 *   intents/<intent_hash>    one record per intent, published with link(2)
 *   acks/<sha256(auth_id)>.<outcome>  the auth service acknowledged that outcome report
 *   journal.log              append-only JSONL audit trail
 * Records are written with src/durable/durable-file.ts: a record is never
 * visible under its final name until it is complete and fsync'd.
 */
import { createHash, randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { appendDurable, createDurable, fsyncDir, isEexist, replaceDurable } from "../durable/durable-file.ts";
import { acquireExclusiveLock, LockError, type ExclusiveLock } from "../durable/exclusive-lock.ts";

export type PaymentJournalState = "STARTED" | "SETTLED" | "REFUSED_BEFORE_SIGNING" | "UNKNOWN";
export type PaymentJournalEntry = { readonly state: PaymentJournalState; readonly detail?: string };
export type AuthDisposition = "RESERVED" | "REJECTED_BEFORE_EXECUTION" | "CANCELLED";

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

export type AuthRecord = {
  readonly auth_id: string;
  readonly intent_hash: string;
  readonly disposition: AuthDisposition;
  readonly detail?: string;
  readonly at: number;
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
  /**
   * Consume `auth_id` without any payment (REJECTED_BEFORE_EXECUTION or
   * CANCELLED). Returns the auth's existing record if it was already consumed.
   */
  consume(entry: { auth_id: string; intent_hash: string; disposition: Exclude<AuthDisposition, "RESERVED">; detail?: string }): AuthRecord;
  /** STARTED -> final state. Throws on storage failure or an illegal transition. */
  record(intentHash: string, state: Exclude<PaymentJournalState, "STARTED">, detail?: string, receipt?: unknown): void;
  get(intentHash: string): PaymentJournalEntry | undefined;
  inspect(intentHash: string): PaymentJournalRecord | undefined;
  list(): PaymentJournalRecord[];
}

const INTENT_HASH = /^[0-9a-f]{64}$/;
export const JOURNAL_FORMAT = "oxdeai-celo-poc/payment-journal/v2";

const authKey = (authId: string) => createHash("sha256").update(authId, "utf8").digest("hex");

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
  const auths = new Map<string, AuthRecord>();
  return {
    reserve({ intent_hash, auth_id, request }) {
      const prior = records.get(intent_hash);
      if (prior) return { ok: false, reason: "DUPLICATE_INTENT", prior: prior.state };
      if (auths.has(auth_id)) return { ok: false, reason: "AUTH_REPLAY" };
      const at = now();
      auths.set(auth_id, { auth_id, intent_hash, disposition: "RESERVED", at });
      records.set(intent_hash, { intent_hash, auth_id, state: "STARTED", request, started_at: at, updated_at: at });
      return { ok: true };
    },
    consume({ auth_id, intent_hash, disposition, detail }) {
      const existing = auths.get(auth_id);
      if (existing) return existing;
      const rec: AuthRecord = { auth_id, intent_hash, disposition, ...(detail !== undefined ? { detail } : {}), at: now() };
      auths.set(auth_id, rec);
      return rec;
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

function isCode(err: unknown, code: string): boolean {
  return (err as NodeJS.ErrnoException | undefined)?.code === code;
}

/** A record that exists but cannot be parsed is UNKNOWN: never treated as absent or as a valid transaction. */
function readRecord(path: string): PaymentJournalRecord {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as PaymentJournalRecord;
  } catch (err) {
    if (isCode(err, "ENOENT")) throw err;
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
    marker: join(dir, "JOURNAL.json"),
    lock: join(dir, "journal.lock"),
    intents: join(dir, "intents"),
    auths: join(dir, "auths"),
    acks: join(dir, "acks"),
    log: join(dir, "journal.log"),
  };
}

function intentPath(dir: string, intentHash: string): string {
  if (!INTENT_HASH.test(intentHash)) throw new Error("JOURNAL_INVALID_INTENT_HASH");
  return join(layout(dir).intents, intentHash);
}

/**
 * Create a new, empty journal at `dir`. `dir` must not exist (mkdir without
 * -p is the atomic "first time" test): an existing journal is never
 * overwritten or reset. Throws JOURNAL_EXISTS otherwise.
 */
export function initFilePaymentJournal(dir: string): void {
  try {
    mkdirSync(dir, { mode: 0o700 });
  } catch (err) {
    if (isEexist(err)) throw new Error(`JOURNAL_EXISTS:${dir}`);
    throw err;
  }
  const p = layout(dir);
  for (const d of [p.intents, p.auths, p.acks]) mkdirSync(d, { mode: 0o700 });
  // The marker is written last: a directory without it is an interrupted init.
  createDurable(p.marker, `${JSON.stringify({ format: JOURNAL_FORMAT, journal_id: randomBytes(16).toString("hex") })}\n`);
  fsyncDir(dir);
}

/** The journal's immutable identity. Throws JOURNAL_MISSING / JOURNAL_CORRUPT. */
export function journalIdOf(dir: string): string {
  let marker: { format?: string; journal_id?: unknown };
  try {
    marker = JSON.parse(readFileSync(layout(dir).marker, "utf8")) as { format?: string; journal_id?: unknown };
  } catch (err) {
    throw new Error(isCode(err, "ENOENT") ? `JOURNAL_MISSING:${dir}` : `JOURNAL_CORRUPT:marker`);
  }
  if (marker.format !== JOURNAL_FORMAT) throw new Error(`JOURNAL_CORRUPT:format ${String(marker.format)}`);
  if (typeof marker.journal_id !== "string" || !/^[0-9a-f]{32}$/.test(marker.journal_id)) throw new Error("JOURNAL_CORRUPT:journal_id");
  return marker.journal_id;
}

/** Throws JOURNAL_MISSING / JOURNAL_CORRUPT unless `dir` is an initialized journal. */
function assertInitialized(dir: string): void {
  const p = layout(dir);
  journalIdOf(dir);
  for (const d of [p.intents, p.auths, p.acks]) {
    let ok = false;
    try {
      ok = lstatSync(d).isDirectory();
    } catch {
      ok = false;
    }
    if (!ok) throw new Error(`JOURNAL_CORRUPT:missing ${d}`);
  }
}

function readAuth(path: string): AuthRecord {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as AuthRecord;
  } catch (err) {
    if (isCode(err, "ENOENT")) throw err;
    // Unreadable: consumed, disposition unknown. Never released, never reused.
    return { auth_id: "", intent_hash: "", disposition: "RESERVED", detail: "JOURNAL_RECORD_UNREADABLE", at: 0 };
  }
}

/** Lock-free read access, for operators. */
export function readFilePaymentJournal(dir: string) {
  const p = layout(dir);
  const inspect = (h: string) => {
    try {
      return readRecord(intentPath(dir, h));
    } catch (err) {
      if (isCode(err, "ENOENT")) return undefined;
      throw err;
    }
  };
  const authOf = (authId: string): AuthRecord | undefined => {
    try {
      return readAuth(join(p.auths, authKey(authId)));
    } catch (err) {
      if (isCode(err, "ENOENT")) return undefined;
      throw err;
    }
  };
  return {
    inspect,
    get: (h: string) => {
      const r = inspect(h);
      return r && entryOf(r);
    },
    list: (): PaymentJournalRecord[] => {
      if (!existsSync(p.intents)) return [];
      return readdirSync(p.intents)
        .filter((n) => INTENT_HASH.test(n))
        .sort()
        .map((n) => readRecord(join(p.intents, n)));
    },
    auth: authOf,
    auths: (): AuthRecord[] => {
      if (!existsSync(p.auths)) return [];
      return readdirSync(p.auths)
        .filter((n) => INTENT_HASH.test(n))
        .sort()
        .map((n) => readAuth(join(p.auths, n)));
    },
    acked: (authId: string, outcome: string) => existsSync(join(p.acks, `${authKey(authId)}.${outcome}`)),
  };
}

export type FilePaymentJournal = PaymentJournal &
  ReturnType<typeof readFilePaymentJournal> & {
    /** Operator reconciliation of a STARTED or UNKNOWN record. */
    resolve(intentHash: string, verdict: Resolution["verdict"], note: string): PaymentJournalRecord;
    /** Durably note that the auth service acknowledged this outcome report. */
    ack(authId: string, outcome: string): void;
    /** Records still STARTED or UNKNOWN with no resolution, found at open. */
    readonly needsReconciliation: readonly PaymentJournalRecord[];
    /** Immutable journal identity (execution domain). */
    readonly journalId: string;
    close(): void;
  };

/**
 * Open an initialized journal for writing. Takes the exclusive writer lock
 * (JOURNAL_LOCKED if another process holds it). Never creates a journal:
 * a missing or damaged journal is JOURNAL_MISSING / JOURNAL_CORRUPT, so
 * financial history is never silently reset.
 */
export function openFilePaymentJournal(dir: string, opts: { now?: () => number; afterAuthRecord?: () => void } = {}): FilePaymentJournal {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const p = layout(dir);
  assertInitialized(dir);

  let lock: ExclusiveLock;
  try {
    lock = acquireExclusiveLock(p.lock);
  } catch (err) {
    if (err instanceof LockError && err.code === "LOCK_HELD") throw new Error(`JOURNAL_LOCKED:${p.lock}`);
    throw new Error(`JOURNAL_UNAVAILABLE:${(err as Error).message}`);
  }

  // Orphan temp files from an interrupted write are never records; remove them.
  for (const d of [p.intents, p.auths, p.acks]) {
    for (const n of readdirSync(d)) if (n.startsWith(".tmp-")) unlinkSync(join(d, n));
  }

  function audit(event: Record<string, unknown>): void {
    appendDurable(p.log, JSON.stringify({ at: now(), ...event }));
  }

  const reader = readFilePaymentJournal(dir);
  const needsReconciliation = reader
    .list()
    .filter((r) => (r.state === "STARTED" || r.state === "UNKNOWN") && r.resolution === undefined);
  audit({ event: "OPEN", pid: process.pid, needs_reconciliation: needsReconciliation.map((r) => r.intent_hash) });

  let closed = false;
  function writable(): void {
    if (closed) throw new Error("JOURNAL_CLOSED");
    lock.assertOwned();
  }

  return {
    ...reader,
    needsReconciliation,
    journalId: journalIdOf(dir),
    reserve({ intent_hash, auth_id, request }) {
      writable();
      const path = intentPath(dir, intent_hash);
      const existing = reader.inspect(intent_hash);
      if (existing) return { ok: false, reason: "DUPLICATE_INTENT", prior: existing.state };
      const at = now();
      try {
        createDurable(join(p.auths, authKey(auth_id)), JSON.stringify({ auth_id, intent_hash, disposition: "RESERVED", at } satisfies AuthRecord));
      } catch (err) {
        if (isEexist(err)) return { ok: false, reason: "AUTH_REPLAY" };
        throw err;
      }
      // A crash here leaves the auth consumed (RESERVED) with no intent record:
      // `pay` is only ever called after the STARTED record below is durable.
      opts.afterAuthRecord?.();
      const record: PaymentJournalRecord = { intent_hash, auth_id, state: "STARTED", request, started_at: at, updated_at: at };
      try {
        createDurable(path, JSON.stringify(record));
      } catch (err) {
        if (isEexist(err)) return { ok: false, reason: "DUPLICATE_INTENT", prior: reader.inspect(intent_hash)?.state ?? "UNKNOWN" };
        throw err;
      }
      audit({ event: "STARTED", intent_hash, auth_id });
      return { ok: true };
    },
    consume({ auth_id, intent_hash, disposition, detail }) {
      writable();
      const rec: AuthRecord = { auth_id, intent_hash, disposition, ...(detail !== undefined ? { detail } : {}), at: now() };
      try {
        createDurable(join(p.auths, authKey(auth_id)), JSON.stringify(rec));
      } catch (err) {
        if (isEexist(err)) return reader.auth(auth_id)!;
        throw err;
      }
      audit({ event: disposition, auth_id, intent_hash, ...(detail !== undefined ? { detail } : {}) });
      return rec;
    },
    record(intentHash, state, detail, receipt) {
      writable();
      const prev = reader.inspect(intentHash);
      if (!prev) throw new Error("JOURNAL_NO_SUCH_INTENT");
      replaceDurable(intentPath(dir, intentHash), JSON.stringify(finalRecord(prev, state, detail, receipt, now())));
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
      audit({ event: "RESOLVED", intent_hash: intentHash, verdict, note });
      return next;
    },
    ack(authId, outcome) {
      writable();
      try {
        createDurable(join(p.acks, `${authKey(authId)}.${outcome}`), JSON.stringify({ auth_id: authId, outcome, at: now() }));
      } catch (err) {
        if (!isEexist(err)) throw err;
      }
    },
    close() {
      if (closed) return;
      closed = true;
      lock.release();
    },
  };
}

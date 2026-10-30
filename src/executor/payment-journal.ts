// SPDX-License-Identifier: MIT
/**
 * Payment journal: the executor's record of every authorization it consumed
 * and every intent handed to `pay`.
 *
 * Per authorization (`auths/`), an immutable disposition, written once:
 *   RESERVED                   consumed for a payment attempt (an intent record follows);
 *   REJECTED_BEFORE_EXECUTION  authentic authorization refused by the executor's own
 *                              pre-payment checks; `pay` was never called;
 *   CANCELLED                  Phase 2C only (no longer written): consumed unused at the
 *                              authorization service's request; `pay` was never called.
 *                              Since Phase 2D the authorization service releases expired,
 *                              unclaimed reservations itself.
 * Once an auth_id is consumed it can never be used again (AUTH_REPLAY).
 *
 * Per intent (`intents/`), the payment state, with the execution claim id
 * (Phase 2D) sent to the authorization service for this attempt:
 *   STARTED                 reserved; the claim is being requested, or `pay` is (about to be) running;
 *   SETTLED                 `pay` returned a receipt that matched the binding;
 *   REFUSED_BEFORE_SIGNING  `pay` threw PaymentRefusedError (nothing signed);
 *   UNKNOWN                 `pay` was invoked and the outcome is not a
 *                           verified settlement;
 *   CLAIM_REFUSED           the authorization service refused the claim; `pay` was never called;
 *   CLAIM_ABANDONED         the claim's answer was lost or failed; this attempt will
 *                           never call `pay` (a positive record, written before giving up).
 *
 * `reserve` is the only way to reach STARTED and it is atomic: it consumes the
 * auth_id and creates the intent record, or fails without calling `pay`. An
 * intent is never reserved twice. A record left in STARTED (for example by a
 * crash) stays STARTED: nothing here converts it to a definitive outcome. An
 * operator may attach a `resolution` to a STARTED or UNKNOWN record, only
 * with verified settlement evidence (src/isolation/journal-cli.ts); the state
 * itself is never rewritten. There is no non-execution resolution: missing
 * evidence of a payment is not evidence of no payment.
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
import { validatePaymentBinding } from "./payment-binding.ts";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { appendDurable, createDurable, fsyncDir, isEexist, replaceDurable } from "../durable/durable-file.ts";
import { acquireExclusiveLock, LockError, type ExclusiveLock } from "../durable/exclusive-lock.ts";
import {
  appendCheckpoint,
  CheckpointError,
  compareJournal,
  EXECUTOR_ANCHOR_FORMAT,
  finalBody,
  loadCheckpointFor,
  type AnchorBody,
  type CheckpointState,
  type Discrepancy,
} from "./executor-anchor.ts";

export type PaymentJournalState = "STARTED" | "SETTLED" | "REFUSED_BEFORE_SIGNING" | "UNKNOWN" | "CLAIM_REFUSED" | "CLAIM_ABANDONED";
export type PaymentJournalEntry = { readonly state: PaymentJournalState; readonly detail?: string };
export type AuthDisposition = "RESERVED" | "REJECTED_BEFORE_EXECUTION" | "CANCELLED";

/**
 * Settlement evidence verified by the executor identity:
 *   MOCK_LEDGER_MAC   a MAC'd mock ledger entry (src/adapters/mock-buy/mock-settlement.ts);
 *   EIP3009_ONCHAIN   a mined receipt carrying this authorization's AuthorizationUsed + Transfer
 *                     (src/chain/eip3009-evidence.ts; x402 testnet integration).
 */
export type SettlementEvidence =
  | { readonly kind: "MOCK_LEDGER_MAC"; readonly reference: string; readonly mac: string; readonly amount: string }
  | import("../chain/eip3009-evidence.ts").OnchainSettlement;
export type Resolution = { readonly verdict: "SETTLED"; readonly amount: string; readonly evidence: SettlementEvidence; readonly note: string; readonly at: number };

export type PaymentBinding = {
  readonly intent_hash: string;
  readonly claim_id: string;
  readonly chain_id: string;
  readonly asset: string;
  readonly payer: string;
  readonly recipient: string;
  readonly amount: string;
  readonly nonce: string;
  readonly valid_after: string;
  readonly valid_before: string;
  readonly signature: string;
};

export type PaymentJournalRecord = {
  readonly intent_hash: string;
  readonly auth_id: string;
  /** Execution claim requested for this attempt (Phase 2D). Absent on legacy records. */
  readonly claim_id?: string;
  readonly state: PaymentJournalState;
  readonly detail?: string;
  readonly request: PurchaseRequest;
  readonly receipt?: unknown;
  readonly started_at: number;
  readonly updated_at: number;
  readonly resolution?: Resolution;
  readonly payment_binding?: PaymentBinding;
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
  bindPayment(intentHash: string, binding: PaymentBinding): void;
  /**
   * Atomically consume `auth_id` and record the intent as STARTED. Synchronous
   * so two requests in one process cannot interleave. Throws on storage
   * failure; the caller must then not call `pay`.
   */
  reserve(entry: { intent_hash: string; auth_id: string; request: PurchaseRequest; claim_id: string }): Reservation;
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
const sha256hex = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

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
    bindPayment(intentHash, binding) {
      const r = records.get(intentHash);
      if (!r || r.state !== "STARTED" || r.payment_binding) throw new Error("PAYMENT_BINDING_REFUSED");
      validatePaymentBinding(r, binding);
      records.set(intentHash, { ...r, payment_binding: structuredClone(binding) });
    },
    reserve({ intent_hash, auth_id, request, claim_id }) {
      const prior = records.get(intent_hash);
      if (prior) return { ok: false, reason: "DUPLICATE_INTENT", prior: prior.state };
      if (auths.has(auth_id)) return { ok: false, reason: "AUTH_REPLAY" };
      const at = now();
      auths.set(auth_id, { auth_id, intent_hash, disposition: "RESERVED", at });
      records.set(intent_hash, { intent_hash, auth_id, claim_id, state: "STARTED", request, started_at: at, updated_at: at });
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

/**
 * Executor consumption checkpoint (src/executor/executor-anchor.ts; AUD-02/03/04).
 *   normal   the checkpoint must be sealed for this journal; any fact it holds that the journal lacks
 *            is a journal rollback: open throws JOURNAL_ROLLBACK_DETECTED (fail closed)
 *   seal     an empty checkpoint is sealed for this journal (GENESIS + every current fact)
 *   recover  a detected rollback is tolerated so that `recoverFromCheckpoint` can re-import the lost facts
 */
export type CheckpointOptions = {
  readonly path: string;
  readonly mode?: "normal" | "seal" | "recover";
  /** Default true. False only for unit tests on filesystems without chattr. */
  readonly requireAppendOnly?: boolean;
  /** Fault injection: called after a journal write, before its checkpoint entry is appended. */
  readonly beforeAppend?: (body: AnchorBody) => void;
  /** Called once when a rollback is detected while running. */
  readonly onRollback?: (detail: string) => void;
};

export type FilePaymentJournal = PaymentJournal &
  ReturnType<typeof readFilePaymentJournal> & {
    /** Operator reconciliation of a STARTED or UNKNOWN record, with settlement evidence the caller verified. */
    resolve(intentHash: string, evidence: SettlementEvidence, note: string): PaymentJournalRecord;
    /** Durably note that the auth service acknowledged this outcome report. */
    ack(authId: string, outcome: string): void;
    /** Records still STARTED or UNKNOWN with no resolution, found at open. */
    readonly needsReconciliation: readonly PaymentJournalRecord[];
    /** Immutable journal identity (execution domain). */
    readonly journalId: string;
    /** Checkpoint facts the journal lacks, found at open (non-empty only in `recover` mode). */
    readonly rolledBack: readonly Discrepancy[];
    /** Re-import every fact the checkpoint holds and the journal lost (`recover` mode only). */
    recoverFromCheckpoint(note: string): { restored: string[] };
    close(): void;
  };

/**
 * Open an initialized journal for writing. Takes the exclusive writer lock
 * (JOURNAL_LOCKED if another process holds it). Never creates a journal:
 * a missing or damaged journal is JOURNAL_MISSING / JOURNAL_CORRUPT, so
 * financial history is never silently reset.
 */
export function openFilePaymentJournal(dir: string, opts: { now?: () => number; afterAuthRecord?: () => void; checkpoint: CheckpointOptions }): FilePaymentJournal {
  // 0007 (F-NOCK): there is no writable journal without its checkpoint; a writer that omitted it would
  // consume authorizations the checkpoint never sees, and bypass rollback detection and its lock.
  if (!opts?.checkpoint?.path) throw new Error("CHECKPOINT_REQUIRED:a writable journal is opened only with its consumption checkpoint");
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
  const journalId = journalIdOf(dir);

  // Checkpoint (AUD-02/03/04): verified before anything is served. On any failure every lock is released.
  const ck = opts.checkpoint;
  let cp: CheckpointState | undefined;
  let cpLock: ExclusiveLock | undefined;
  let rolledBack: Discrepancy[] = [];
  /** Set when the checkpoint's or the journal's state is not known any more: every write refused until restart. */
  let broken: string | undefined;
  {
    try {
      // 0007 (F-LOCK): the single-writer lock is ALSO taken on the checkpoint file itself. Unlike
      // journal.lock, it lives outside the journal's rollback domain and cannot be replaced, renamed or
      // unlinked (append-only), so a journal directory swapped under a running executor cannot admit a
      // second writer (a second executor, or journal-cli recover/resolve/seal).
      try {
        cpLock = acquireExclusiveLock(ck.path, { create: false });
      } catch (err) {
        if (err instanceof LockError && err.code === "LOCK_HELD") throw new CheckpointError("CHECKPOINT_LOCKED", ck.path);
        throw new CheckpointError((err as Error).message.includes("ENOENT") ? "CHECKPOINT_MISSING" : "CHECKPOINT_UNAVAILABLE", (err as Error).message);
      }
      const mode = ck.mode ?? "normal";
      cp = loadCheckpointFor(ck.path, journalId, { requireAppendOnly: ck.requireAppendOnly, allowUnsealed: mode === "seal" });
      if (mode === "seal") {
        if (cp.entries.length > 0) throw new CheckpointError("CHECKPOINT_ALREADY_SEALED", ck.path);
        // An interrupted seal left only torn lines (0007, F-TORN-GENESIS): the genesis acknowledges them.
        const prefix = cp.tornLines.map(sha256hex);
        cp = appendCheckpoint(ck.path, cp, { kind: "GENESIS", format: EXECUTOR_ANCHOR_FORMAT, journal_id: journalId, ...(prefix.length ? { torn_prefix: prefix } : {}) });
      }
      // One TORN acknowledges every torn line before it, also several from repeated crashes (0007, F-TORN2).
      if (cp.tornLines.length > 0) cp = appendCheckpoint(ck.path, cp, { kind: "TORN", torn_sha256s: cp.tornLines.map(sha256hex) });
      const view = { ...reader, journalId };
      const cmp = compareJournal(cp, view);
      rolledBack = cmp.rolledBack;
      if (rolledBack.length > 0 && mode !== "recover") {
        throw new CheckpointError(
          "JOURNAL_ROLLBACK_DETECTED",
          `${rolledBack.length} checkpointed fact(s) missing from the journal: ${rolledBack.slice(0, 5).map((d) => `${d.kind} ${d.id} (${d.detail})`).join("; ")}`,
        );
      }
      // Journal ahead of the checkpoint: a crash between the journal write and its checkpoint entry. Never acted on.
      if (rolledBack.length === 0) for (const b of cmp.catchUp) cp = appendCheckpoint(ck.path, cp, b);
    } catch (err) {
      cpLock?.release();
      lock.release();
      throw err;
    }
  }

  const needsReconciliation = reader
    .list()
    .filter((r) => (r.state === "STARTED" || r.state === "UNKNOWN") && r.resolution === undefined);
  audit({ event: "OPEN", pid: process.pid, needs_reconciliation: needsReconciliation.map((r) => r.intent_hash), ...(rolledBack.length ? { rolled_back: rolledBack } : {}) });

  let closed = false;
  function writable(): void {
    if (closed) throw new Error("JOURNAL_CLOSED");
    if (broken) throw new Error(`JOURNAL_UNAVAILABLE:${broken}`);
    if ((ck.mode ?? "normal") === "recover" && rolledBack.length > 0) throw new Error("JOURNAL_RECOVERY_REQUIRED");
    lock.assertOwned();
    cpLock!.assertOwned();
  }

  /** Append the checkpoint entry for a journal write that just completed; until it is durable nothing may act on it. */
  function checkpoint(body: AnchorBody): void {
    if (!cp) throw new Error("JOURNAL_CHECKPOINT_UNAVAILABLE:not loaded");
    try {
      ck.beforeAppend?.(body);
      cp = appendCheckpoint(ck.path, cp, body);
    } catch (err) {
      broken = `checkpoint append failed: ${(err as Error).message}`;
      throw new Error(`JOURNAL_CHECKPOINT_UNAVAILABLE:${(err as Error).message}`);
    }
  }

  /** A checkpointed consumption that the journal no longer holds can only come from a journal rollback while running. */
  function assertNotRolledBack(authId: string): void {
    if (!cp!.consumes.has(authId) || reader.auth(authId) !== undefined) return;
    broken = `journal rollback detected: auth ${authId} was consumed (checkpoint) but is absent from the journal`;
    ck?.onRollback?.(broken);
    throw new Error(`JOURNAL_ROLLBACK_DETECTED:${broken}`);
  }

  return {
    ...reader,
    needsReconciliation,
    journalId,
    get rolledBack() {
      return rolledBack;
    },
    recoverFromCheckpoint(note: string) {
      if (closed) throw new Error("JOURNAL_CLOSED");
      if (!cp || (ck.mode ?? "normal") !== "recover") throw new Error("JOURNAL_RECOVERY_NOT_ENABLED");
      if (broken) throw new Error(`JOURNAL_UNAVAILABLE:${broken}`);
      lock.assertOwned();
      cpLock!.assertOwned();
      const restored: string[] = [];
      const at = now();
      for (const c of cp.consumes.values()) {
        if (reader.auth(c.auth_id) === undefined) {
          createDurable(join(p.auths, authKey(c.auth_id)), JSON.stringify({ auth_id: c.auth_id, intent_hash: c.intent_hash, disposition: c.disposition, detail: "RECOVERED_FROM_CHECKPOINT", at } satisfies AuthRecord));
          restored.push(`auth ${c.auth_id} ${c.disposition}`);
        }
        const f = cp.finals.get(c.intent_hash);
        const request = c.request ?? f?.request;
        const claimId = c.claim_id ?? f?.claim_id;
        // 0007 (F-LEGACY): a legacy intent (no claim id) is rebuilt too, from the request the checkpoint keeps.
        if (c.disposition === "RESERVED" && request !== undefined && reader.inspect(c.intent_hash) === undefined) {
          const res = cp.resolved.get(c.intent_hash);
          // Without a checkpointed final state the outcome is unknown: the claim may have paid (D5: never NOT_EXECUTED).
          const rec: PaymentJournalRecord = {
            intent_hash: c.intent_hash,
            auth_id: c.auth_id,
            ...(claimId !== undefined ? { claim_id: claimId } : {}),
            state: f?.state ?? "UNKNOWN",
            detail: f?.detail ?? "RECOVERED_FROM_CHECKPOINT:outcome lost by a journal rollback; the payment may have executed",
            request,
            ...(f?.receipt !== undefined ? { receipt: f.receipt } : {}),
            started_at: at,
            updated_at: at,
            ...(res !== undefined ? { resolution: res.resolution } : {}),
          };
          createDurable(intentPath(dir, c.intent_hash), JSON.stringify(rec));
          restored.push(`intent ${c.intent_hash} ${rec.state}`);
        }
      }
      for (const f of cp.finals.values()) {
        const r = reader.inspect(f.intent_hash);
        if (r === undefined || r.detail === "JOURNAL_RECORD_UNREADABLE" || r.state === f.state) continue;
        if (r.state !== "STARTED") throw new Error(`CHECKPOINT_CONFLICT:intent ${f.intent_hash} is ${r.state} in the journal, ${f.state} in the checkpoint`);
        const { detail: _d, receipt: _r, ...rest } = r;
        replaceDurable(intentPath(dir, f.intent_hash), JSON.stringify({ ...rest, state: f.state, ...(f.detail !== undefined ? { detail: f.detail } : {}), ...(f.receipt !== undefined ? { receipt: f.receipt } : {}), updated_at: at }));
        restored.push(`intent ${f.intent_hash} STARTED->${f.state}`);
      }
      for (const b of cp.bindings.values()) {
        const r = reader.inspect(b.intent_hash);
        if (!r || r.detail === "JOURNAL_RECORD_UNREADABLE") throw new Error("PAYMENT_BINDING_RECOVERY_REFUSED");
        if (r.payment_binding && JSON.stringify(r.payment_binding) !== JSON.stringify(b.binding)) throw new Error("PAYMENT_BINDING_CONFLICT");
        validatePaymentBinding(r, b.binding);
        if (!r.payment_binding) {
          replaceDurable(intentPath(dir, b.intent_hash), JSON.stringify({ ...r, payment_binding: b.binding }));
          restored.push(`payment binding ${b.intent_hash}`);
        }
      }
      for (const res of cp.resolved.values()) {
        const r = reader.inspect(res.intent_hash);
        if (r === undefined || r.detail === "JOURNAL_RECORD_UNREADABLE" || r.resolution !== undefined) continue;
        replaceDurable(intentPath(dir, res.intent_hash), JSON.stringify({ ...r, resolution: res.resolution }));
        restored.push(`resolution ${res.intent_hash}`);
      }
      audit({ event: "RECOVERED_FROM_CHECKPOINT", note, restored });
      cp = appendCheckpoint(ck.path, cp, { kind: "RECOVERED", note, restored });
      const after = compareJournal(cp, { ...reader, journalId });
      if (after.rolledBack.length > 0) {
        broken = "recovery incomplete";
        throw new Error(`JOURNAL_RECOVERY_INCOMPLETE:${after.rolledBack.map((d) => `${d.kind} ${d.id}`).join("; ")}`);
      }
      for (const b of after.catchUp) cp = appendCheckpoint(ck.path, cp, b);
      rolledBack = [];
      return { restored };
    },
    bindPayment(intentHash, binding) {
      writable();
      const r = reader.inspect(intentHash);
      if (!r || r.state !== "STARTED" || r.payment_binding) throw new Error("PAYMENT_BINDING_REFUSED");
      validatePaymentBinding(r, binding);
      replaceDurable(intentPath(dir, intentHash), JSON.stringify({ ...r, payment_binding: binding }));
      checkpoint({ kind: "PAYMENT_BINDING", intent_hash: intentHash, binding });
    },
    reserve({ intent_hash, auth_id, request, claim_id }) {
      writable();
      const path = intentPath(dir, intent_hash);
      const existing = reader.inspect(intent_hash);
      if (existing) return { ok: false, reason: "DUPLICATE_INTENT", prior: existing.state };
      assertNotRolledBack(auth_id);
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
      const record: PaymentJournalRecord = { intent_hash, auth_id, claim_id, state: "STARTED", request, started_at: at, updated_at: at };
      try {
        createDurable(path, JSON.stringify(record));
      } catch (err) {
        if (isEexist(err)) {
          checkpoint({ kind: "CONSUME", auth_id, intent_hash, disposition: "RESERVED" });
          return { ok: false, reason: "DUPLICATE_INTENT", prior: reader.inspect(intent_hash)?.state ?? "UNKNOWN" };
        }
        throw err;
      }
      audit({ event: "STARTED", intent_hash, auth_id });
      // Durable outside the journal's rollback domain before the claim is requested or `pay` can run.
      checkpoint({ kind: "CONSUME", auth_id, intent_hash, disposition: "RESERVED", claim_id, request });
      return { ok: true };
    },
    consume({ auth_id, intent_hash, disposition, detail }) {
      writable();
      assertNotRolledBack(auth_id);
      const rec: AuthRecord = { auth_id, intent_hash, disposition, ...(detail !== undefined ? { detail } : {}), at: now() };
      try {
        createDurable(join(p.auths, authKey(auth_id)), JSON.stringify(rec));
      } catch (err) {
        if (isEexist(err)) return reader.auth(auth_id)!;
        throw err;
      }
      audit({ event: disposition, auth_id, intent_hash, ...(detail !== undefined ? { detail } : {}) });
      // Durable outside the journal's rollback domain before the rejection is answered or VOIDed (AUD-02).
      checkpoint({ kind: "CONSUME", auth_id, intent_hash, disposition });
      return rec;
    },
    record(intentHash, state, detail, receipt) {
      writable();
      const prev = reader.inspect(intentHash);
      if (!prev) throw new Error("JOURNAL_NO_SUCH_INTENT");
      const next = finalRecord(prev, state, detail, receipt, now());
      replaceDurable(intentPath(dir, intentHash), JSON.stringify(next));
      audit({ event: state, intent_hash: intentHash, ...(detail !== undefined ? { detail } : {}) });
      checkpoint(finalBody(next));
    },
    resolve(intentHash, evidence, note) {
      writable();
      const prev = reader.inspect(intentHash);
      if (!prev) throw new Error("JOURNAL_NO_SUCH_INTENT");
      if (prev.state !== "STARTED" && prev.state !== "UNKNOWN") throw new Error(`JOURNAL_NOT_RECONCILABLE:${prev.state}`);
      if (prev.resolution) throw new Error("JOURNAL_ALREADY_RESOLVED");
      if (evidence.kind === "EIP3009_ONCHAIN") {
        const b = prev.payment_binding;
        if (!b || !cp!.bindings.has(intentHash) || compareJournal(cp!, { ...reader, journalId }).rolledBack.length) throw new Error("PAYMENT_BINDING_REQUIRED");
        validatePaymentBinding(prev, b);
        if (evidence.amount !== b.amount || evidence.asset !== b.asset || evidence.payer !== b.payer ||
            evidence.pay_to !== b.recipient || evidence.nonce !== b.nonce || evidence.network !== `eip155:${b.chain_id}`) throw new Error("PAYMENT_BINDING_EVIDENCE_MISMATCH");
      }
      if (prev.claim_id === undefined) throw new Error("JOURNAL_NOT_RECONCILABLE:no claim");
      const next: PaymentJournalRecord = { ...prev, resolution: { verdict: "SETTLED", amount: evidence.amount, evidence, note, at: now() } };
      replaceDurable(intentPath(dir, intentHash), JSON.stringify(next));
      audit({ event: "RESOLVED", intent_hash: intentHash, verdict: "SETTLED", amount: evidence.amount, reference: evidence.reference, note });
      // The recovery decision is kept outside the journal's rollback domain (append-only, hash-chained).
      checkpoint({ kind: "RESOLVED", intent_hash: intentHash, resolution: next.resolution! });
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
      cpLock?.release();
      lock.release();
    },
  };
}

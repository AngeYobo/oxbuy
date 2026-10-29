// SPDX-License-Identifier: MIT
/**
 * Executor consumption checkpoint (Phase 2D remediation of AUD-02 / AUD-03 / AUD-04).
 *
 * Why it exists. The payment journal lives inside the executor state root,
 * which an operator may restore from a snapshot (supported recovery model).
 * Every fact the journal holds is then rolled back with it, including the
 * consumption of an authorization the executor rejected or abandoned while
 * the authorization service was unreachable (its VOID never arrived). The
 * authorization service cannot record what it never received, so a fact that
 * must survive a journal restore needs a store OUTSIDE the journal's rollback
 * domain. A hash chain inside the journal would be restored together with it.
 *
 * What it is. One append-only, hash-chained JSONL file per journal:
 *
 *   <executorStateRoot>.anchor/                 root 0755   (provisionExecutorStateRoot)
 *     <journal_id>.log                          oxdeai-executor 0600, chattr +a
 *
 * Same trust model as the policy anchor (src/authorization/policy-anchor.ts):
 * the kernel lets the executor only append; truncating, rewriting, renaming
 * or deleting it needs CAP_LINUX_IMMUTABLE (root), which is outside the
 * supported model. Restoring the executor state root does not touch it.
 *
 * Entries (each: seq, prev, hash = sha256(prev || canonical entry without hash)):
 *   GENESIS   {format, journal_id, torn_prefix?}        first entry; binds the file to one journal (domain);
 *                                                       torn_prefix acknowledges torn lines left by an interrupted seal
 *   CONSUME   {auth_id, intent_hash, disposition, claim_id?, request?}
 *                                                       an auth_id consumed by the journal (reserve or reject)
 *   FINAL     {intent_hash, auth_id, state, detail?, receipt?}   an intent left STARTED for a final state
 *   RESOLVED  {intent_hash, resolution}                 an operator settlement resolution (D5 evidence)
 *   TORN      {torn_sha256s}                            acknowledges the torn line(s) directly before it (a crash
 *                                                       during an append, possibly repeated: 0007, F-TORN2)
 *   RECOVERED {note, restored}                          an operator recovery re-imported lost journal records
 *
 * Ordering rule (enforced by payment-journal.ts): the journal record is
 * written first, the checkpoint entry second, and only then does the
 * executor act on it (claim / pay / answer the rejection). Hence:
 *   - checkpoint ⊆ journal in normal operation; anything the checkpoint holds
 *     that the journal lacks (or holds in an earlier state) can only come
 *     from a journal rollback => ROLLBACK DETECTED, fail closed;
 *   - journal ⊄ checkpoint only after a crash between the two writes; those
 *     records were never acted on and are appended at the next open (catch-up).
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { appendDurable } from "../durable/durable-file.ts";
import { isAppendOnly } from "../authorization/policy-anchor.ts";
import type { AuthDisposition, PaymentJournalRecord, PaymentJournalState, Resolution } from "./payment-journal.ts";

export const EXECUTOR_ANCHOR_FORMAT = "oxdeai-celo-poc/executor-anchor/v1";
const GENESIS_PREV = "0".repeat(64);

/** `<executorStateRoot>.anchor`, for a journal at `<executorStateRoot>/journal`. */
export const executorAnchorRootFor = (journalDir: string) => `${dirname(journalDir)}.anchor`;
export const executorAnchorPathFor = (journalDir: string, journalId: string) => join(executorAnchorRootFor(journalDir), `${journalId}.log`);

export type AnchorBody =
  | { kind: "GENESIS"; format: string; journal_id: string; torn_prefix?: readonly string[] }
  | { kind: "CONSUME"; auth_id: string; intent_hash: string; disposition: AuthDisposition; claim_id?: string; request?: PurchaseRequest }
  | {
      kind: "FINAL";
      intent_hash: string;
      auth_id: string;
      state: Exclude<PaymentJournalState, "STARTED">;
      detail?: string;
      receipt?: unknown;
      /** 0007 (F-LEGACY): enough to rebuild the intent record even without a CONSUME request. */
      claim_id?: string;
      request?: PurchaseRequest;
    }
  | { kind: "RESOLVED"; intent_hash: string; resolution: Resolution }
  | { kind: "TORN"; torn_sha256?: string; torn_sha256s?: readonly string[] }
  | { kind: "RECOVERED"; note: string; restored: readonly string[] };
export type AnchorEntry = AnchorBody & { readonly seq: number; readonly prev: string; readonly hash: string };

export class CheckpointError extends Error {
  readonly code: string;
  constructor(code: string, detail = "") {
    super(detail ? `${code}:${detail}` : code);
    this.code = code;
    this.name = "CheckpointError";
  }
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
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
const seal = (body: Omit<AnchorEntry, "hash">): AnchorEntry => ({ ...body, hash: sha256(`${body.prev}${canonical(body)}`) }) as AnchorEntry;

/** Facts folded from a verified checkpoint. */
export type CheckpointState = {
  readonly entries: readonly AnchorEntry[];
  readonly tip: AnchorEntry | undefined;
  readonly journalId: string | undefined;
  readonly consumes: ReadonlyMap<string, Extract<AnchorEntry, { kind: "CONSUME" }>>;
  readonly finals: ReadonlyMap<string, Extract<AnchorEntry, { kind: "FINAL" }>>;
  readonly resolved: ReadonlyMap<string, Extract<AnchorEntry, { kind: "RESOLVED" }>>;
  /** Unacknowledged torn line(s) at the end of the file (a crash during an append), oldest first. */
  readonly tornLines: readonly string[];
  readonly needsNewline: boolean;
};

/** Parse and verify checkpoint text. Throws CHECKPOINT_CORRUPT. An empty text is an unsealed checkpoint. */
export function parseCheckpoint(raw: string): CheckpointState {
  const lines = raw.split("\n");
  const last = lines.pop();
  if (last !== undefined && last !== "") lines.push(last);
  const entries: AnchorEntry[] = [];
  const parse = (l: string): AnchorEntry | undefined => {
    try {
      const e = JSON.parse(l) as AnchorEntry;
      return typeof e === "object" && e !== null && typeof (e as { kind?: unknown }).kind === "string" ? e : undefined;
    } catch {
      return undefined;
    }
  };
  const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x, k) => x === b[k]);
  // Consecutive unparsable lines are torn appends. They are tolerated only at the end of the file, or when the
  // very next entry acknowledges exactly them: a TORN (after the genesis) or the GENESIS (interrupted seal).
  let pending: string[] = [];
  for (const line of lines) {
    const e = parse(line);
    if (!e) {
      pending.push(line);
      continue;
    }
    if (pending.length > 0) {
      const shas = pending.map(sha256);
      const ack =
        e.kind === "TORN" ? (e.torn_sha256s ?? (e.torn_sha256 !== undefined ? [e.torn_sha256] : [])) : e.kind === "GENESIS" && entries.length === 0 ? (e.torn_prefix ?? []) : [];
      if (!same(ack, shas)) throw new CheckpointError("CHECKPOINT_CORRUPT", "unparsable entry");
    } else if ((e.kind === "TORN" && entries.length > 0) || (e.kind === "GENESIS" && (e.torn_prefix ?? []).length > 0)) {
      throw new CheckpointError("CHECKPOINT_CORRUPT", `${e.kind} ${entries.length} does not follow the torn line(s) it names`);
    }
    const prev = entries.length === 0 ? GENESIS_PREV : entries[entries.length - 1]!.hash;
    const { hash, ...body } = e;
    if (e.prev !== prev || e.seq !== entries.length || seal(body).hash !== hash) throw new CheckpointError("CHECKPOINT_CORRUPT", `chain broken at seq ${entries.length}`);
    entries.push(e);
    pending = [];
  }
  const consumes = new Map<string, Extract<AnchorEntry, { kind: "CONSUME" }>>();
  const finals = new Map<string, Extract<AnchorEntry, { kind: "FINAL" }>>();
  const resolved = new Map<string, Extract<AnchorEntry, { kind: "RESOLVED" }>>();
  let journalId: string | undefined;
  entries.forEach((e, i) => {
    if (i === 0) {
      if (e.kind !== "GENESIS" || e.format !== EXECUTOR_ANCHOR_FORMAT || !/^[0-9a-f]{32}$/.test(e.journal_id)) throw new CheckpointError("CHECKPOINT_CORRUPT", "no genesis");
      journalId = e.journal_id;
      return;
    }
    if (e.kind === "GENESIS") throw new CheckpointError("CHECKPOINT_CORRUPT", `second genesis at seq ${e.seq}`);
    if (e.kind === "CONSUME") consumes.set(e.auth_id, e);
    else if (e.kind === "FINAL") finals.set(e.intent_hash, e);
    else if (e.kind === "RESOLVED") resolved.set(e.intent_hash, e);
  });
  return { entries, tip: entries.at(-1), journalId, consumes, finals, resolved, tornLines: pending, needsNewline: raw.length > 0 && !raw.endsWith("\n") };
}

/** Read the checkpoint file. Throws CHECKPOINT_MISSING / CHECKPOINT_UNREADABLE / CHECKPOINT_CORRUPT. */
export function readCheckpoint(path: string): CheckpointState {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new CheckpointError(code === "ENOENT" ? "CHECKPOINT_MISSING" : "CHECKPOINT_UNREADABLE", `${path} ${code ?? ""}`.trim());
  }
  return parseCheckpoint(raw);
}

/** The exact bytes to append for `body` after `state` (a missing newline is terminated first). */
export function nextCheckpointEntry(state: CheckpointState, body: AnchorBody): { entry: AnchorEntry; text: string } {
  const entry = seal({ ...body, seq: state.entries.length, prev: state.tip?.hash ?? GENESIS_PREV } as Omit<AnchorEntry, "hash">);
  return { entry, text: `${state.needsNewline ? "\n" : ""}${JSON.stringify(entry)}\n` };
}

/** Append one entry (fsync'd) and return the re-read state; the re-read tip must be that entry. */
export function appendCheckpoint(path: string, state: CheckpointState, body: AnchorBody): CheckpointState {
  const { entry, text } = nextCheckpointEntry(state, body);
  appendDurable(path, text, { chmod: false });
  const after = readCheckpoint(path);
  if (after.tip?.hash !== entry.hash) throw new CheckpointError("CHECKPOINT_UNCONFIRMED", "tip is not the entry just appended");
  return after;
}

export const checkpointIsAppendOnly = (path: string) => isAppendOnly(path);

/** Read-only view of a journal, as payment-journal.ts readFilePaymentJournal provides it. */
export type JournalView = {
  readonly journalId: string;
  auth(authId: string): { auth_id: string; intent_hash: string; disposition: AuthDisposition; detail?: string } | undefined;
  auths(): { auth_id: string; intent_hash: string; disposition: AuthDisposition; detail?: string }[];
  inspect(intentHash: string): PaymentJournalRecord | undefined;
  list(): PaymentJournalRecord[];
};

export type Discrepancy = { readonly kind: "AUTH_MISSING" | "INTENT_MISSING" | "INTENT_REGRESSED" | "RESOLUTION_MISSING"; readonly id: string; readonly detail: string };

const UNREADABLE = "JOURNAL_RECORD_UNREADABLE";

/**
 * Compare a journal with its checkpoint. `rolledBack`: facts the checkpoint
 * holds that the journal lacks or holds in an earlier state (only a journal
 * rollback produces them). `catchUp`: journal facts the checkpoint lacks
 * (crash between the journal write and the checkpoint append), to append.
 * Unreadable journal records are corruption, not rollback: they are already
 * handled fail-closed by the journal (UNKNOWN, never released, never reused).
 */
export function compareJournal(cp: CheckpointState, j: JournalView): { rolledBack: Discrepancy[]; catchUp: AnchorBody[] } {
  const rolledBack: Discrepancy[] = [];
  for (const c of cp.consumes.values()) {
    if (j.auth(c.auth_id) === undefined) rolledBack.push({ kind: "AUTH_MISSING", id: c.auth_id, detail: `consumed ${c.disposition}` });
    else if (c.disposition === "RESERVED" && (c.claim_id !== undefined || c.request !== undefined) && j.inspect(c.intent_hash) === undefined) {
      rolledBack.push({ kind: "INTENT_MISSING", id: c.intent_hash, detail: c.claim_id !== undefined ? `claim ${c.claim_id}` : "legacy intent (no claim)" });
    }
  }
  for (const f of cp.finals.values()) {
    const r = j.inspect(f.intent_hash);
    if (r === undefined) {
      if (!rolledBack.some((d) => d.id === f.intent_hash)) rolledBack.push({ kind: "INTENT_MISSING", id: f.intent_hash, detail: `final ${f.state}` });
    } else if (r.detail !== UNREADABLE && r.state !== f.state) rolledBack.push({ kind: "INTENT_REGRESSED", id: f.intent_hash, detail: `journal ${r.state}, checkpoint ${f.state}` });
  }
  for (const res of cp.resolved.values()) {
    const r = j.inspect(res.intent_hash);
    if (r !== undefined && r.detail !== UNREADABLE && r.resolution === undefined) rolledBack.push({ kind: "RESOLUTION_MISSING", id: res.intent_hash, detail: "resolution lost" });
  }

  const catchUp: AnchorBody[] = [];
  for (const a of j.auths()) {
    if (a.auth_id === "" || a.detail === UNREADABLE || cp.consumes.has(a.auth_id)) continue;
    const intent = a.disposition === "RESERVED" ? j.inspect(a.intent_hash) : undefined;
    const bound = intent !== undefined && intent.detail !== UNREADABLE && intent.auth_id === a.auth_id ? intent : undefined;
    catchUp.push({
      kind: "CONSUME",
      auth_id: a.auth_id,
      intent_hash: a.intent_hash,
      disposition: a.disposition,
      // 0007 (F-LEGACY): the request is kept for every bound intent, also a legacy one without a claim id.
      ...(bound?.claim_id !== undefined ? { claim_id: bound.claim_id } : {}),
      ...(bound !== undefined && bound.request !== undefined ? { request: bound.request } : {}),
    });
  }
  for (const r of j.list()) {
    if (r.detail === UNREADABLE || r.state === "STARTED") continue;
    if (!cp.finals.has(r.intent_hash)) catchUp.push(finalBody(r));
    if (r.resolution !== undefined && !cp.resolved.has(r.intent_hash)) catchUp.push({ kind: "RESOLVED", intent_hash: r.intent_hash, resolution: r.resolution });
  }
  for (const r of j.list()) {
    if (r.detail !== UNREADABLE && r.state === "STARTED" && r.resolution !== undefined && !cp.resolved.has(r.intent_hash)) catchUp.push({ kind: "RESOLVED", intent_hash: r.intent_hash, resolution: r.resolution });
  }
  return { rolledBack, catchUp };
}

export function finalBody(r: PaymentJournalRecord): Extract<AnchorBody, { kind: "FINAL" }> {
  return {
    kind: "FINAL",
    intent_hash: r.intent_hash,
    auth_id: r.auth_id,
    state: r.state as Exclude<PaymentJournalState, "STARTED">,
    ...(r.detail !== undefined ? { detail: r.detail } : {}),
    ...(r.receipt !== undefined ? { receipt: r.receipt } : {}),
    ...(r.claim_id !== undefined ? { claim_id: r.claim_id } : {}),
    ...(r.request !== undefined ? { request: r.request } : {}),
  };
}

/** Open-time verification of a checkpoint file for `journalId` (existence, append-only, sealed, binding). */
export function loadCheckpointFor(path: string, journalId: string, o: { requireAppendOnly?: boolean; allowUnsealed?: boolean } = {}): CheckpointState {
  const cp = readCheckpoint(path);
  if (o.requireAppendOnly !== false && !checkpointIsAppendOnly(path)) throw new CheckpointError("CHECKPOINT_NOT_APPEND_ONLY", path);
  if (cp.entries.length === 0) {
    // Empty, or only torn lines of an interrupted seal (0007, F-TORN-GENESIS): `seal` completes it.
    if (o.allowUnsealed) return cp;
    throw new CheckpointError("CHECKPOINT_UNSEALED", cp.tornLines.length > 0 ? `${path} (interrupted seal)` : path);
  }
  if (cp.journalId !== journalId) throw new CheckpointError("CHECKPOINT_DOMAIN_MISMATCH", `checkpoint ${cp.journalId}, journal ${journalId}`);
  return cp;
}

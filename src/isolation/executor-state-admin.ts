// SPDX-License-Identifier: MIT
/**
 * Operator administration of the executor's persistent state (Phase 2C; N2).
 *
 *   <executorStateRoot>/          oxdeai-executor 0700   (provisionExecutorStateRoot)
 *     journal/                    payment journal         (initExecutorState, once)
 *     mock-wallet.key             0600 mock wallet key    (initExecutorState, once; Phase 2D: persistent,
 *                                 so ledger evidence stays verifiable across deployments)
 *     ledger.jsonl                mock ledger, created at the first payment
 *
 *   <executorStateRoot>.anchor/   root 0755              consumption checkpoint root (AUD-02/03/04)
 *     <journal_id>.log            oxdeai-executor 0600, chattr +a: append-only checkpoint, sealed at init
 *                                 (src/executor/executor-anchor.ts). Outside the state root, so an
 *                                 executor-state restore cannot roll it back.
 *
 * The root lives outside every deployment's runtime directory, so a teardown
 * and redeployment keep the journal (including STARTED / UNKNOWN records that
 * still need reconciliation), the consumed auth_ids, and the ledger. The
 * executor never creates a journal: a missing or damaged one makes it refuse
 * to start (exit 78). `init` refuses an existing journal (JOURNAL_EXISTS).
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { executorAnchorPathFor, executorAnchorRootFor } from "../executor/executor-anchor.ts";
import { commandAs, identityOf } from "./identity.ts";

export const executorJournalDir = (root: string) => join(root, "journal");
export const executorLedgerPath = (root: string) => join(root, "ledger.jsonl");
export const executorWalletKeyPath = (root: string) => join(root, "mock-wallet.key");
export const executorAnchorRoot = (root: string) => executorAnchorRootFor(executorJournalDir(root));
export const executorAnchorPath = (root: string, journalId: string) => executorAnchorPathFor(executorJournalDir(root), journalId);

/** Create (or re-assert) the executor state root: oxdeai-executor 0700. Idempotent; never touches existing state. */
export function provisionExecutorStateRoot(root: string): void {
  const ex = identityOf("executor");
  if (!ex) throw new Error("IDENTITY_MISSING:oxdeai-executor");
  const r = spawnSync("sudo", ["-n", "install", "-d", "-o", String(ex.uid), "-g", String(ex.gid), "-m", "0700", root], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`EXECUTOR_STATE_PROVISION_FAILED:${r.stderr.trim()}`);
  const a = spawnSync("sudo", ["-n", "install", "-d", "-o", "0", "-g", "0", "-m", "0755", executorAnchorRoot(root)], { encoding: "utf8" });
  if (a.status !== 0) throw new Error(`EXECUTOR_STATE_PROVISION_FAILED:checkpoint root ${a.stderr.trim()}`);
}

/** The journal's immutable id, read by the operator. */
function journalIdAsOperator(root: string): string {
  const m = spawnSync("sudo", ["-n", "cat", join(executorJournalDir(root), "JOURNAL.json")], { encoding: "utf8" });
  const id = m.status === 0 ? (JSON.parse(m.stdout) as { journal_id?: unknown }).journal_id : undefined;
  if (typeof id !== "string" || !/^[0-9a-f]{32}$/.test(id)) throw new Error(`JOURNAL_MISSING:${executorJournalDir(root)}`);
  return id;
}

/**
 * Create and seal the consumption checkpoint of an existing journal (AUD-02/03/04). Used by `init`, and
 * once by an operator migrating a pre-checkpoint journal (`executor-cli seal`, executor stopped). The
 * file is created empty (oxdeai-executor 0600), made append-only, then sealed by the executor identity
 * (GENESIS + every fact the journal holds now).
 *
 * 0007 (S2, F-TORN-GENESIS, F-SIBLING): an existing checkpoint that is still unsealed (empty, or only the
 * torn lines of an interrupted seal) is completed. An already sealed one is refused
 * (CHECKPOINT_ALREADY_SEALED). An existing file is never re-armed: one without the append-only attribute
 * is refused (CHECKPOINT_NOT_APPEND_ONLY), because it may have been restored, and re-adding the attribute
 * would hide a rollback.
 */
export function sealExecutorCheckpoint(root: string): { anchorPath: string; journalId: string } {
  const ex = identityOf("executor");
  if (!ex) throw new Error("IDENTITY_MISSING:oxdeai-executor");
  const journalId = journalIdAsOperator(root);
  const anchorPath = executorAnchorPath(root, journalId);
  if (spawnSync("sudo", ["-n", "test", "-e", anchorPath]).status === 0) {
    const attrs = spawnSync("sudo", ["-n", "/usr/bin/lsattr", "-d", anchorPath], { encoding: "utf8" });
    if (attrs.status !== 0 || !(attrs.stdout.trim().split(/\s+/)[0] ?? "").includes("a")) {
      throw new Error(`CHECKPOINT_NOT_APPEND_ONLY:${anchorPath} exists without +a; it is never re-armed (see docs/RECOVERY-RUNBOOK.md)`);
    }
    return runSeal(root, anchorPath, journalId);
  }
  const staging = mkdtempSync(join(tmpdir(), "oxdeai-anchor-"));
  chmodSync(staging, 0o700);
  try {
    const tmp = join(staging, "a");
    writeFileSync(tmp, "", { mode: 0o600, flag: "wx" });
    const i = spawnSync("sudo", ["-n", "install", "-o", String(ex.uid), "-g", String(ex.gid), "-m", "0600", tmp, anchorPath], { encoding: "utf8" });
    if (i.status !== 0) throw new Error(`CHECKPOINT_CREATE_FAILED:${i.stderr.trim()}`);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
  const c = spawnSync("sudo", ["-n", "chattr", "+a", anchorPath], { encoding: "utf8" });
  if (c.status !== 0) throw new Error(`CHECKPOINT_CREATE_FAILED:chattr ${c.stderr.trim()}`);
  return runSeal(root, anchorPath, journalId);
}

/** Seal (GENESIS + current facts) as the executor identity; refuses an already sealed checkpoint. */
function runSeal(root: string, anchorPath: string, journalId: string): { anchorPath: string; journalId: string } {
  const cli = resolve(fileURLToPath(import.meta.url), "..", "journal-cli.ts");
  const [cmd, args] = commandAs("executor", [realpathSync(process.execPath), cli, executorJournalDir(root), "seal"]);
  const r = spawnSync(cmd, args, { encoding: "utf8", cwd: "/", timeout: 30_000 });
  if (r.status !== 0) throw new Error(`CHECKPOINT_SEAL_FAILED:${r.stderr.match(/CHECKPOINT_[A-Z_]+[^\n]*/)?.[0] ?? r.stderr.trim().split("\n").slice(-3).join(" ")}`);
  return { anchorPath, journalId };
}

/** Initialize the journal once, as the executor identity. Throws JOURNAL_EXISTS if it already exists. */
export function initExecutorState(root: string): { journalDir: string } {
  const cli = resolve(fileURLToPath(import.meta.url), "..", "journal-cli.ts");
  const [cmd, args] = commandAs("executor", [realpathSync(process.execPath), cli, executorJournalDir(root), "init"]);
  const r = spawnSync(cmd, args, { encoding: "utf8", cwd: "/", timeout: 30_000 });
  if (r.status !== 0) {
    const msg = r.stderr.match(/JOURNAL_EXISTS[^\n]*/)?.[0] ?? r.stderr.trim().split("\n").slice(-3).join(" ");
    throw new Error(msg.startsWith("JOURNAL_EXISTS") ? msg : `EXECUTOR_STATE_INIT_FAILED:${msg}`);
  }
  // Mock wallet key (Phase 2D): created once with the journal, never replaced.
  const ex = identityOf("executor")!;
  const wallet = executorWalletKeyPath(root);
  if (spawnSync("sudo", ["-n", "test", "-e", wallet]).status !== 0) {
    const staging = mkdtempSync(join(tmpdir(), "oxdeai-wallet-"));
    chmodSync(staging, 0o700);
    try {
      const tmp = join(staging, "k");
      writeFileSync(tmp, randomBytes(32), { mode: 0o600, flag: "wx" });
      const w = spawnSync("sudo", ["-n", "install", "-o", String(ex.uid), "-g", String(ex.gid), "-m", "0600", tmp, wallet], { encoding: "utf8" });
      if (w.status !== 0) throw new Error(`EXECUTOR_STATE_INIT_FAILED:wallet ${w.stderr.trim()}`);
    } finally {
      rmSync(staging, { recursive: true, force: true });
    }
  }
  sealExecutorCheckpoint(root);
  return { journalDir: executorJournalDir(root) };
}

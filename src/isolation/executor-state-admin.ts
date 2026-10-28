// SPDX-License-Identifier: MIT
/**
 * Operator administration of the executor's persistent state (Phase 2C; N2).
 *
 *   <executorStateRoot>/          oxdeai-executor 0700   (provisionExecutorStateRoot)
 *     journal/                    payment journal         (initExecutorState, once)
 *     ledger.jsonl                mock ledger, created at the first payment
 *
 * The root lives outside every deployment's runtime directory, so a teardown
 * and redeployment keep the journal (including STARTED / UNKNOWN records that
 * still need reconciliation), the consumed auth_ids, and the ledger. The
 * executor never creates a journal: a missing or damaged one makes it refuse
 * to start (exit 78). `init` refuses an existing journal (JOURNAL_EXISTS).
 */
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { commandAs, identityOf } from "./identity.ts";

export const executorJournalDir = (root: string) => join(root, "journal");
export const executorLedgerPath = (root: string) => join(root, "ledger.jsonl");

/** Create (or re-assert) the executor state root: oxdeai-executor 0700. Idempotent; never touches existing state. */
export function provisionExecutorStateRoot(root: string): void {
  const ex = identityOf("executor");
  if (!ex) throw new Error("IDENTITY_MISSING:oxdeai-executor");
  const r = spawnSync("sudo", ["-n", "install", "-d", "-o", String(ex.uid), "-g", String(ex.gid), "-m", "0700", root], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`EXECUTOR_STATE_PROVISION_FAILED:${r.stderr.trim()}`);
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
  return { journalDir: executorJournalDir(root) };
}

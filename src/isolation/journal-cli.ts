// SPDX-License-Identifier: MIT
/**
 * Operator tool for the durable payment journal. Run as the executor's OS
 * identity; the agent identity cannot read the journal directory.
 *
 *   node journal-cli.ts <journalDir> init        (once; refuses an existing journal)
 *   node journal-cli.ts <journalDir> auths       (per-authorization dispositions)
 *   node journal-cli.ts <journalDir> list
 *   node journal-cli.ts <journalDir> pending
 *   node journal-cli.ts <journalDir> show <intent_hash>
 *   node journal-cli.ts <journalDir> resolve <intent_hash> SETTLED <note>
 *   node journal-cli.ts <journalDir> seal                 (once; the checkpoint must exist and be empty)
 *   node journal-cli.ts <journalDir> verify               (read-only: journal against its checkpoint)
 *   node journal-cli.ts <journalDir> recover <note>       (re-import facts lost by a journal rollback)
 *
 * Checkpoint (AUD-02/03/04, src/executor/executor-anchor.ts): `<executorStateRoot>.anchor/<journal_id>.log`.
 * `resolve`, `seal` and `recover` take the journal's writer lock (executor stopped) and append to the
 * checkpoint; a missing, unsealed, foreign, or not append-only checkpoint refuses them.
 *
 * `list`, `pending`, and `show` are read-only and lock-free. `resolve` takes
 * the journal's single-writer lock, so the executor must be stopped first. It
 * attaches a settlement resolution to a STARTED or UNKNOWN record only with
 * verified evidence (Phase 2D, D5): exactly one ledger entry for the intent
 * whose MAC under the persistent mock wallet key binds this intent, this
 * record's claim, and this journal (src/adapters/mock-buy/mock-settlement.ts).
 * It never changes the state, and the intent can never be paid again. After a
 * restart the executor reports RESOLVED_SETTLED with the evidenced amount, and
 * the auth service confirms the claim.
 *
 * There is no NOT_SETTLED resolution: a missing ledger entry is not proof
 * that nothing was paid, and the mock has no positive evidence of
 * non-execution. Such a reservation stays UNCERTAIN and charged.
 */
import { dirname, join, resolve as resolvePath } from "node:path";
import { verifySettlementEvidence } from "../adapters/mock-buy/mock-settlement.ts";
import { compareJournal, executorAnchorPathFor, loadCheckpointFor } from "../executor/executor-anchor.ts";
import { initFilePaymentJournal, journalIdOf, openFilePaymentJournal, readFilePaymentJournal } from "../executor/payment-journal.ts";

const [dir, command, intentHash, verdict, ...note] = process.argv.slice(2);
if (!dir || !command) throw new Error("usage: journal-cli <journalDir> list|pending|show|resolve ...");

let out: unknown;
if (command === "init") {
  initFilePaymentJournal(dir);
  process.stdout.write(`${JSON.stringify({ initialized: dir })}\n`);
  process.exit(0);
}
const reader = readFilePaymentJournal(dir);
const checkpointPath = () => executorAnchorPathFor(resolvePath(dir), journalIdOf(dir));
switch (command) {
  case "list":
    out = reader.list();
    break;
  case "auths":
    out = reader.auths();
    break;
  case "pending":
    out = reader.list().filter((r) => (r.state === "STARTED" || r.state === "UNKNOWN") && r.resolution === undefined);
    break;
  case "show":
    out = reader.inspect(intentHash ?? "") ?? null;
    break;
  case "resolve": {
    if (verdict === "NOT_SETTLED") throw new Error("RESOLUTION_REFUSED:no positive evidence of non-execution exists; the reservation stays charged");
    if (verdict !== "SETTLED") throw new Error("verdict must be SETTLED");
    if (note.length === 0) throw new Error("a reconciliation note is required");
    const journal = openFilePaymentJournal(dir, { checkpoint: { path: checkpointPath() } });
    try {
      const record = journal.inspect(intentHash ?? "");
      if (!record || record.claim_id === undefined) throw new Error("JOURNAL_NOT_RECONCILABLE:no claimed intent");
      const root = dirname(resolvePath(dir));
      const evidence = verifySettlementEvidence(
        // Same layout as src/isolation/executor-state-admin.ts (<root>/journal, <root>/mock-wallet.key, <root>/ledger.jsonl).
        { walletKeyPath: join(root, "mock-wallet.key"), ledgerPath: join(root, "ledger.jsonl") },
        { intent_hash: record.intent_hash, claim_id: record.claim_id, journal_id: journal.journalId, request: record.request },
      );
      out = journal.resolve(record.intent_hash, evidence, note.join(" "));
    } finally {
      journal.close();
    }
    break;
  }
  case "seal": {
    const journal = openFilePaymentJournal(dir, { checkpoint: { path: checkpointPath(), mode: "seal" } });
    journal.close();
    out = { sealed: checkpointPath(), journal_id: journalIdOf(dir) };
    break;
  }
  case "verify": {
    // Read-only, lock-free. Outcomes: SAFE_TO_RESUME, ROLLBACK_DETECTED (recover), or a CHECKPOINT_* failure.
    const journalId = journalIdOf(dir);
    try {
      const cp = loadCheckpointFor(checkpointPath(), journalId);
      const { rolledBack, catchUp } = compareJournal(cp, { ...reader, journalId });
      out = { outcome: rolledBack.length ? "ROLLBACK_DETECTED" : "SAFE_TO_RESUME", journal_id: journalId, checkpoint: checkpointPath(), entries: cp.entries.length, rolled_back: rolledBack, catch_up: catchUp.length, torn_lines: cp.tornLines.length };
    } catch (err) {
      out = { outcome: "CHECKPOINT_FAILURE", journal_id: journalId, checkpoint: checkpointPath(), error: (err as Error).message };
    }
    break;
  }
  case "recover": {
    const why = [intentHash, verdict, ...note].filter(Boolean).join(" ");
    if (!why) throw new Error("a recovery note is required");
    const journal = openFilePaymentJournal(dir, { checkpoint: { path: checkpointPath(), mode: "recover" } });
    try {
      const found = journal.rolledBack.map((d) => `${d.kind} ${d.id} (${d.detail})`);
      const { restored } = found.length ? journal.recoverFromCheckpoint(why) : { restored: [] };
      out = { outcome: "SAFE_TO_RESUME", found, restored };
    } finally {
      journal.close();
    }
    break;
  }
  default:
    throw new Error(`unknown command ${command}`);
}
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

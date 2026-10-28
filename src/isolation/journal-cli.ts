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
 *   node journal-cli.ts <journalDir> resolve <intent_hash> SETTLED|NOT_SETTLED <note>
 *
 * `list`, `pending`, and `show` are read-only and lock-free. `resolve` takes
 * the journal's single-writer lock, so the executor must be stopped first. It
 * attaches the operator's verdict to a STARTED or UNKNOWN record; it never
 * changes the state, and the intent can never be paid again. After a restart
 * the executor reports the resolution to the auth service (RESOLVED_SETTLED
 * or RESOLVED_NOT_SETTLED), which only then confirms or releases the
 * reservation.
 */
import { initFilePaymentJournal, openFilePaymentJournal, readFilePaymentJournal } from "../executor/payment-journal.ts";

const [dir, command, intentHash, verdict, ...note] = process.argv.slice(2);
if (!dir || !command) throw new Error("usage: journal-cli <journalDir> list|pending|show|resolve ...");

let out: unknown;
if (command === "init") {
  initFilePaymentJournal(dir);
  process.stdout.write(`${JSON.stringify({ initialized: dir })}\n`);
  process.exit(0);
}
const reader = readFilePaymentJournal(dir);
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
    if (verdict !== "SETTLED" && verdict !== "NOT_SETTLED") throw new Error("verdict must be SETTLED or NOT_SETTLED");
    if (note.length === 0) throw new Error("a reconciliation note is required");
    const journal = openFilePaymentJournal(dir);
    try {
      out = journal.resolve(intentHash ?? "", verdict, note.join(" "));
    } finally {
      journal.close();
    }
    break;
  }
  default:
    throw new Error(`unknown command ${command}`);
}
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

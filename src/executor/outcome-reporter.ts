// SPDX-License-Identifier: MIT
/**
 * Delivers executor outcome reports to the authorization service (Phase 2C;
 * F3, Phase 2D).
 *
 * One pass (`run`): for every auth record in the journal, derive the outcome
 * of its claim from the journal (never from memory alone, only from positive
 * records, src/executor/outcome-report.ts), and send it unless the auth
 * service already acknowledged that outcome. The ack is recorded durably only
 * after the auth service committed it.
 *
 * Since Phase 2D the executor no longer cancels expired authorizations: the
 * authorization service releases expired, unclaimed reservations itself (no
 * claim can be granted after expiry), and unclaimed rejections are VOIDed
 * synchronously by the executor.
 *
 * Crash safety: every step is idempotent. A crash before the auth service
 * commits means the report is sent again; a crash after it commits but before
 * the ack is recorded means a duplicate, which the auth service answers
 * ALREADY_APPLIED. No step depends on in-memory state surviving a restart;
 * `inFlight` only distinguishes EXECUTING from UNCERTAIN while this process runs.
 * Passes never overlap.
 */
import { ackKey, deriveOutcome, signReport, REPORT_TYPE, type OutcomeReport } from "./outcome-report.ts";
import type { FilePaymentJournal } from "./payment-journal.ts";

export type ReporterTransport = {
  settle(signed: unknown): Promise<{ status: number; body: unknown }>;
};

export type ReporterFaults = {
  /** SIGKILL after the auth service acknowledged a report, before the ack is journaled. */
  readonly crashBeforeAck?: boolean;
};

export function createOutcomeReporter(o: {
  journal: FilePaymentJournal;
  transport: ReporterTransport;
  key: { privateKeyPem: string; kid: string };
  inFlight: () => ReadonlySet<string>;
  faults?: ReporterFaults;
  log?: (event: Record<string, unknown>) => void;
}) {
  let running: Promise<void> | null = null;
  let again = false;

  async function deliver(): Promise<void> {
    const inFlight = o.inFlight();
    for (const auth of o.journal.auths()) {
      const intent = auth.intent_hash ? o.journal.inspect(auth.intent_hash) : undefined;
      const out = deriveOutcome(auth, intent, intent !== undefined && inFlight.has(intent.intent_hash));
      if (out === null) continue;
      const key = ackKey(out);
      if (o.journal.acked(auth.auth_id, key)) continue;
      const report: OutcomeReport = {
        type: REPORT_TYPE,
        auth_id: auth.auth_id,
        intent_hash: auth.intent_hash,
        claim_id: out.claim_id,
        outcome: out.outcome,
        ...(out.reason !== undefined ? { reason: out.reason } : {}),
        ...(out.amount !== undefined ? { amount: out.amount } : {}),
        journal_id: o.journal.journalId,
        executor_kid: o.key.kid,
      };
      const res = await o.transport.settle(signReport(report, o.key.privateKeyPem));
      const status = (res.body as { status?: string; reason?: string } | undefined)?.status;
      o.log?.({ event: "outcome_report", auth_id: auth.auth_id, outcome: key, http: res.status, status, reason: (res.body as { reason?: string })?.reason });
      // Acknowledged = the auth service durably holds this outcome (or a later one), or the
      // claim was never committed there (NOT_CLAIMED: final, moves nothing).
      if (res.status === 200 && (status === "APPLIED" || status === "ALREADY_APPLIED" || status === "STALE" || status === "NOT_CLAIMED")) {
        if (o.faults?.crashBeforeAck) process.kill(process.pid, "SIGKILL");
        o.journal.ack(auth.auth_id, key);
      }
    }
  }

  async function pass(): Promise<void> {
    try {
      await deliver();
    } catch (err) {
      o.log?.({ event: "outcome_reporter_error", step: "deliver", error: (err as Error).message });
    }
  }

  return {
    /** Run one pass now (or once more after the current one). Never throws. */
    run(): Promise<void> {
      if (running) {
        again = true;
        return running;
      }
      running = (async () => {
        do {
          again = false;
          await pass();
        } while (again);
      })().finally(() => {
        running = null;
      });
      return running;
    },
  };
}

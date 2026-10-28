// SPDX-License-Identifier: MIT
/**
 * Delivers executor outcome reports to the authorization service and cancels
 * expired, unused authorizations (Phase 2C; F3).
 *
 * One pass (`run`):
 *   1. Cancellation: ask the auth service which reservations are RESERVED past
 *      their expiry (+ grace). For each, consume the auth_id durably as
 *      CANCELLED, unless the journal already holds it (then its real state is
 *      reported instead). A cancelled auth_id is refused forever, so its budget
 *      can be released without any chance of a later payment.
 *   2. Delivery: for every auth record in the journal, derive the outcome from
 *      the journal (never from memory alone), and send it unless the auth
 *      service already acknowledged that outcome. The ack is recorded durably
 *      only after the auth service committed it.
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
  expired(graceSeconds: number): Promise<{ status: number; body: unknown }>;
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
  graceSeconds: number;
  faults?: ReporterFaults;
  log?: (event: Record<string, unknown>) => void;
}) {
  let running: Promise<void> | null = null;
  let again = false;

  async function cancelExpired(): Promise<void> {
    const res = await o.transport.expired(o.graceSeconds);
    const list = (res.body as { expired?: Array<{ auth_id?: unknown; intent_hash?: unknown }> } | undefined)?.expired;
    if (res.status !== 200 || !Array.isArray(list)) return;
    for (const e of list) {
      if (typeof e.auth_id !== "string" || typeof e.intent_hash !== "string" || !/^[0-9a-f]{64}$/.test(e.intent_hash)) continue;
      o.journal.consume({ auth_id: e.auth_id, intent_hash: e.intent_hash, disposition: "CANCELLED", detail: "EXPIRED_UNUSED" });
    }
  }

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
        outcome: out.outcome,
        ...(out.reason !== undefined ? { reason: out.reason } : {}),
        ...(out.amount !== undefined ? { amount: out.amount } : {}),
        journal_id: o.journal.journalId,
        executor_kid: o.key.kid,
      };
      const res = await o.transport.settle(signReport(report, o.key.privateKeyPem));
      const status = (res.body as { status?: string; reason?: string } | undefined)?.status;
      o.log?.({ event: "outcome_report", auth_id: auth.auth_id, outcome: key, http: res.status, status, reason: (res.body as { reason?: string })?.reason });
      // Acknowledged = the auth service durably holds this outcome (or a later one).
      if (res.status === 200 && (status === "APPLIED" || status === "ALREADY_APPLIED" || status === "STALE")) {
        if (o.faults?.crashBeforeAck) process.kill(process.pid, "SIGKILL");
        o.journal.ack(auth.auth_id, key);
      }
    }
  }

  async function pass(): Promise<void> {
    try {
      await cancelExpired();
    } catch (err) {
      o.log?.({ event: "outcome_reporter_error", step: "cancel", error: (err as Error).message });
    }
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

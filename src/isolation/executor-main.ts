// SPDX-License-Identifier: MIT
/**
 * Process C: protected payment executor.
 *
 * Runs as the executor's OS identity (oxdeai-executor). Listens only on a
 * Unix-domain socket in exec-ipc/ (setgid directory executor:gateway 2750,
 * socket 0660), so only the gateway identity can connect. Holds the internal
 * executor token, the mock wallet key, the mock ledger, the durable payment
 * journal, and the outcome-report signing key; never the authorization
 * signing key.
 *
 * Phase 2C: the journal and ledger are persistent and operator-initialized
 * (<executorStateRoot>); a missing or damaged journal makes the executor
 * refuse to start (exit 78), and a journal held by another process exit 75.
 * Outcome reports go to the auth service over the settle channel
 * (src/isolation/settle-channel.ts, src/executor/outcome-reporter.ts).
 *
 *   node executor-main.ts <executor-config.json>
 */
import { setTimeout as sleep } from "node:timers/promises";
import { createMockBuyAdapter } from "../adapters/mock-buy/mock-buy.ts";
import { withMockSettlement } from "../adapters/mock-buy/mock-settlement.ts";
import { createPaymentExecutor } from "../executor/executor.ts";
import { domainAudience } from "../executor/execution-domain.ts";
import { interpretClaim, interpretVoid, type ExecutionAuthority } from "../executor/execution-authority.ts";
import { CLAIM_TYPE, signClaim, signVoid, VOID_TYPE } from "../executor/outcome-report.ts";
import { createOutcomeReporter } from "../executor/outcome-reporter.ts";
import { PaymentRefusedError, type PaymentAdapter } from "../executor/payment-adapter.ts";
import { journalIdOf, openFilePaymentJournal, type FilePaymentJournal } from "../executor/payment-journal.ts";
import { emit, readConfig, type ExecutorConfig, type ExecutorFaults } from "./config.ts";
import { serveJson } from "./ipc.ts";
import { settlePost } from "./settle-channel.ts";

function withFaults(inner: PaymentAdapter, faults: ExecutorFaults): PaymentAdapter {
  return {
    async quote(r) {
      if (faults.delayQuoteMs) await sleep(faults.delayQuoteMs);
      const q = await inner.quote(r);
      return faults.quoteDrift ? { ...q, amount: (BigInt(q.amount) * 10n).toString() } : q;
    },
    async pay(payment) {
      if (faults.delayPayMs) await sleep(faults.delayPayMs);
      if (faults.refuseBeforeSigning) throw new PaymentRefusedError("MOCK_REFUSED_BEFORE_SIGNING");
      if (faults.crashBeforePay) process.kill(process.pid, "SIGKILL");
      const receipt = await inner.pay(payment);
      if (faults.crashAfterPay) process.kill(process.pid, "SIGKILL");
      return receipt;
    },
  };
}

const config = readConfig<ExecutorConfig>(process.argv[2]);
process.umask(0o077);
const faults = config.faults ?? {};

function refuse(code: number, reason: string): never {
  process.stderr.write(`${JSON.stringify({ event: "refused", role: "executor", reason })}\n`);
  process.exit(code);
}

let journal: FilePaymentJournal;
try {
  // CX2 first: a journal of another execution domain is refused before its checkpoint is looked at.
  const jid = journalIdOf(config.journalDir);
  if (jid !== config.domain.journal_id) refuse(78, `EXECUTION_DOMAIN_MISMATCH:journal ${jid} uid ${process.getuid!()}`);
  journal = openFilePaymentJournal(config.journalDir, {
    // Fault: crash between consuming the auth_id and creating the intent record.
    afterAuthRecord: faults.crashAfterAuthRecord ? () => process.kill(process.pid, "SIGKILL") : undefined,
    // AUD-02/03/04: a checkpointed fact missing from the journal (a rollback) refuses to start (exit 78).
    checkpoint: {
      path: config.anchorPath,
      beforeAppend: faults.crashBeforeCheckpoint ? () => process.kill(process.pid, "SIGKILL") : undefined,
      onRollback: (detail) => emit({ event: "journal_rollback_detected", detail }),
    },
  });
} catch (err) {
  const msg = (err as Error).message;
  refuse(msg.startsWith("JOURNAL_LOCKED") || msg.startsWith("CHECKPOINT_LOCKED") ? 75 : 78, msg);
}
// CX2: verify the execution-domain binding from this process's own uid and open journal.
{
  const d = { journal_id: journal.journalId, executor_uid: process.getuid!() };
  if (journal.journalId !== config.domain.journal_id || d.executor_uid !== config.domain.executor_uid) {
    refuse(78, `EXECUTION_DOMAIN_MISMATCH:journal ${journal.journalId} uid ${d.executor_uid}`);
  }
  if (config.verification.expectedAudience !== domainAudience(config.domain.baseAudience, d)) refuse(78, "EXECUTION_DOMAIN_MISMATCH:audience");
}
const mock = createMockBuyAdapter(config.services.map((s) => ({ ...s, price: BigInt(s.price) })));
const adapter = withFaults(withMockSettlement(mock.adapter, { ...config, journalId: journal.journalId }), faults);
// The authorization service as execution authority (Phase 2D), over the peer-proofed settle channel.
// Any transport failure is a non-definitive claim answer: the attempt is abandoned, never paid.
const authority: ExecutionAuthority = {
  async claim(c) {
    const signed = signClaim({ type: CLAIM_TYPE, ...c, journal_id: journal.journalId, executor_kid: config.reportKey.kid }, config.reportKey.privateKeyPem);
    try {
      const res = await settlePost(config.settleSocketPath, config.proofDir, "/v1/claim", { claim: signed }, config.claimTimeoutMs);
      return interpretClaim(c, res.status, res.body);
    } catch (err) {
      return { ok: false, definitive: false, reason: `CLAIM_UNAVAILABLE:${(err as NodeJS.ErrnoException).code ?? (err as Error).message}` };
    }
  },
  async void(v) {
    const signed = signVoid({ type: VOID_TYPE, ...v, journal_id: journal.journalId, executor_kid: config.reportKey.kid }, config.reportKey.privateKeyPem);
    try {
      const res = await settlePost(config.settleSocketPath, config.proofDir, "/v1/void", { void: signed }, config.claimTimeoutMs);
      const answer = interpretVoid(res.status, res.body);
      emit({ event: "void", auth_id: v.auth_id, reason: v.reason, acknowledged: answer.acknowledged, final: answer.final, detail: answer.reason });
      return answer;
    } catch (err) {
      emit({ event: "void", auth_id: v.auth_id, reason: v.reason, acknowledged: false, detail: (err as Error).message });
      return { acknowledged: false, final: false, reason: (err as Error).message };
    }
  },
};
const executor = createPaymentExecutor({
  internalToken: config.internalToken,
  adapter,
  verification: { ...config.verification, now: () => Math.floor(Date.now() / 1000) },
  journal,
  authority,
});

const reporter = createOutcomeReporter({
  journal,
  key: config.reportKey,
  inFlight: executor.inFlight,
  faults: { crashBeforeAck: faults.crashBeforeAck },
  transport: {
    settle: (signed) => settlePost(config.settleSocketPath, config.proofDir, "/v1/settle", { report: signed }),
  },
  log: emit,
});

const delay = faults.delayResponseMs ?? 0;
const server = await serveJson(config.socketPath, 0o660, {
  "/v1/execute": async (body, headers) => {
    const res = await executor.handle(body, headers);
    void reporter.run();
    if (delay) await sleep(delay);
    return { status: res.status, body: res.body };
  },
  "/v1/quote": async (body, headers) => {
    const res = await executor.handleQuote(body, headers);
    return { status: res.status, body: res.body };
  },
});

for (const r of journal.needsReconciliation) emit({ event: "needs_reconciliation", intent_hash: r.intent_hash, state: r.state });
emit({ event: "ready", role: "executor", pid: process.pid });

void reporter.run();
const timer = setInterval(() => void reporter.run(), config.reconcileIntervalMs);

function shutdown() {
  clearInterval(timer);
  server.close(() => {
    journal.close();
    process.exit(0);
  });
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

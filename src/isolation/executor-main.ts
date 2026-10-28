// SPDX-License-Identifier: MIT
/**
 * Process C: protected payment executor.
 *
 * Runs as the executor's OS identity (oxdeai-executor). Listens only on a
 * Unix-domain socket in exec-ipc/ (setgid directory executor:gateway 2750,
 * socket 0660), so only the gateway identity can connect. Holds the internal
 * executor token, the mock wallet key, the mock ledger, and the durable
 * payment journal; never the authorization signing key.
 *
 *   node executor-main.ts <executor-config.json>
 */
import { setTimeout as sleep } from "node:timers/promises";
import { createMockBuyAdapter } from "../adapters/mock-buy/mock-buy.ts";
import { withMockSettlement } from "../adapters/mock-buy/mock-settlement.ts";
import { createPaymentExecutor } from "../executor/executor.ts";
import type { PaymentAdapter } from "../executor/payment-adapter.ts";
import { openFilePaymentJournal } from "../executor/payment-journal.ts";
import { emit, readConfig, type ExecutorConfig, type ExecutorFaults } from "./config.ts";
import { serveJson } from "./ipc.ts";

function withFaults(inner: PaymentAdapter, faults: ExecutorFaults): PaymentAdapter {
  return {
    quote: (r) => inner.quote(r),
    async pay(payment) {
      if (faults.delayPayMs) await sleep(faults.delayPayMs);
      if (faults.crashBeforePay) process.kill(process.pid, "SIGKILL");
      const receipt = await inner.pay(payment);
      if (faults.crashAfterPay) process.kill(process.pid, "SIGKILL");
      return receipt;
    },
  };
}

const config = readConfig<ExecutorConfig>(process.argv[2]);
process.umask(0o077);

const journal = openFilePaymentJournal(config.journalDir);
const mock = createMockBuyAdapter(config.services.map((s) => ({ ...s, price: BigInt(s.price) })));
const adapter = withFaults(withMockSettlement(mock.adapter, config), config.faults ?? {});
const executor = createPaymentExecutor({
  internalToken: config.internalToken,
  adapter,
  verification: { ...config.verification, now: () => Math.floor(Date.now() / 1000) },
  journal,
});

const delay = config.faults?.delayResponseMs ?? 0;
const server = await serveJson(config.socketPath, 0o660, {
  "/v1/execute": async (body, headers) => {
    const res = await executor.handle(body, headers);
    if (delay) await sleep(delay);
    return { status: res.status, body: res.body };
  },
  "/v1/quote": async (body, headers) => {
    const res = await executor.handleQuote(body, headers);
    return { status: res.status, body: res.body };
  },
});

for (const r of journal.needsReconciliation) emit({ event: "needs_reconciliation", intent_hash: r.intent_hash, state: r.state });
emit({ event: "ready", role: "executor", pid: process.pid, stale_lock_recovered: journal.staleLockRecovered });

function shutdown() {
  server.close(() => {
    journal.close();
    process.exit(0);
  });
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// SPDX-License-Identifier: MIT
/**
 * The OxDeAI stack behind the Guarded Buyer, in one process: authorization service (PDP + execution authority),
 * gateway (PEP), executor with the x402 EIP-3009 adapter (v1 and v2), durable journal + checkpoint, outcome
 * reporter. The agent code only ever gets `authorize` and `purchase`: it never sees the wallet key, the
 * executor, or the internal token.
 *
 * Budget scope: the policy state is in memory, so the budget applies per session (one run of the CLI). The
 * process-isolated deployment with durable policy state is src/isolation/ (tests/isolation/x402-process.test.ts).
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInMemoryReplayStore } from "@oxdeai/guard";
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { createX402EvmAdapter } from "../adapters/x402-evm/x402-evm.ts";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../authorization/policy-state.ts";
import type { EvmRpc } from "../chain/rpc.ts";
import { createLocalExecutionAuthority } from "../executor/execution-authority.ts";
import { createPaymentExecutor } from "../executor/executor.ts";
import { createOutcomeReporter } from "../executor/outcome-reporter.ts";
import { initFilePaymentJournal, openFilePaymentJournal } from "../executor/payment-journal.ts";
import { createPaymentGateway } from "../gateway/gateway.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, LOCAL_JOURNAL_ID, PDP_ISSUER, POLICY_VERSION, policyStateFor } from "../system.ts";
import type { Catalog } from "./catalog.ts";

export type GuardedStackOptions = {
  readonly catalog: Catalog;
  readonly rpc: EvmRpc;
  readonly loadWalletKey: () => Uint8Array;
  /** Directory for the journal and its checkpoint (created and sealed on first use). Executor-private. */
  readonly stateDir: string;
  readonly fetch?: typeof fetch;
  readonly endpoints?: Readonly<Record<string, string>>;
  readonly now?: () => number;
  readonly ttlSeconds?: number;
  readonly receiptTimeoutMs?: number;
  readonly receiptPollMs?: number;
  readonly log?: (e: Record<string, unknown>) => void;
};

export function createGuardedStack(o: GuardedStackOptions) {
  const now = o.now ?? (() => Math.floor(Date.now() / 1000));
  const c = o.catalog;
  const store = createInMemoryPolicyStateStore(
    policyStateFor({
      services: c.services.map((s) => {
        const u = new URL(s.url);
        return { service_id: s.service_id, resource: `${u.origin}${u.pathname}`, network: s.network, asset: s.asset, pay_to: s.pay_to };
      }),
      assets: [...new Set(c.services.map((s) => s.asset))],
      budget: BigInt(c.budget),
      perActionMax: BigInt(c.per_call_max),
    }),
  );
  const rk = generateKeyPairSync("ed25519");
  const execKey = { privateKeyPem: rk.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), kid: "exec-guarded-buyer" };
  const auth = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: GATEWAY_AUDIENCE,
    agentId: AGENT_ID,
    ttlSeconds: o.ttlSeconds ?? 120,
    stateStore: store,
    now,
    executorReportKey: { publicKeyPem: rk.publicKey.export({ type: "spki", format: "pem" }).toString(), kid: execKey.kid },
  });

  mkdirSync(o.stateDir, { recursive: true, mode: 0o700 });
  const journalDir = join(o.stateDir, "journal");
  const checkpoint = { path: join(o.stateDir, "checkpoint.log"), requireAppendOnly: false };
  if (!existsSync(journalDir)) {
    initFilePaymentJournal(journalDir);
    writeFileSync(checkpoint.path, "", { mode: 0o600 });
    openFilePaymentJournal(journalDir, { checkpoint: { ...checkpoint, mode: "seal" } }).close();
  }
  const journal = openFilePaymentJournal(journalDir, { checkpoint, now });
  const token = randomBytes(32).toString("hex");
  const executor = createPaymentExecutor({
    internalToken: token,
    adapter: createX402EvmAdapter({
      network: c.network,
      rpc: o.rpc,
      loadWalletKey: o.loadWalletKey,
      approvedRecipients: [...new Set(c.services.map((s) => s.pay_to))],
      endpoints: o.endpoints,
      fetch: o.fetch,
      now,
      receiptTimeoutMs: o.receiptTimeoutMs ?? 60_000,
      receiptPollMs: o.receiptPollMs ?? 2_000,
      log: o.log,
    }),
    verification: { expectedAudience: GATEWAY_AUDIENCE, trustedKeySets: [auth.trustMaterial.keySet], trustedAuthorizationAuthorities: [auth.trustMaterial.authority], now },
    journal,
    authority: createLocalExecutionAuthority(auth, execKey, LOCAL_JOURNAL_ID),
  });
  const gateway = createPaymentGateway({
    expectedAudience: GATEWAY_AUDIENCE,
    trustedKeySets: [auth.trustMaterial.keySet],
    trustedAuthorizationAuthorities: [auth.trustMaterial.authority],
    internalToken: token,
    executor: { handle: executor.handle },
    replayStore: createInMemoryReplayStore(),
    now,
    timeoutMs: 180_000,
  });

  return {
    /** PDP decision for an exact request. */
    authorize: (r: PurchaseRequest) => auth.authorize(r),
    /** PEP + executor: pays only what the authorization binds. */
    async purchase(a: { request: PurchaseRequest; intent_ref: unknown; authorization: unknown }) {
      const r = await gateway.submit({ action: { request: a.request, intent_ref: a.intent_ref }, authorization: a.authorization });
      return { status: r.status, ...r.body };
    },
    /** One outcome-report pass: settles the budget from the journal. */
    async report() {
      await createOutcomeReporter({ journal, key: execKey, inFlight: executor.inFlight, transport: { settle: async (s) => ({ status: 200, body: await auth.settle(s) }) } }).run();
    },
    spent: async () => (await store.load()).state.budget.spent_in_period[AGENT_ID] ?? 0n,
    reservation: async (authId: string) => (await store.load()).reservations[authId],
    journal,
    close: () => journal.close(),
  };
}

export type GuardedStack = ReturnType<typeof createGuardedStack>;

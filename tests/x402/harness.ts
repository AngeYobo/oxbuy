// SPDX-License-Identifier: MIT
/**
 * In-process OxDeAI x402 world for the testnet-integration tests: the real authorization service,
 * gateway, executor, durable journal + checkpoint, outcome reporter, the real x402 EIP-3009 adapter,
 * the real x402 seller, and the HTTP JSON-RPC client, against SimChain / SimFacilitator.
 *
 * Synthetic credentials only: the payer key is random per test and never written to evidence.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInMemoryReplayStore, INTERNAL_EXECUTOR_TOKEN_HEADER, type ReplayStore } from "@oxdeai/guard";
import type { PurchaseRequest } from "../../src/agent/purchase-request.ts";
import { createX402EvmAdapter, type X402EvmConfig } from "../../src/adapters/x402-evm/x402-evm.ts";
import { createAuthorizationService } from "../../src/authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../../src/authorization/policy-state.ts";
import { addressOfPrivateKey, eip3009NonceForIntent } from "../../src/chain/evm.ts";
import { createHttpRpc } from "../../src/chain/rpc.ts";
import { createLocalExecutionAuthority, type ExecutionAuthority } from "../../src/executor/execution-authority.ts";
import { createPaymentExecutor, type PaymentExecutor } from "../../src/executor/executor.ts";
import { createOutcomeReporter } from "../../src/executor/outcome-reporter.ts";
import type { PaymentAdapter } from "../../src/executor/payment-adapter.ts";
import { initFilePaymentJournal, openFilePaymentJournal, type FilePaymentJournal } from "../../src/executor/payment-journal.ts";
import { createPaymentGateway } from "../../src/gateway/gateway.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, LOCAL_JOURNAL_ID, PDP_ISSUER, POLICY_VERSION } from "../../src/system.ts";
import { startSeller, type Seller, type SellerHooks, type SellerRoute } from "../../src/x402/seller.ts";
import { TESTNET_NETWORK, TESTNET_SELLER_ORIGIN, TESTNET_SELLER_PATH, TESTNET_USDC, testnetPolicyState, testnetRequirements, testnetService } from "../../src/x402/testnet-profile.ts";
import { createSimChain, createSimFacilitator } from "./sim.ts";

export const PRICE = 1_000n; // 0.001 USDC
const TOKEN = randomBytes(32).toString("hex");
const headers = { [INTERNAL_EXECUTOR_TOKEN_HEADER]: TOKEN };

export type World = Awaited<ReturnType<typeof x402World>>;

export async function x402World(o: { budget?: bigint; ttlSeconds?: number; sellerHooks?: SellerHooks; adapter?: Partial<X402EvmConfig>; x402Version?: 1 | 2 } = {}) {
  let now = Math.floor(Date.now() / 1000);
  const clock = { now: () => now, advance: (s: number) => void (now += s) };

  const payerKey = randomBytes(32);
  const payer = addressOfPrivateKey(payerKey);
  const payee = addressOfPrivateKey(randomBytes(32));
  const chain = createSimChain({ network: TESTNET_NETWORK, asset: TESTNET_USDC, now: clock.now });
  const rpcUrl = await chain.listen();
  chain.mint(payer, 1_000_000n);
  const facilitator = createSimFacilitator(chain, TESTNET_NETWORK);

  const service = testnetService(payee, PRICE);
  const route: SellerRoute = {
    method: "POST",
    path: TESTNET_SELLER_PATH,
    description: "OxDeAI x402 testnet demo report",
    // The 402 names the token in Circle's checksummed spelling, as the real network does.
    requirements: { ...testnetRequirements(service), asset: "0x01C5C0122039549AD1493B8220cABEdD739BC44E" },
    body: () => JSON.stringify({ report: "paid content" }),
  };
  const seller: Seller = await startSeller({ publicOrigin: TESTNET_SELLER_ORIGIN, routes: [route], facilitator: facilitator.client, hooks: o.sellerHooks, x402Version: o.x402Version });

  // Authorization service (PDP + execution authority).
  const store = createInMemoryPolicyStateStore(testnetPolicyState(service, { budget: o.budget ?? 5_000n, perActionMax: 2_000n }));
  const reportKeys = generateKeyPairSync("ed25519");
  const execKey = { privateKeyPem: reportKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), kid: "exec-x402" };
  const auth = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: GATEWAY_AUDIENCE,
    agentId: AGENT_ID,
    ttlSeconds: o.ttlSeconds ?? 60,
    stateStore: store,
    now: clock.now,
    executorReportKey: { publicKeyPem: reportKeys.publicKey.export({ type: "spki", format: "pem" }).toString(), kid: execKey.kid },
  });
  const local = createLocalExecutionAuthority(auth, execKey, LOCAL_JOURNAL_ID);
  const down = { claim: false, void: false };
  const authority: ExecutionAuthority = {
    claim: (c) => (down.claim ? Promise.reject(new Error("ECONNREFUSED")) : local.claim(c)),
    void: (v) => (down.void ? Promise.reject(new Error("ECONNREFUSED")) : local.void(v)),
  };

  // Executor-private wallet: counted, so tests can prove the key was never even read.
  const wallet = { loads: 0 };
  const rpc = createHttpRpc(rpcUrl, { timeoutMs: 2_000 });
  const adapterConfig: X402EvmConfig = {
    network: TESTNET_NETWORK.caip2,
    rpc,
    loadWalletKey: () => {
      wallet.loads += 1;
      return Uint8Array.from(payerKey);
    },
    approvedRecipients: [payee],
    endpoints: { [TESTNET_SELLER_ORIGIN]: seller.url },
    now: clock.now,
    receiptTimeoutMs: 1_500,
    receiptPollMs: 50,
    httpTimeoutMs: 5_000,
    ...o.adapter,
  };

  // Durable journal + checkpoint (unit-test layout: no chattr; see tests/executor/payment-journal.test.ts).
  const dir = mkdtempSync(join(tmpdir(), "oxdeai-x402-"));
  const journalDir = join(dir, "journal");
  const checkpoint = { path: join(dir, "checkpoint.log"), requireAppendOnly: false };
  initFilePaymentJournal(journalDir);
  writeFileSync(checkpoint.path, "");
  openFilePaymentJournal(journalDir, { checkpoint: { ...checkpoint, mode: "seal" } }).close();

  let journal: FilePaymentJournal = openFilePaymentJournal(journalDir, { checkpoint, now: clock.now });
  const wrap = { adapter: (a: PaymentAdapter) => a };
  const build = () =>
    createPaymentExecutor({
      internalToken: TOKEN,
      adapter: wrap.adapter(createX402EvmAdapter(adapterConfig)),
      verification: { expectedAudience: GATEWAY_AUDIENCE, trustedKeySets: [auth.trustMaterial.keySet], trustedAuthorizationAuthorities: [auth.trustMaterial.authority], now: clock.now },
      journal,
      authority,
    });
  let executor: PaymentExecutor = build();
  let replayStore: ReplayStore = createInMemoryReplayStore();
  const buildGateway = () =>
    createPaymentGateway({
      expectedAudience: GATEWAY_AUDIENCE,
      trustedKeySets: [auth.trustMaterial.keySet],
      trustedAuthorizationAuthorities: [auth.trustMaterial.authority],
      internalToken: TOKEN,
      executor: { handle: (b, h) => executor.handle(b, h) },
      replayStore,
      now: clock.now,
      timeoutMs: 20_000,
    });
  let gateway = buildGateway();

  const request = (over: Partial<PurchaseRequest> = {}): PurchaseRequest => ({
    service_id: service.service_id,
    method: "POST",
    url: `${service.resource}?topic=celo`,
    body: JSON.stringify({ q: "oxdeai" }),
    network: service.network,
    asset: service.asset,
    recipient: service.pay_to,
    max_amount: PRICE.toString(),
    ...over,
  });

  async function authorize(over: Partial<PurchaseRequest> = {}) {
    const req = request(over);
    const d = await auth.authorize(req);
    if (d.decision !== "ALLOW") throw new Error(`expected ALLOW: ${JSON.stringify(d)}`);
    return { request: req, intent_ref: d.intent_ref, authorization: d.authorization };
  }
  async function submit(a: { request: PurchaseRequest; intent_ref: unknown; authorization: unknown }) {
    const r = await gateway.submit({ action: { request: a.request, intent_ref: a.intent_ref }, authorization: a.authorization });
    return { status: r.status, ...r.body } as Record<string, any>;
  }
  const reservation = async (authId: string) => (await store.load()).reservations[authId]!;
  const spent = async () => (await store.load()).state.budget.spent_in_period[AGENT_ID] ?? 0n;
  /** One outcome-report pass from the journal to the auth service (budget settlement). */
  async function report() {
    await createOutcomeReporter({
      journal,
      key: execKey,
      inFlight: executor.inFlight,
      transport: { settle: async (signed) => ({ status: 200, body: await auth.settle(signed) }) },
    }).run();
  }
  /** "Restart" the executor process: same durable journal, new instance and adapter. */
  function restartExecutor() {
    journal.close();
    journal = openFilePaymentJournal(journalDir, { checkpoint, now: clock.now });
    executor = build();
  }
  function restartGateway() {
    replayStore = createInMemoryReplayStore();
    gateway = buildGateway();
  }

  return {
    clock,
    chain,
    facilitator,
    seller,
    route,
    service,
    payer,
    payee,
    wallet,
    down,
    auth,
    store,
    rpc,
    adapterConfig,
    wrap,
    dirs: { dir, journalDir, checkpoint },
    get journal() {
      return journal;
    },
    get executor() {
      return executor;
    },
    request,
    authorize,
    submit,
    executeDirect: (body: unknown, h: Record<string, string> = headers) => executor.handle(body, h),
    reservation,
    spent,
    report,
    restartExecutor,
    restartGateway,
    nonceFor: (intentHash: string) => eip3009NonceForIntent(intentHash),
    async close() {
      try {
        journal.close();
      } catch {
        /* already closed */
      }
      await seller.close();
      await chain.close();
      // Test-owned mkdtemp directory only (fail closed otherwise).
      if (!dir.startsWith(join(tmpdir(), "oxdeai-x402-")) || dir.includes("..")) throw new Error(`UNSAFE_CLEANUP_TARGET:${dir}`);
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

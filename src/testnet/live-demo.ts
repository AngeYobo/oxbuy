// SPDX-License-Identifier: MIT
/**
 * Live Celo Sepolia demonstration: a real x402 v2 / EIP-3009 payment under the OxDeAI authorization
 * boundary, plus three live negative checks. TESTNET ONLY: the network is fixed to Celo Sepolia
 * (eip155:11142220) and the RPC's chain id must equal it before anything is signed.
 *
 *   npm run testnet:live          (see docs/TESTNET-X402.md for setup; never commit the env values)
 *
 * Required environment:
 *   OXDEAI_TESTNET_PAYER_KEY_FILE   0600 file holding a TESTNET private key (hex) funded with Sepolia USDC
 *   OXDEAI_TESTNET_PAY_TO           approved recipient (lower-case address you control)
 *   OXDEAI_X402_API_KEY             Celo facilitator key for /settle (https://x402.celo.org)
 * Optional:
 *   OXDEAI_TESTNET_RPC_URL          default https://forno.celo-sepolia.celo-testnet.org
 *   OXDEAI_X402_FACILITATOR_URL     default https://api.x402.sepolia.celo.org
 *   OXDEAI_TESTNET_PRICE            atomic USDC units, default 1000 (0.001 USDC), max 2000
 *   OXDEAI_TESTNET_EVIDENCE_DIR     default evidence/testnet
 *
 * Scenarios (all must hold for exit code 0):
 *   L1 authorized payment: ALLOW, mined, AuthorizationUsed + Transfer verified on chain
 *   L2 replay of the consumed authorization: refused; no new transfer (balances, nonce state)
 *   L3 a 402 naming another recipient: refused before signing; no transfer
 *   L4 a 402 above the authorized maximum: refused before signing; no transfer
 * The evidence file holds hashes, explorer links, addresses and results; never a key.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInMemoryReplayStore } from "@oxdeai/guard";
import { createX402EvmAdapter } from "../adapters/x402-evm/x402-evm.ts";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../authorization/policy-state.ts";
import { authorizationConsumed, verifyOnchainSettlement, type OnchainSettlement } from "../chain/eip3009-evidence.ts";
import { addressOfPrivateKey, decodeWord, eip3009NonceForIntent, encodeBalanceOf, parsePrivateKey } from "../chain/evm.ts";
import { createHttpRpc } from "../chain/rpc.ts";
import { createLocalExecutionAuthority } from "../executor/execution-authority.ts";
import { createPaymentExecutor } from "../executor/executor.ts";
import { createOutcomeReporter } from "../executor/outcome-reporter.ts";
import { initFilePaymentJournal, openFilePaymentJournal } from "../executor/payment-journal.ts";
import { createPaymentGateway } from "../gateway/gateway.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, LOCAL_JOURNAL_ID, PDP_ISSUER, POLICY_VERSION } from "../system.ts";
import { createHttpFacilitatorClient } from "../x402/facilitator-client.ts";
import { startSeller } from "../x402/seller.ts";
import { TESTNET_NETWORK, TESTNET_SELLER_ORIGIN, TESTNET_SELLER_PATH, TESTNET_USDC, testnetPolicyState, testnetRequirements, testnetService } from "../x402/testnet-profile.ts";

export type LiveResult = { ok: boolean; evidencePath: string; evidence: Record<string, unknown> };

function required(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v) throw new Error(`LIVE_CONFIG_MISSING:${name} (see docs/TESTNET-X402.md)`);
  return v;
}

export async function runLiveDemo(env: NodeJS.ProcessEnv = process.env, log: (line: string) => void = (l) => process.stdout.write(`${l}\n`)): Promise<LiveResult> {
  const keyFile = required(env, "OXDEAI_TESTNET_PAYER_KEY_FILE");
  const payTo = required(env, "OXDEAI_TESTNET_PAY_TO").toLowerCase();
  const apiKey = required(env, "OXDEAI_X402_API_KEY");
  const rpcUrl = env.OXDEAI_TESTNET_RPC_URL ?? TESTNET_NETWORK.defaultRpcUrl;
  const facilitatorUrl = env.OXDEAI_X402_FACILITATOR_URL ?? TESTNET_NETWORK.facilitatorUrl;
  const price = BigInt(env.OXDEAI_TESTNET_PRICE ?? "1000");
  const evidenceRoot = resolve(env.OXDEAI_TESTNET_EVIDENCE_DIR ?? "evidence/testnet");

  if ((statSync(keyFile).mode & 0o077) !== 0) throw new Error(`LIVE_KEY_FILE_TOO_OPEN:${keyFile} must be mode 0600`);
  const payer = (() => {
    const k = parsePrivateKey(readFileSync(keyFile, "utf8"));
    const a = addressOfPrivateKey(k);
    k.fill(0);
    return a;
  })();
  if (payer === payTo) throw new Error("LIVE_CONFIG_INVALID:payer and recipient must differ");

  const rpc = createHttpRpc(rpcUrl, { timeoutMs: 15_000 });
  const chainId = await rpc.chainId();
  if (chainId !== TESTNET_NETWORK.chainId) throw new Error(`LIVE_WRONG_CHAIN:${chainId} is not Celo Sepolia (${TESTNET_NETWORK.chainId}); refusing`);
  const balance = async (who: string) => decodeWord(await rpc.call(TESTNET_USDC.address, encodeBalanceOf(who)));
  const before = { payer: await balance(payer), payee: await balance(payTo) };
  log(`payer ${payer} USDC ${before.payer}; recipient ${payTo} USDC ${before.payee}; chain ${chainId}`);
  if (before.payer < price) throw new Error(`LIVE_INSUFFICIENT_FUNDS:payer holds ${before.payer} < ${price} (fund it with Celo Sepolia USDC; docs/TESTNET-X402.md §4)`);

  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const runDir = join(evidenceRoot, runId);
  mkdirSync(runDir, { recursive: true });

  // Seller (payee side) with the real facilitator.
  const service = testnetService(payTo, price);
  const route = { method: "POST" as const, path: TESTNET_SELLER_PATH, description: "OxDeAI x402 testnet demo", requirements: testnetRequirements(service), body: () => JSON.stringify({ report: "OxDeAI x402 testnet demo content" }) };
  const sellerLog: Record<string, unknown>[] = [];
  const seller = await startSeller({ publicOrigin: TESTNET_SELLER_ORIGIN, routes: [route], facilitator: createHttpFacilitatorClient({ baseUrl: facilitatorUrl, apiKey }), log: (e) => sellerLog.push(e) });

  // OxDeAI side, in process (the process-isolated deployment is exercised offline: tests/isolation/x402-process.test.ts).
  const store = createInMemoryPolicyStateStore(testnetPolicyState(service));
  const rk = generateKeyPairSync("ed25519");
  const execKey = { privateKeyPem: rk.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), kid: "exec-live" };
  const auth = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: GATEWAY_AUDIENCE,
    agentId: AGENT_ID,
    ttlSeconds: 120,
    stateStore: store,
    now: () => Math.floor(Date.now() / 1000),
    executorReportKey: { publicKeyPem: rk.publicKey.export({ type: "spki", format: "pem" }).toString(), kid: execKey.kid },
  });
  const journalDir = join(runDir, "journal");
  const checkpoint = { path: join(runDir, "checkpoint.log"), requireAppendOnly: false };
  initFilePaymentJournal(journalDir);
  writeFileSync(checkpoint.path, "");
  openFilePaymentJournal(journalDir, { checkpoint: { ...checkpoint, mode: "seal" } }).close();
  const journal = openFilePaymentJournal(journalDir, { checkpoint });
  const adapterLog: Record<string, unknown>[] = [];
  const token = randomBytes(32).toString("hex");
  const executor = createPaymentExecutor({
    internalToken: token,
    adapter: createX402EvmAdapter({
      network: TESTNET_NETWORK.caip2,
      rpc,
      loadWalletKey: () => parsePrivateKey(readFileSync(keyFile, "utf8")),
      approvedRecipients: [payTo],
      endpoints: { [TESTNET_SELLER_ORIGIN]: seller.url },
      receiptTimeoutMs: 60_000,
      receiptPollMs: 2_000,
      log: (e) => adapterLog.push(e),
    }),
    verification: { expectedAudience: GATEWAY_AUDIENCE, trustedKeySets: [auth.trustMaterial.keySet], trustedAuthorizationAuthorities: [auth.trustMaterial.authority], now: () => Math.floor(Date.now() / 1000) },
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
    now: () => Math.floor(Date.now() / 1000),
    timeoutMs: 120_000,
  });
  const request = (q: string) => ({
    service_id: service.service_id,
    method: "POST" as const,
    url: `${service.resource}?run=${runId}&q=${q}`,
    body: JSON.stringify({ q }),
    network: service.network,
    asset: service.asset,
    recipient: service.pay_to,
    max_amount: price.toString(),
  });
  const authorize = async (q: string) => {
    const d = await auth.authorize(request(q));
    if (d.decision !== "ALLOW") throw new Error(`LIVE_AUTHORIZE_DENIED:${JSON.stringify(d)}`);
    return { request: request(q), intent_ref: d.intent_ref, authorization: d.authorization };
  };
  const submit = async (a: Awaited<ReturnType<typeof authorize>>) => (await gateway.submit({ action: { request: a.request, intent_ref: a.intent_ref }, authorization: a.authorization })).body;

  const scenarios: Record<string, unknown>[] = [];
  let settlement: OnchainSettlement | undefined;
  let ok = true;
  const expect = (id: string, cond: boolean, detail: Record<string, unknown>) => {
    scenarios.push({ id, result: cond ? "PASS" : "FAIL", ...detail });
    if (!cond) ok = false;
    log(`${id} ${cond ? "PASS" : "FAIL"} ${JSON.stringify(detail)}`);
  };
  try {
    // L1
    const a = await authorize("l1");
    const r1 = await submit(a);
    const nonce = eip3009NonceForIntent(a.authorization.intent_hash);
    if (r1.decision === "ALLOW") {
      const tx = (r1.receipt as { reference: string }).reference;
      const binding = journal.inspect(a.authorization.intent_hash)?.payment_binding;
      if (!binding) throw new Error("PAYMENT_BINDING_REQUIRED");
      settlement = await verifyOnchainSettlement(rpc, TESTNET_NETWORK, { asset: TESTNET_USDC.address, payer, payTo, nonce, maxAmount: price, signedAmount: BigInt(binding.amount), txHash: tx });
    }
    expect("L1-authorized-payment", r1.decision === "ALLOW" && settlement !== undefined, {
      decision: r1.decision,
      detail: r1.detail,
      tx: settlement?.reference,
      explorer: settlement ? TESTNET_NETWORK.explorerTxUrl(settlement.reference) : undefined,
      block: settlement?.block,
      amount: settlement?.amount,
      nonce,
      auth_id: a.authorization.auth_id,
      intent_hash: a.authorization.intent_hash,
    });
    // L2
    const mid = await balance(payTo);
    const r2 = await submit(a);
    expect("L2-replay-refused", r2.decision !== "ALLOW" && (await balance(payTo)) === mid && (await authorizationConsumed(rpc, { asset: TESTNET_USDC.address, payer, nonce })), { decision: r2.decision, reason: r2.reason });
    // L3
    const b = await authorize("l3");
    seller.routes[0] = { ...route, requirements: { ...route.requirements, payTo: payer } };
    const r3 = await submit(b);
    seller.routes[0] = route;
    expect("L3-recipient-mismatch-refused", r3.decision !== "ALLOW" && /RECIPIENT/.test(String(r3.detail)) && !(await authorizationConsumed(rpc, { asset: TESTNET_USDC.address, payer, nonce: eip3009NonceForIntent(b.authorization.intent_hash) })), { decision: r3.decision, detail: r3.detail, final: r3.final });
    // L4
    const c = await authorize("l4");
    seller.routes[0] = { ...route, requirements: { ...route.requirements, amount: (price + 1n).toString() } };
    const r4 = await submit(c);
    seller.routes[0] = route;
    expect("L4-amount-above-authorization-refused", r4.decision !== "ALLOW" && /EXCEEDS_AUTHORIZED_MAX/.test(String(r4.detail)) && !(await authorizationConsumed(rpc, { asset: TESTNET_USDC.address, payer, nonce: eip3009NonceForIntent(c.authorization.intent_hash) })), { decision: r4.decision, detail: r4.detail, final: r4.final });
    // Budget settlement from the journal.
    await createOutcomeReporter({ journal, key: execKey, inFlight: executor.inFlight, transport: { settle: async (s) => ({ status: 200, body: await auth.settle(s) }) } }).run();
    const res = (await store.load()).reservations[a.authorization.auth_id];
    expect("L5-budget-settled", res?.state === "CONFIRMED" && res.charged === settlement?.amount, { state: res?.state, charged: res?.charged });
  } finally {
    journal.close();
    await seller.close();
  }
  const after = { payer: await balance(payer), payee: await balance(payTo) };
  const evidence = {
    schema: "oxdeai-celo-poc/testnet-live-evidence/v1",
    run_id: runId,
    network: TESTNET_NETWORK.caip2,
    chain_id: chainId.toString(),
    rpc_url: rpcUrl,
    facilitator_url: facilitatorUrl,
    asset: TESTNET_USDC.address,
    payer,
    pay_to: payTo,
    price: price.toString(),
    balances: { before: { payer: before.payer.toString(), payee: before.payee.toString() }, after: { payer: after.payer.toString(), payee: after.payee.toString() } },
    scenarios,
    settlement: settlement ?? null,
    adapter_events: adapterLog,
    seller_events: sellerLog,
    result: ok ? "PASS" : "FAIL",
  };
  const evidencePath = join(runDir, "live-evidence.json");
  writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  log(`evidence: ${evidencePath} (${ok ? "PASS" : "FAIL"})`);
  return { ok, evidencePath, evidence };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runLiveDemo()
    .then((r) => process.exit(r.ok ? 0 : 1))
    .catch((err) => {
      process.stderr.write(`${(err as Error).message}\n`);
      process.exit(2);
    });
}

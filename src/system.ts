// SPDX-License-Identifier: MIT
/**
 * Composition root for the local Phase 1 system.
 *
 * Builds the authorization service (PDP), gateway (PEP), executor, and mock
 * buy adapter, and returns:
 *   - `client`: the only object handed to the agent;
 *   - `harness`: operator/test handles for inspection and fault injection.
 *     Never handed to the agent.
 *
 * The internal executor token is created here and captured only by the
 * gateway and executor closures. It is not returned.
 *
 * In-process limitation: all components share one Node.js process. Closures
 * keep the agent from *being handed* the executor, but they are not an
 * isolation boundary against code that runs in the same process. This
 * composition is the test harness for protocol logic; the process-isolated
 * deployment is src/isolation/launcher.ts. See docs/ARCHITECTURE.md.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createInMemoryReplayStore, type ReplayStore } from "@oxdeai/guard";
import type { State } from "@oxdeai/core";
import type { AgentGatewayClient, PurchaseResult } from "./agent/agent.ts";
import { createMockBuyAdapter, type MockBuy, type MockService } from "./adapters/mock-buy/mock-buy.ts";
import { createAuthorizationService } from "./authorization/authorization-service.ts";
import { paymentTarget, validatePurchaseRequest } from "./authorization/intent.ts";
import { createInMemoryPolicyStateStore } from "./authorization/policy-state.ts";
import { createLocalExecutionAuthority } from "./executor/execution-authority.ts";
import { createPaymentExecutor, type PaymentExecutor } from "./executor/executor.ts";
import { createInMemoryPaymentJournal } from "./executor/payment-journal.ts";
import type { PaymentAdapter } from "./executor/payment-adapter.ts";
import { createPaymentGateway } from "./gateway/gateway.ts";

export const AGENT_ID = "agent-celo-poc-1";
export const GATEWAY_AUDIENCE = "oxdeai-celo-poc.gateway";
export const PDP_ISSUER = "oxdeai-celo-poc.pdp";
export const POLICY_VERSION = "x402-poc-v1";
/** Fixed start time so runs are reproducible. Unix seconds. */
export const DEFAULT_START_TIME = 1_800_000_000;
/** Gateway -> executor timeout. Expiry is reported INDETERMINATE. */
export const GATEWAY_TIMEOUT_MS = 30_000;

// Mock identifiers. Not real networks, tokens, or addresses.
export const MOCK_NETWORK = "mock-celo";
export const MOCK_ASSET = "mock-usdc";

export const SERVICES = {
  weather: {
    service_id: "weather-api",
    resource: "https://api.example.test/v1/weather",
    network: MOCK_NETWORK,
    asset: MOCK_ASSET,
    pay_to: "0x1111111111111111111111111111111111111111",
    price: 10_000n,
  },
  premium: {
    service_id: "premium-api",
    resource: "https://api.example.test/v1/premium",
    network: MOCK_NETWORK,
    asset: MOCK_ASSET,
    pay_to: "0x1111111111111111111111111111111111111111",
    price: 30_000n,
  },
  unlisted: {
    service_id: "unlisted-api",
    resource: "https://unlisted.example.test/v1/data",
    network: MOCK_NETWORK,
    asset: MOCK_ASSET,
    pay_to: "0x2222222222222222222222222222222222222222",
    price: 10_000n,
  },
} as const satisfies Record<string, MockService>;

export const POLICY = {
  perActionMax: 20_000n,
  budget: 50_000n,
  ttlSeconds: 60,
  /** Allowed (network, recipient, service) tuples. */
  allowedServices: [SERVICES.weather, SERVICES.premium],
};

export function initialPolicyState(): State {
  return policyStateFor({ services: POLICY.allowedServices, assets: [MOCK_ASSET], budget: POLICY.budget, perActionMax: POLICY.perActionMax });
}

/**
 * Policy state for an explicit allowlist (the mock deployment above, or the x402 testnet profile,
 * src/x402/testnet-profile.ts). Same limits and structure; only the allowed targets, assets, budget
 * and per-action maximum differ.
 */
export function policyStateFor(p: {
  services: readonly Pick<MockService, "service_id" | "resource" | "network" | "asset" | "pay_to">[];
  assets: readonly string[];
  budget: bigint;
  perActionMax: bigint;
}): State {
  const targets = p.services.map((s) =>
    paymentTarget(
      validatePurchaseRequest({
        service_id: s.service_id,
        method: "GET",
        url: s.resource,
        body: null,
        network: s.network,
        asset: s.asset,
        recipient: s.pay_to,
        max_amount: "1",
      }),
    ),
  );
  return {
    policy_version: POLICY_VERSION,
    period_id: "phase1",
    kill_switch: { global: false, agents: {} },
    allowlists: { action_types: ["PAYMENT"], assets: [...p.assets], targets },
    budget: { budget_limit: { [AGENT_ID]: p.budget }, spent_in_period: {} },
    max_amount_per_action: { [AGENT_ID]: p.perActionMax },
    velocity: { config: { window_seconds: 60, max_actions: 100 }, counters: {} },
    replay: { window_seconds: 3600, max_nonces_per_agent: 256, nonces: {} },
    recursion: { max_depth: { [AGENT_ID]: 1 } },
    concurrency: { max_concurrent: { [AGENT_ID]: 100 }, active: {}, active_auths: {} },
    tool_limits: { window_seconds: 60, max_calls: { [AGENT_ID]: 100 }, calls: {} },
  };
}

/** Replay store wrapper with an availability switch for fault injection. */
function createSwitchableReplayStore() {
  const inner = createInMemoryReplayStore();
  let available = true;
  const store: ReplayStore & { setAvailable(value: boolean): void } = {
    async consumeAuthId(authId, opts) {
      if (!available) throw new Error("replay store unavailable");
      return inner.consumeAuthId(authId, opts);
    },
    setAvailable(value) {
      available = value;
    },
  };
  return store;
}

/** Fault injection for tests. Every hook sits on the trusted side. */
export type LocalSystemFaults = {
  /** Wrap the executor's payment adapter (e.g. fail after settlement). */
  readonly wrapAdapter?: (inner: PaymentAdapter, mock: MockBuy["inspect"]) => PaymentAdapter;
  /** Wrap the gateway -> executor transport (e.g. lose the response). */
  readonly wrapExecutorHandle?: (inner: PaymentExecutor["handle"]) => PaymentExecutor["handle"];
  readonly gatewayTimeoutMs?: number;
};

/** Placeholder journal id of the in-process harness (no execution domain). */
export const LOCAL_JOURNAL_ID = "0".repeat(32);

export function createLocalSystem(opts: { startTime?: number; initialState?: State | null; faults?: LocalSystemFaults } = {}) {
  let now = opts.startTime ?? DEFAULT_START_TIME;
  const clock = {
    now: () => now,
    advance(seconds: number) {
      now += seconds;
    },
  };

  const policyStore = createInMemoryPolicyStateStore(opts.initialState === null ? undefined : (opts.initialState ?? initialPolicyState()));
  // Executor message key (claims, voids, reports): the same signed path as the process deployment.
  const reportKeys = generateKeyPairSync("ed25519");
  const executorReportKey = {
    privateKeyPem: reportKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: reportKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    kid: `exec-${randomBytes(4).toString("hex")}`,
  };
  const authService = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: GATEWAY_AUDIENCE,
    agentId: AGENT_ID,
    ttlSeconds: POLICY.ttlSeconds,
    stateStore: policyStore,
    now: clock.now,
    executorReportKey: { publicKeyPem: executorReportKey.publicKeyPem, kid: executorReportKey.kid },
  });
  // No execution domain in-process: reservations are unbound, and so is this authority's (placeholder) journal id.
  const authority = createLocalExecutionAuthority(authService, executorReportKey, LOCAL_JOURNAL_ID);

  const mockBuy = createMockBuyAdapter(Object.values(SERVICES));
  const internalToken = randomBytes(32).toString("hex");
  const faults = opts.faults ?? {};
  const adapter = faults.wrapAdapter ? faults.wrapAdapter(mockBuy.adapter, mockBuy.inspect) : mockBuy.adapter;
  const executor = createPaymentExecutor({
    internalToken,
    adapter,
    verification: {
      expectedAudience: GATEWAY_AUDIENCE,
      trustedKeySets: [authService.trustMaterial.keySet],
      trustedAuthorizationAuthorities: [authService.trustMaterial.authority],
      now: clock.now,
    },
    // In-process harness only; the executor process uses the durable journal.
    journal: createInMemoryPaymentJournal(clock.now),
    authority,
  });
  const replayStore = createSwitchableReplayStore();
  const gateway = createPaymentGateway({
    expectedAudience: GATEWAY_AUDIENCE,
    trustedKeySets: [authService.trustMaterial.keySet],
    trustedAuthorizationAuthorities: [authService.trustMaterial.authority],
    internalToken,
    executor: { handle: faults.wrapExecutorHandle ? faults.wrapExecutorHandle(executor.handle) : executor.handle },
    replayStore,
    now: clock.now,
    timeoutMs: faults.gatewayTimeoutMs ?? GATEWAY_TIMEOUT_MS,
  });

  const client: AgentGatewayClient = {
    async quote(request) {
      const q = await mockBuy.adapter.quote(request);
      return { network: q.network, asset: q.asset, pay_to: q.pay_to, amount: q.amount };
    },
    authorize: authService.authorize,
    async purchase({ request, intent_ref, authorization }): Promise<PurchaseResult> {
      const r = await gateway.submit({ action: { request, intent_ref }, authorization });
      return {
        decision: r.body.decision,
        executed: r.body.executed,
        status: r.status,
        reason: r.body.reason,
        detail: r.body.detail,
        ...(r.body.final !== undefined ? { final: r.body.final } : {}),
        receipt: r.body.receipt,
        auth_id: r.body.auth_id,
        intent_hash: r.body.intent_hash,
      };
    },
  };
  Object.freeze(client);

  return {
    client,
    harness: { clock, policyStore, replayStore, authService, gateway, executor, authority, executorReportKey, mockBuy: mockBuy.inspect },
  };
}

export type LocalSystem = ReturnType<typeof createLocalSystem>;

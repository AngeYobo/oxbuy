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
 * isolation boundary against code that runs in the same process. See
 * docs/ARCHITECTURE.md.
 */
import { randomBytes } from "node:crypto";
import { createInMemoryReplayStore, type ReplayStore } from "@oxdeai/guard";
import type { State } from "@oxdeai/core";
import type { AgentGatewayClient, PurchaseResult } from "./agent/agent.ts";
import { createMockBuyAdapter, type MockService } from "./adapters/mock-buy/mock-buy.ts";
import { createAuthorizationService } from "./authorization/authorization-service.ts";
import { paymentTarget, validatePurchaseRequest } from "./authorization/intent.ts";
import { createInMemoryPolicyStateStore } from "./authorization/policy-state.ts";
import { createPaymentExecutor } from "./executor/executor.ts";
import { createPaymentGateway } from "./gateway/gateway.ts";

export const AGENT_ID = "agent-celo-poc-1";
export const GATEWAY_AUDIENCE = "oxdeai-celo-poc.gateway";
export const PDP_ISSUER = "oxdeai-celo-poc.pdp";
export const POLICY_VERSION = "x402-poc-v1";
/** Fixed start time so runs are reproducible. Unix seconds. */
export const DEFAULT_START_TIME = 1_800_000_000;

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
  const targets = POLICY.allowedServices.map((s) =>
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
    allowlists: { action_types: ["PAYMENT"], assets: [MOCK_ASSET], targets },
    budget: { budget_limit: { [AGENT_ID]: POLICY.budget }, spent_in_period: {} },
    max_amount_per_action: { [AGENT_ID]: POLICY.perActionMax },
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

export function createLocalSystem(opts: { startTime?: number; initialState?: State | null } = {}) {
  let now = opts.startTime ?? DEFAULT_START_TIME;
  const clock = {
    now: () => now,
    advance(seconds: number) {
      now += seconds;
    },
  };

  const policyStore = createInMemoryPolicyStateStore(opts.initialState === null ? undefined : (opts.initialState ?? initialPolicyState()));
  const authService = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: GATEWAY_AUDIENCE,
    agentId: AGENT_ID,
    ttlSeconds: POLICY.ttlSeconds,
    stateStore: policyStore,
    now: clock.now,
  });

  const mockBuy = createMockBuyAdapter(Object.values(SERVICES));
  const internalToken = randomBytes(32).toString("hex");
  const executor = createPaymentExecutor({ internalToken, adapter: mockBuy.adapter });
  const replayStore = createSwitchableReplayStore();
  const gateway = createPaymentGateway({
    expectedAudience: GATEWAY_AUDIENCE,
    trustedKeySets: [authService.trustMaterial.keySet],
    trustedAuthorizationAuthorities: [authService.trustMaterial.authority],
    internalToken,
    executor,
    replayStore,
    now: clock.now,
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
        detail: (r.body.upstream_error as { error?: string } | undefined)?.error,
        receipt: r.body.upstream_result,
      };
    },
  };
  Object.freeze(client);

  return {
    client,
    harness: { clock, policyStore, replayStore, authService, gateway, executor, mockBuy: mockBuy.inspect },
  };
}

export type LocalSystem = ReturnType<typeof createLocalSystem>;

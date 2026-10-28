// SPDX-License-Identifier: MIT
/**
 * CX2 (Phase 2C): an authorization is bound to one execution domain through
 * its signed audience. With the SAME PDP signing key and trust material, an
 * executor of another domain (another journal) refuses it before any payment
 * step and without consuming it; the executor of its own domain pays it.
 * Isolates the binding from per-deployment key rotation.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import { createMockBuyAdapter } from "../../src/adapters/mock-buy/mock-buy.ts";
import { createAuthorizationService } from "../../src/authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../../src/authorization/policy-state.ts";
import { domainAudience, domainId } from "../../src/executor/execution-domain.ts";
import { createPaymentExecutor } from "../../src/executor/executor.ts";
import { createInMemoryPaymentJournal } from "../../src/executor/payment-journal.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, initialPolicyState, PDP_ISSUER, POLICY_VERSION, SERVICES } from "../../src/system.ts";
import { requestFor } from "../helpers.ts";

const D1 = { journal_id: "1".repeat(32), executor_uid: 994 };
const D2 = { journal_id: "2".repeat(32), executor_uid: 994 };
const TOKEN = "t".repeat(64);
const now = () => Math.floor(Date.now() / 1000);
const pem = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();

function pdp(domain: typeof D1) {
  return createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: domainAudience(GATEWAY_AUDIENCE, domain),
    agentId: AGENT_ID,
    ttlSeconds: 60,
    stateStore: createInMemoryPolicyStateStore(initialPolicyState()),
    now,
    signingKey: { privateKeyPem: pem, kid: "pdp-shared" },
    executionDomain: domain,
  });
}

function executor(domain: typeof D1, trust: ReturnType<typeof pdp>["trustMaterial"]) {
  const mock = createMockBuyAdapter(Object.values(SERVICES));
  const journal = createInMemoryPaymentJournal(now);
  const ex = createPaymentExecutor({
    internalToken: TOKEN,
    adapter: mock.adapter,
    verification: { expectedAudience: domainAudience(GATEWAY_AUDIENCE, domain), trustedKeySets: [trust.keySet], trustedAuthorizationAuthorities: [trust.authority], now },
    journal,
  });
  return { ex, mock, journal };
}

test("CX2e domain ids differ per journal and per executor uid; the audience names the domain", () => {
  assert.notEqual(domainId(D1), domainId(D2));
  assert.notEqual(domainId(D1), domainId({ ...D1, executor_uid: 995 }));
  assert.ok(domainAudience(GATEWAY_AUDIENCE, D1).endsWith(`#exec-domain=${domainId(D1)}`));
  assert.throws(() => domainId({ journal_id: "not-hex", executor_uid: 1 }), /EXECUTION_DOMAIN_INVALID/);
});

test("CX2e same signing key, other domain: refused before payment, not consumed; its own domain pays it once", async () => {
  const auth = pdp(D1);
  const request = requestFor(SERVICES.weather);
  const d = await auth.authorize(request);
  assert.equal(d.decision, "ALLOW");
  if (d.decision !== "ALLOW") return;
  assert.equal(d.authorization.audience, domainAudience(GATEWAY_AUDIENCE, D1));
  const body = { action: { request, intent_ref: d.intent_ref }, authorization: d.authorization };
  const headers = { [INTERNAL_EXECUTOR_TOKEN_HEADER]: TOKEN };

  const foreign = executor(D2, auth.trustMaterial);
  const r2 = await foreign.ex.handle(body, headers);
  assert.equal(r2.status, 409);
  assert.match((r2.body as { error: string }).error, /EXECUTOR_AUTHORIZATION_INVALID:.*AUTH_AUDIENCE_MISMATCH/);
  assert.equal(foreign.mock.inspect.counters.payments, 0);
  assert.deepEqual(foreign.journal.list(), [], "nothing reserved in the foreign domain's journal");

  const own = executor(D1, auth.trustMaterial);
  const r1 = await own.ex.handle(body, headers);
  assert.equal(r1.status, 200, JSON.stringify(r1.body));
  assert.equal(own.mock.inspect.counters.payments, 1);
  assert.equal((await own.ex.handle(body, headers)).status, 409, "and never twice");
  assert.equal(own.mock.inspect.counters.payments, 1);
});

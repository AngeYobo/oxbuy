// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyAuthorization } from "@oxdeai/core";
import { createPurchaseAgent } from "../../src/agent/agent.ts";
import { GATEWAY_AUDIENCE } from "../../src/system.ts";
import { authorize, newSystem, requestFor, SERVICES } from "../helpers.ts";

test("T1 valid authorized request: ALLOW and exactly one mock payment", async () => {
  const sys = newSystem();
  const auth = await authorize(sys, requestFor(SERVICES.weather));

  // The artifact is a real, strictly verifiable OxDeAI AuthorizationV1.
  const verified = verifyAuthorization(auth.authorization, {
    mode: "strict",
    now: sys.harness.clock.now(),
    trustedKeySets: [sys.harness.authService.trustMaterial.keySet],
    trustedAuthorizationAuthorities: [sys.harness.authService.trustMaterial.authority],
    expectedAudience: GATEWAY_AUDIENCE,
    requireSignatureVerification: true,
  });
  assert.equal(verified.status, "ok");
  assert.equal(verified.signatureVerified, true);
  assert.equal(auth.authorization.decision, "ALLOW");

  const result = await sys.client.purchase(auth);
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.executed, true);
  assert.equal(result.status, 200);
  const receipt = result.receipt as { reference: string; amount: string; pay_to: string };
  assert.match(receipt.reference, /^mock-/);
  assert.equal(receipt.amount, "10000");
  assert.equal(receipt.pay_to, SERVICES.weather.pay_to);
  assert.equal(sys.harness.mockBuy.counters.payments, 1);
});

test("T1b agent flow quote -> authorize -> purchase executes once", async () => {
  const sys = newSystem();
  const agent = createPurchaseAgent(sys.client);
  const outcome = await agent.buy({
    service_id: SERVICES.weather.service_id,
    method: "GET",
    url: `${SERVICES.weather.resource}?city=nairobi`,
    body: null,
  });
  assert.equal(outcome.stage, "purchase");
  if (outcome.stage !== "purchase") return;
  assert.equal(outcome.result.decision, "ALLOW");
  assert.equal(outcome.result.executed, true);
  assert.equal(sys.harness.mockBuy.counters.payments, 1);
});

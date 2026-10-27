// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import type { AuthorizationV1 } from "@oxdeai/core";
import type { IntentRef, PurchaseRequest } from "../src/agent/purchase-request.ts";
import { createLocalSystem, type LocalSystem, SERVICES } from "../src/system.ts";

type Service = (typeof SERVICES)[keyof typeof SERVICES];

export function requestFor(service: Service, overrides: Partial<PurchaseRequest> = {}): PurchaseRequest {
  return {
    service_id: service.service_id,
    method: "POST",
    url: `${service.resource}?city=lagos`,
    body: JSON.stringify({ units: "metric", days: 3 }),
    network: service.network,
    asset: service.asset,
    recipient: service.pay_to,
    max_amount: service.price.toString(),
    ...overrides,
  };
}

export type Authorized = { request: PurchaseRequest; intent_ref: IntentRef; authorization: AuthorizationV1 };

/** Obtain an ALLOW authorization or fail the test. */
export async function authorize(sys: LocalSystem, request: PurchaseRequest): Promise<Authorized> {
  const result = await sys.client.authorize(request);
  assert.equal(result.decision, "ALLOW", `expected ALLOW, got ${JSON.stringify(result)}`);
  if (result.decision !== "ALLOW") throw new Error("unreachable");
  return { request, intent_ref: result.intent_ref, authorization: result.authorization };
}

/** The mock buy adapter never signed or settled anything. */
export function assertNoPayment(sys: LocalSystem): void {
  const { counters, ledger } = sys.harness.mockBuy;
  assert.equal(counters.signatures, 0, "mock buy signed a payment");
  assert.equal(counters.payments, 0, "mock buy settled a payment");
  assert.equal(ledger.length, 0, "mock buy ledger is not empty");
}

export function newSystem(): LocalSystem {
  return createLocalSystem();
}

export { SERVICES };

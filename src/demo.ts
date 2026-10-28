// SPDX-License-Identifier: MIT
/**
 * Local demo: runs the README scenarios against the mock adapter and prints
 * one line per scenario. No network, no wallet, no chain.
 *
 *   node src/demo.ts            # print table
 *   node src/demo.ts --json     # print JSON (used for evidence/demo-output.json)
 */
import type { AuthorizationV1 } from "@oxdeai/core";
import type { IntentRef, PurchaseRequest } from "./agent/purchase-request.ts";
import { createLocalSystem, POLICY, SERVICES } from "./system.ts";

type Row = { scenario: string; expected: "ALLOW" | "DENY"; decision: string; executed: boolean | "unknown"; reason: string; payments: number };

function request(service: (typeof SERVICES)[keyof typeof SERVICES], overrides: Partial<PurchaseRequest> = {}): PurchaseRequest {
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

async function scenario(
  name: string,
  expected: Row["expected"],
  run: (sys: ReturnType<typeof createLocalSystem>) => Promise<{ decision: string; executed?: boolean | "unknown"; reason?: string }>,
): Promise<Row> {
  const sys = createLocalSystem();
  const out = await run(sys);
  return {
    scenario: name,
    expected,
    decision: out.decision,
    executed: out.executed ?? false,
    reason: out.reason ?? "",
    payments: sys.harness.mockBuy.counters.payments,
  };
}

async function authorizeThen(
  sys: ReturnType<typeof createLocalSystem>,
  req: PurchaseRequest,
  then: (auth: { request: PurchaseRequest; intent_ref: IntentRef; authorization: AuthorizationV1 }) => Promise<{ decision: string; executed?: boolean | "unknown"; reason?: string }>,
) {
  const a = await sys.client.authorize(req);
  if (a.decision !== "ALLOW") return { decision: "DENY", reason: `PDP:${a.reasons.join(",")}` };
  return then({ request: req, intent_ref: a.intent_ref, authorization: a.authorization });
}

const rows: Row[] = [
  await scenario("Authorized payment", "ALLOW", (sys) => authorizeThen(sys, request(SERVICES.weather), (a) => sys.client.purchase(a))),
  await scenario("Unauthorized service", "DENY", (sys) => authorizeThen(sys, request(SERVICES.unlisted), (a) => sys.client.purchase(a))),
  await scenario("Unauthorized recipient", "DENY", (sys) =>
    authorizeThen(sys, request(SERVICES.weather, { recipient: SERVICES.unlisted.pay_to }), (a) => sys.client.purchase(a)),
  ),
  await scenario("Amount exceeds policy cap", "DENY", (sys) => authorizeThen(sys, request(SERVICES.premium), (a) => sys.client.purchase(a))),
  await scenario("Body modified after authorization", "DENY", (sys) =>
    authorizeThen(sys, request(SERVICES.weather), (a) => sys.client.purchase({ ...a, request: { ...a.request, body: '{"days":30}' } })),
  ),
  await scenario("Expired authorization", "DENY", (sys) =>
    authorizeThen(sys, request(SERVICES.weather), (a) => {
      sys.harness.clock.advance(POLICY.ttlSeconds + 1);
      return sys.client.purchase(a);
    }),
  ),
  await scenario("Replayed authorization (2nd use)", "DENY", (sys) =>
    authorizeThen(sys, request(SERVICES.weather), async (a) => {
      await sys.client.purchase(a);
      return sys.client.purchase(a);
    }),
  ),
  await scenario("Invalid signature", "DENY", (sys) =>
    authorizeThen(sys, request(SERVICES.weather), (a) =>
      sys.client.purchase({ ...a, authorization: { ...a.authorization, expiry: a.authorization.expiry + 3600 } }),
    ),
  ),
  await scenario("Policy state unavailable", "DENY", (sys) => {
    sys.harness.policyStore.setAvailable(false);
    return authorizeThen(sys, request(SERVICES.weather), (a) => sys.client.purchase(a));
  }),
  await scenario("Direct executor call, no token", "DENY", async (sys) => {
    const r = await sys.harness.executor.handle({ request: request(SERVICES.weather) }, {});
    return { decision: r.status === 200 ? "ALLOW" : "DENY", executed: r.executed, reason: `EXECUTOR_HTTP_${r.status}` };
  }),
];

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ generated_by: "node src/demo.ts --json", mock_only: true, rows }, null, 2));
} else {
  console.log("MOCK ONLY: no wallet, no network, no chain.\n");
  for (const r of rows) {
    const ok = r.decision === r.expected ? "OK " : "BAD";
    console.log(`${ok} ${r.scenario.padEnd(36)} ${r.decision.padEnd(5)} executed=${String(r.executed).padEnd(5)} payments=${r.payments} ${r.reason}`);
  }
}
if (rows.some((r) => r.decision !== r.expected)) process.exitCode = 1;

// SPDX-License-Identifier: MIT
/**
 * Independent audit regression AUD-01, process level (Phase 2D, architecture C).
 *
 * The auth service's DONE append fails while it commits an execution claim
 * (fault `failDoneAppend`: an I/O error, no crash). The claim's new state is
 * already renamed into place, so the restart completes the pending PREPARE:
 * the claim IS committed. The answer the executor received must therefore not
 * be a definitive refusal. Checked on real processes and mock payments only:
 *   - nothing is paid;
 *   - after the auth restart the reservation reaches a final state (released
 *     by the executor's positive abandonment record) instead of staying
 *     EXECUTING and charged forever with a journal that says CLAIM_REFUSED;
 *   - the authorization is never payable again (gateway restart, replay).
 */
import assert from "node:assert/strict";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { identitiesUnavailableReason } from "../../src/isolation/identity.ts";
import type { IsolatedSystem } from "../../src/isolation/launcher.ts";
import { AGENT_ID, SERVICES } from "../../src/system.ts";
import { freshExecutorState, freshPolicyState, REPO_ROOT, removeStateRoot, trustedArtifact } from "./trusted-artifact.ts";

const BLOCKED = identitiesUnavailableReason();
const opts = BLOCKED === null ? {} : { skip: `BLOCKED: ${BLOCKED}` };
const PROBE = join(REPO_ROOT, "tests", "isolation", "agent-probe.ts");
const PRICE = BigInt(SERVICES.weather.price);

let trusted: Awaited<ReturnType<typeof trustedArtifact>>;
const roots: string[] = [];
const systems: IsolatedSystem[] = [];
before(async () => {
  if (BLOCKED === null) trusted = await trustedArtifact();
});
after(async () => {
  for (const s of systems.splice(0)) await s.stop();
  for (const r of roots.splice(0)) removeStateRoot(r);
  trusted?.cleanup();
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const request = () => ({
  service_id: SERVICES.weather.service_id,
  method: "POST",
  url: `${SERVICES.weather.resource}?city=lagos`,
  body: JSON.stringify({ units: "metric", days: 3 }),
  network: SERVICES.weather.network,
  asset: SERVICES.weather.asset,
  recipient: SERVICES.weather.pay_to,
  max_amount: SERVICES.weather.price.toString(),
});
type Reservation = { state: string; charged: string; claim?: { claim_id: string }; history: { outcome?: string; reason?: string; claim_id?: string }[] };
const policyFile = (s: IsolatedSystem) =>
  JSON.parse(s.privileged.read(join(s.paths.authStateDir, "state.json")).toString("utf8")) as {
    state: { budget: { spent_in_period: Record<string, { $bigint: string }> } };
    reservations: Record<string, Reservation>;
  };
const spent = (s: IsolatedSystem) => BigInt(policyFile(s).state.budget.spent_in_period[AGENT_ID]?.$bigint ?? "0");
const reservation = (s: IsolatedSystem, id: string) => policyFile(s).reservations[id];
const authorizeAsAgent = async (s: IsolatedSystem) => (await s.runAgent(PROBE, ["authorize-only", s.paths.publicSocket])).result as any;
const submit = async (s: IsolatedSystem, a: { authorization: any; intent_ref: any }) =>
  (await s.runAgent(PROBE, ["submit", s.paths.publicSocket, JSON.stringify({ request: request(), intent_ref: a.intent_ref, authorization: a.authorization })])).result as any;
async function waitFor<T>(what: string, fn: () => T | undefined | false, timeoutMs = 20_000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await sleep(250);
  }
}

test("AUD01-p claim commit not confirmed (DONE append fails): nothing paid; after the auth restart the claimed reservation is released by the executor's abandonment record, not left charged forever; never payable again", opts, async () => {
  const policyStateRoot = freshPolicyState({ budget: String(2n * PRICE), ttlSeconds: 10 });
  const executorStateRoot = freshExecutorState();
  roots.push(policyStateRoot, executorStateRoot);
  const s = await trusted.launch({ policyStateRoot, executorStateRoot, ttlSeconds: 10, reconcileIntervalMs: 300, expiryReleaseIntervalMs: 300 });
  systems.push(s);
  const a = await authorizeAsAgent(s);
  const id = a.authorization.auth_id as string;
  assert.equal(reservation(s, id)!.state, "RESERVED");
  // The next commit (the claim) writes the new state and then fails to append DONE.
  await s.restartAuth({ failDoneAppend: true });
  const r = await submit(s, a);
  assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
  assert.equal(s.ledger().length, 0, "nothing paid");
  const intent = s.journal().inspect(a.authorization.intent_hash)!;
  await s.stopAuth();
  await s.startAuth(); // no fault: the crash-state table completes the pending PREPARE
  const claimed = reservation(s, id)!;
  assert.equal(claimed.claim?.claim_id, intent.claim_id, "ground truth: the claim was committed by the restart");
  // The executor's record must let the authority reach a final state.
  const final = await waitFor("final state", () => (reservation(s, id)!.state === "RELEASED" ? reservation(s, id) : undefined), 20_000).catch(() => reservation(s, id)!);
  assert.equal(final.state, "RELEASED", `answer ${r.detail}; journal ${intent.state}, reservation ${final.state} charged ${final.charged}: a claim that never paid must not stay charged forever`);
  assert.equal(final.history.at(-1)!.claim_id, intent.claim_id);
  assert.equal(spent(s), 0n);
  // Never payable again, even after a gateway restart.
  await s.restartGateway();
  assert.notEqual((await submit(s, a)).decision, "ALLOW");
  assert.equal(s.ledger().length, 0);
  assert.equal(reservation(s, id)!.state, "RELEASED");
});

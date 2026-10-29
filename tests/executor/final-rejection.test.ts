// SPDX-License-Identifier: MIT
/**
 * Patch 0008 (independent-review finding F-SIBLING): a rejection is answered as final only once the
 * authorization service has durably confirmed that the authorization can never be claimed again.
 *
 * F-SIBLING end state: the executor's journal AND its checkpoint are restored together from an older
 * backup, so no executor-side store remembers the rejection. A fresh in-memory journal models exactly that
 * state here. The authorization service's policy state is not rolled back (it has its own anchor).
 *
 *   FR1  final rejection (VOID acknowledged) survives the full executor-state loss: never paid
 *   FR2  unconfirmed rejection (authority unreachable) is answered final:false; residual characterized:
 *        after the full executor-state loss it can pay once, within its binding, charged once
 *   FR3  abandoned claim: final only with the acknowledged VOID
 *   FR4  claim refused by the service: final only when the refusal proves no later claim is possible
 *   FR5  answer interpretation table (interpretVoid, claimRefusalIsFinal)
 *   FR6  every NOT_EXECUTED answer carries a boolean `final`; replay and unauthentic answers are never final
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import { createAuthorizationService } from "../../src/authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../../src/authorization/policy-state.ts";
import { createMockBuyAdapter } from "../../src/adapters/mock-buy/mock-buy.ts";
import { claimRefusalIsFinal, createLocalExecutionAuthority, interpretVoid, type ExecutionAuthority } from "../../src/executor/execution-authority.ts";
import { domainAudience } from "../../src/executor/execution-domain.ts";
import { createPaymentExecutor } from "../../src/executor/executor.ts";
import type { PaymentAdapter } from "../../src/executor/payment-adapter.ts";
import { createInMemoryPaymentJournal } from "../../src/executor/payment-journal.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, initialPolicyState, PDP_ISSUER, POLICY_VERSION, SERVICES } from "../../src/system.ts";
import { requestFor } from "../helpers.ts";

const keys = generateKeyPairSync("ed25519");
const priv = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const execKey = { privateKeyPem: priv, kid: "exec-1" };
const trusted = { publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), kid: "exec-1" };
const JID = "c".repeat(32);
const DOMAIN = { journal_id: JID, executor_uid: 994 };
const TOKEN = "t".repeat(64);
const PRICE = SERVICES.weather.price;
const headers = { [INTERNAL_EXECUTOR_TOKEN_HEADER]: TOKEN };

function world() {
  const store = createInMemoryPolicyStateStore(initialPolicyState());
  const svc = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: domainAudience(GATEWAY_AUDIENCE, DOMAIN),
    agentId: AGENT_ID,
    ttlSeconds: 60,
    stateStore: store,
    now: () => Math.floor(Date.now() / 1000),
    executorReportKey: trusted,
    executionDomain: DOMAIN,
  });
  const local = createLocalExecutionAuthority(svc, execKey, JID);
  // Fault switches for the executor -> service channel (the service itself keeps running).
  const down = { claim: false, void: false };
  const authority: ExecutionAuthority = {
    claim: (c) => (down.claim ? Promise.reject(new Error("ECONNREFUSED")) : local.claim(c)),
    void: (v) => (down.void ? Promise.reject(new Error("ECONNREFUSED")) : local.void(v)),
  };
  const mock = createMockBuyAdapter(Object.values(SERVICES).map((x) => ({ ...x })));
  const drifting: PaymentAdapter = { ...mock.adapter, quote: async (r) => ({ ...(await mock.adapter.quote(r)), amount: (PRICE * 10n).toString() }) };
  /** A fresh executor process; `fresh journal` = journal and checkpoint restored to before the rejection. */
  const executor = (adapter: PaymentAdapter) =>
    createPaymentExecutor({
      internalToken: TOKEN,
      adapter,
      verification: {
        expectedAudience: domainAudience(GATEWAY_AUDIENCE, DOMAIN),
        trustedKeySets: [svc.trustMaterial.keySet],
        trustedAuthorizationAuthorities: [svc.trustMaterial.authority],
        now: () => Math.floor(Date.now() / 1000),
      },
      journal: createInMemoryPaymentJournal(),
      authority,
    });
  const rec = async (id: string) => (await store.load()).reservations[id]!;
  const spent = async () => (await store.load()).state.budget.spent_in_period[AGENT_ID] ?? 0n;
  return { svc, down, mock, drifting, executor, rec, spent };
}

async function authorize(w: ReturnType<typeof world>) {
  const request = requestFor(SERVICES.weather);
  const d = await w.svc.authorize(request);
  if (d.decision !== "ALLOW") throw new Error("expected ALLOW");
  return { envelope: { action: { request, intent_ref: d.intent_ref }, authorization: d.authorization }, id: d.authorization.auth_id };
}

test("FR1 final rejection: VOID acknowledged -> final:true; after the executor's journal and checkpoint are both lost, the authorization is still never paid", async () => {
  const w = world();
  const { envelope, id } = await authorize(w);
  const r1 = await w.executor(w.drifting).handle(envelope, headers);
  assert.equal(r1.executed, false);
  assert.deepEqual([(r1.body as any).outcome, (r1.body as any).final], ["NOT_EXECUTED", true], JSON.stringify(r1.body));
  const v = await w.rec(id);
  assert.deepEqual([v.state, v.history.at(-1)!.outcome, v.history.at(-1)!.reason], ["RELEASED", "VOID", "REJECTED_BEFORE_EXECUTION"]);
  // F-SIBLING end state: a new executor with no memory of the rejection, and a quote that would now pass.
  const r2 = await w.executor(w.mock.adapter).handle(envelope, headers);
  assert.equal(r2.executed, false, JSON.stringify(r2.body));
  assert.match(String((r2.body as any).error), /EXECUTOR_CLAIM_REFUSED:CLAIM_REFUSED:NOT_ELIGIBLE:RELEASED/);
  assert.equal((r2.body as any).final, true);
  assert.equal(w.mock.inspect.ledger.length, 0, "a final rejection never pays");
  assert.equal(await w.spent(), 0n);
});

test("FR2 unconfirmed rejection: VOID unreachable -> final:false (residual: protected only by the executor's state; after its full loss the authorization pays at most once, within its binding)", async () => {
  const w = world();
  const { envelope, id } = await authorize(w);
  w.down.void = true;
  const r1 = await w.executor(w.drifting).handle(envelope, headers);
  assert.equal(r1.executed, false);
  assert.deepEqual([(r1.body as any).outcome, (r1.body as any).final], ["NOT_EXECUTED", false], JSON.stringify(r1.body));
  assert.equal((await w.rec(id)).state, "RESERVED", "the service never learned of the rejection");
  // Residual characterization: the caller was told the rejection is NOT final.
  w.down.void = false;
  const r2 = await w.executor(w.mock.adapter).handle(envelope, headers);
  assert.equal(r2.executed, true, JSON.stringify(r2.body));
  assert.equal(w.mock.inspect.ledger.length, 1);
  assert.ok(BigInt(w.mock.inspect.ledger[0]!.amount) <= PRICE, "within the authorized maximum");
  assert.equal(await w.spent(), PRICE, "charged once");
  const r3 = await w.executor(w.mock.adapter).handle(envelope, headers);
  assert.equal(r3.executed, false, "and never twice: the service granted its single claim");
  assert.equal(w.mock.inspect.ledger.length, 1);
});

test("FR3 abandoned claim: final only with the acknowledged VOID", async () => {
  {
    const w = world();
    const { envelope, id } = await authorize(w);
    w.down.claim = true;
    const r = await w.executor(w.mock.adapter).handle(envelope, headers);
    assert.match(String((r.body as any).error), /EXECUTOR_CLAIM_UNAVAILABLE/);
    assert.equal((r.body as any).final, true, JSON.stringify(r.body));
    assert.equal((await w.rec(id)).state, "RELEASED");
    w.down.claim = false;
    const r2 = await w.executor(w.mock.adapter).handle(envelope, headers);
    assert.equal(r2.executed, false, "never paid after the executor's state is lost");
    assert.equal(w.mock.inspect.ledger.length, 0);
  }
  {
    const w = world();
    const { envelope, id } = await authorize(w);
    w.down.claim = true;
    w.down.void = true;
    const r = await w.executor(w.mock.adapter).handle(envelope, headers);
    assert.equal((r.body as any).final, false, JSON.stringify(r.body));
    assert.equal((await w.rec(id)).state, "RESERVED");
    assert.equal(w.mock.inspect.ledger.length, 0);
  }
});

test("FR4 claim refused by the service: final only when the refusal proves that no later claim is possible", async () => {
  const w = world();
  const { envelope, id } = await authorize(w);
  // Consume the single claim, then let a second executor (no memory of it) present the same authorization.
  // (No outcome reporter runs in process, so the reservation stays EXECUTING after the payment.)
  const paid = await w.executor(w.mock.adapter).handle(envelope, headers);
  assert.equal(paid.executed, true);
  const r = await w.executor(w.mock.adapter).handle(envelope, headers);
  assert.match(String((r.body as any).error), /CLAIM_REFUSED:NOT_ELIGIBLE:EXECUTING/);
  assert.equal((r.body as any).final, true);
  assert.equal(w.mock.inspect.ledger.length, 1);
  assert.equal((await w.rec(id)).state, "EXECUTING");
  // A refusal that says nothing about later claims is not final: wrong execution domain.
  const other = world();
  const o = await authorize(other);
  const foreign = createPaymentExecutor({
    internalToken: TOKEN,
    adapter: other.mock.adapter,
    verification: {
      expectedAudience: domainAudience(GATEWAY_AUDIENCE, DOMAIN),
      trustedKeySets: [other.svc.trustMaterial.keySet],
      trustedAuthorizationAuthorities: [other.svc.trustMaterial.authority],
      now: () => Math.floor(Date.now() / 1000),
    },
    journal: createInMemoryPaymentJournal(),
    authority: createLocalExecutionAuthority(other.svc, execKey, "d".repeat(32)),
  });
  const rf = await foreign.handle(o.envelope, headers);
  assert.match(String((rf.body as any).error), /CLAIM_REFUSED:REPORT_REJECTED:DOMAIN_NOT_CURRENT/);
  assert.equal((rf.body as any).final, false);
  assert.equal((await other.rec(o.id)).state, "RESERVED");
});

test("FR5 answer interpretation: only the service's own confirmation is final", () => {
  // Reasons exactly as the service produces them (ReportRejected / ClaimRefused messages, transition()).
  const v = (status: number, body: unknown) => interpretVoid(status, body).final;
  assert.equal(v(200, { status: "APPLIED", released: "1" }), true);
  assert.equal(v(200, { status: "ALREADY_APPLIED", released: "0" }), true);
  for (const s of ["RELEASED", "EXECUTING", "CONFIRMED", "UNCERTAIN", "LEGACY_RESERVATION"]) {
    assert.equal(v(200, { status: "REJECTED", reason: `REPORT_REJECTED:VOID_NOT_ELIGIBLE:${s}` }), true, s);
  }
  for (const reason of [
    "REPORT_REJECTED:DOMAIN_MISMATCH",
    "REPORT_REJECTED:DOMAIN_NOT_CURRENT",
    "REPORT_REJECTED:UNKNOWN_RESERVATION",
    "REPORT_REJECTED:INTENT_HASH_MISMATCH",
    "REPORT_REJECTED:CLAIM_ID_REQUIRED",
    "POLICY_STATE_UNAVAILABLE:x",
    "POLICY_STATE_CONFLICT",
    "REPORT_INVALID:signature",
    "VOID_NOT_ELIGIBLE:RELEASED",
    "REPORT_REJECTED:VOID_NOT_ELIGIBLE:RELEASED;x",
  ]) {
    assert.equal(v(200, { status: "REJECTED", reason }), false, reason);
  }
  assert.equal(v(403, { status: "REJECTED", reason: "REPORT_REJECTED:VOID_NOT_ELIGIBLE:RELEASED" }), false, "peer-proof refusal: not the service's reservation answer");
  assert.equal(v(500, {}), false);
  assert.equal(v(200, { status: "APPLIED_LATER" }), false);
  for (const r of ["RELEASED", "EXECUTING", "CONFIRMED", "UNCERTAIN", "LEGACY_RESERVATION", "ALREADY_CLAIMED"]) assert.equal(claimRefusalIsFinal(`CLAIM_REFUSED:NOT_ELIGIBLE:${r}`), true, r);
  assert.equal(claimRefusalIsFinal("CLAIM_REFUSED:AUTH_EXPIRED_AT_CLAIM"), true);
  for (const r of [
    "CLAIM_REFUSED:NOT_ELIGIBLE:DEAD_CLAIM",
    "CLAIM_REFUSED:INTENT_HASH_MISMATCH",
    "CLAIM_REFUSED:AUTH_ID_MISMATCH",
    "CLAIM_REFUSED:CLAIM_ID_INVALID",
    "REPORT_REJECTED:DOMAIN_NOT_CURRENT",
    "REPORT_REJECTED:UNKNOWN_RESERVATION",
    "REPORT_INVALID:signature",
    "NOT_ELIGIBLE:RELEASED",
    "AUTH_EXPIRED_AT_CLAIM",
  ]) {
    assert.equal(claimRefusalIsFinal(r), false, r);
  }
});

test("FR6 every NOT_EXECUTED answer carries a boolean final; replay and unauthentic answers are never final", async () => {
  const w = world();
  const { envelope } = await authorize(w);
  const ex = w.executor(w.drifting);
  const first = await ex.handle(envelope, headers);
  assert.equal((first.body as any).final, true);
  // Repeating a rejected authorization re-sends its VOID: the service answers ALREADY_APPLIED, which is final.
  const again = await ex.handle(envelope, headers);
  assert.deepEqual([(again.body as any).outcome, (again.body as any).final], ["NOT_EXECUTED", true]);
  // Replay of a paid authorization: AUTH_REPLAY carries no confirmation from the service.
  const w2 = world();
  const p = await authorize(w2);
  const ex2 = w2.executor(w2.mock.adapter);
  assert.equal((await ex2.handle(p.envelope, headers)).executed, true);
  const replay = await ex2.handle(p.envelope, headers);
  assert.match(String((replay.body as any).error), /EXECUTOR_AUTH_REPLAY|EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT/);
  assert.deepEqual([(replay.body as any).outcome, (replay.body as any).final], ["NOT_EXECUTED", false], "a replay answer is not a fresh confirmation");
  const tampered = { ...envelope, authorization: { ...envelope.authorization, signature: "AAAA" } };
  const bad = await w.executor(w.mock.adapter).handle(tampered, headers);
  assert.deepEqual([(bad.body as any).outcome, (bad.body as any).final], ["NOT_EXECUTED", false]);
  assert.equal(w.mock.inspect.ledger.length, 0);
});

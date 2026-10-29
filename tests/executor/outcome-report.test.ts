// SPDX-License-Identifier: MIT
/**
 * Phase 2C (F3, CX2) / Phase 2D (architecture C): executor messages (claim,
 * void, report) are verified strictly, including their type and journal
 * (domain); reports are derived only from positive journal records bound to a
 * claim; the service grants at most one claim per authorization.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { createAuthorizationService } from "../../src/authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../../src/authorization/policy-state.ts";
import { createLocalExecutionAuthority } from "../../src/executor/execution-authority.ts";
import { domainAudience } from "../../src/executor/execution-domain.ts";
import {
  ackKey,
  CLAIM_TYPE,
  deriveOutcome,
  REPORT_TYPE,
  signClaim,
  signReport,
  signVoid,
  verifyClaim,
  verifyReport,
  verifyVoid,
  VOID_TYPE,
  type OutcomeReport,
} from "../../src/executor/outcome-report.ts";
import type { AuthRecord, PaymentJournalRecord } from "../../src/executor/payment-journal.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, initialPolicyState, PDP_ISSUER, POLICY_VERSION, SERVICES } from "../../src/system.ts";
import { requestFor } from "../helpers.ts";

const keys = generateKeyPairSync("ed25519");
const priv = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const trusted = { publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), kid: "exec-1" };
const H = "a".repeat(64);
const JID = "b".repeat(32);
const C = "c".repeat(32);
const report: OutcomeReport = { type: REPORT_TYPE, auth_id: "A", intent_hash: H, claim_id: C, outcome: "SETTLED", amount: "10000", journal_id: JID, executor_kid: "exec-1" };

test("OR1 a valid report verifies and yields its facts, claim, and journal", () => {
  const facts = verifyReport(signReport(report, priv), trusted);
  assert.deepEqual([facts.auth_id, facts.claim_id, facts.outcome, facts.amount, facts.journal_id], ["A", C, "SETTLED", "10000", JID]);
  assert.match(facts.report_id, /^[0-9a-f]{64}$/);
});

test("OR2 any change to a signed message, a foreign key, a bad shape, or a message of another type is refused", () => {
  const signed = signReport(report, priv);
  for (const patch of [{ outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING" }, { amount: "1" }, { auth_id: "B" }, { journal_id: "c".repeat(32) }, { intent_hash: "d".repeat(64) }, { claim_id: "e".repeat(32) }]) {
    assert.throws(() => verifyReport({ ...signed, report: { ...report, ...patch } }, trusted), /REPORT_INVALID:signature/, JSON.stringify(patch));
  }
  const other = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  assert.throws(() => verifyReport(signReport(report, other), trusted), /REPORT_INVALID:signature/);
  assert.throws(() => verifyReport(signReport({ ...report, executor_kid: "exec-2" }, priv), trusted), /REPORT_INVALID:kid/);
  assert.throws(() => verifyReport(signReport({ ...report, extra: 1 } as never, priv), trusted), /REPORT_INVALID:keys/);
  assert.throws(() => verifyReport(signReport({ ...report, journal_id: "short" }, priv), trusted), /REPORT_INVALID:journal_id/);
  assert.throws(() => verifyReport(signReport({ ...report, claim_id: undefined } as never, priv), trusted), /REPORT_INVALID:claim_id/, "a report must name its claim");
  assert.throws(() => verifyReport(signReport({ ...report, outcome: "EXECUTING" as never }, priv), trusted), /REPORT_INVALID:outcome/, "EXECUTING is a claim now, not a report");
  assert.throws(() => verifyReport(signReport({ ...report, outcome: "RESOLVED_NOT_SETTLED" as never }, priv), trusted), /REPORT_INVALID:outcome/);
  assert.throws(() => verifyReport(signReport({ ...report, reason: "CANCELLED" as never }, priv), trusted), /REPORT_INVALID:reason/);
  assert.throws(() => verifyReport(null, trusted), /REPORT_INVALID:shape/);
  // Type separation: a signed claim or void is never accepted as another message type.
  const claim = signClaim({ type: CLAIM_TYPE, auth_id: "A", intent_hash: H, claim_id: C, journal_id: JID, executor_kid: "exec-1" }, priv);
  const v = signVoid({ type: VOID_TYPE, auth_id: "A", intent_hash: H, reason: "REJECTED_BEFORE_EXECUTION", journal_id: JID, executor_kid: "exec-1" }, priv);
  assert.equal(verifyClaim(claim, trusted).claim_id, C);
  assert.equal(verifyVoid(v, trusted).reason, "REJECTED_BEFORE_EXECUTION");
  assert.throws(() => verifyReport(claim, trusted), /REPORT_INVALID:(keys|type)/);
  assert.throws(() => verifyVoid(claim, trusted), /REPORT_INVALID:(keys|type)/);
  assert.throws(() => verifyClaim(v, trusted), /REPORT_INVALID:(keys|type)/);
  assert.throws(() => verifyClaim(signed, trusted), /REPORT_INVALID:(keys|type)/);
  assert.throws(() => verifyVoid(signVoid({ type: VOID_TYPE, auth_id: "A", intent_hash: H, reason: "NOT_STARTED" as never, journal_id: JID, executor_kid: "exec-1" }, priv), trusted), /REPORT_INVALID:reason/);
});

const auth = (disposition: AuthRecord["disposition"], extra: Partial<AuthRecord> = {}): AuthRecord => ({ auth_id: "A", intent_hash: H, disposition, at: 1, ...extra });
const intent = (state: PaymentJournalRecord["state"], extra: Partial<PaymentJournalRecord> = {}): PaymentJournalRecord =>
  ({ intent_hash: H, auth_id: "A", claim_id: C, state, request: {} as never, started_at: 1, updated_at: 1, ...extra }) as PaymentJournalRecord;
const evidence = { kind: "MOCK_LEDGER_MAC" as const, reference: "mock-1", mac: "m", amount: "9000" };

test("OR3 derivation: only positive records bound to a claim are reported; absence is never non-execution", () => {
  // Nothing reported without a claim: unclaimed rejections are VOIDed synchronously, never from the journal.
  assert.equal(deriveOutcome(auth("REJECTED_BEFORE_EXECUTION"), undefined, false), null);
  assert.equal(deriveOutcome(auth("CANCELLED"), undefined, false), null);
  assert.equal(deriveOutcome(auth("RESERVED"), undefined, false), null, "no intent record: no claim was ever sent");
  assert.equal(deriveOutcome(auth("RESERVED"), intent("STARTED", { claim_id: undefined }), false), null, "legacy intent without a claim: held");
  assert.equal(deriveOutcome(auth("RESERVED"), intent("CLAIM_REFUSED"), false), null, "refused claim: nothing committed");
  assert.equal(deriveOutcome(auth("RESERVED"), intent("STARTED"), true), null, "in flight: nothing reported");
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("REFUSED_BEFORE_SIGNING"), false), { outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING", claim_id: C });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("CLAIM_ABANDONED"), false), { outcome: "NOT_EXECUTED", reason: "CLAIM_ABANDONED", claim_id: C });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("STARTED"), false), { outcome: "UNCERTAIN", claim_id: C });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("UNKNOWN"), false), { outcome: "UNCERTAIN", claim_id: C });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("SETTLED", { receipt: { amount: "9000" } }), false), { outcome: "SETTLED", amount: "9000", claim_id: C });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("SETTLED", { receipt: {} }), false), { outcome: "UNCERTAIN", claim_id: C }, "a settlement without an amount is not trusted");
  assert.deepEqual(
    deriveOutcome(auth("RESERVED"), intent("UNKNOWN", { resolution: { verdict: "SETTLED", amount: "9000", evidence, note: "n", at: 2 } }), false),
    { outcome: "RESOLVED_SETTLED", amount: "9000", claim_id: C },
  );
  assert.equal(deriveOutcome(auth("RESERVED", { detail: "JOURNAL_RECORD_UNREADABLE", auth_id: "" }), undefined, false), null, "unreadable: held, never released");
  assert.equal(deriveOutcome(auth("RESERVED"), intent("SETTLED", { auth_id: "OTHER" }), false), null, "intent of another authorization");
  assert.equal(deriveOutcome(auth("RESERVED"), intent("UNKNOWN", { detail: "JOURNAL_RECORD_UNREADABLE", auth_id: "" }), false), null, "unreadable intent: held");
});

test("OR4 one acknowledgement key per outcome and reason", () => {
  assert.equal(ackKey({ outcome: "SETTLED" }), "SETTLED");
  assert.equal(ackKey({ outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING" }), "NOT_EXECUTED-REFUSED_BEFORE_SIGNING");
  assert.notEqual(ackKey({ outcome: "SETTLED" }), ackKey({ outcome: "UNCERTAIN" }));
});

function service(domain = { journal_id: JID, executor_uid: 994 }, now = () => Math.floor(Date.now() / 1000)) {
  const store = createInMemoryPolicyStateStore(initialPolicyState());
  const svc = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: domainAudience(GATEWAY_AUDIENCE, domain),
    agentId: AGENT_ID,
    ttlSeconds: 60,
    stateStore: store,
    now,
    executorReportKey: trusted,
    executionDomain: domain,
  });
  return { svc, store, spent: async () => (await store.load()).state.budget.spent_in_period[AGENT_ID] };
}

test("OR5 claim, void, and reports: the journal must be the current domain and the reservation's; duplicates never release twice", async () => {
  const { svc, spent } = service();
  const d = await svc.authorize(requestFor(SERVICES.weather));
  if (d.decision !== "ALLOW") throw new Error("expected ALLOW");
  const ids = { auth_id: d.authorization.auth_id, intent_hash: d.authorization.intent_hash };
  const claim = (claim_id: string, journal_id = JID) => svc.claim(signClaim({ type: CLAIM_TYPE, ...ids, claim_id, journal_id, executor_kid: "exec-1" }, priv));
  const r = (patch: Partial<OutcomeReport>) => signReport({ type: REPORT_TYPE, ...ids, journal_id: JID, executor_kid: "exec-1", claim_id: C, outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING", ...patch } as OutcomeReport, priv);
  assert.equal(await spent(), 10000n);
  assert.match(((await claim(C, "f".repeat(32))) as { reason: string }).reason, /DOMAIN_NOT_CURRENT/);
  assert.deepEqual(await claim(C), { status: "CLAIMED", ...ids, claim_id: C });
  assert.match(((await claim(C)) as { reason: string }).reason, /NOT_ELIGIBLE:EXECUTING/, "never acknowledged twice");
  assert.match(((await svc.settle(r({ journal_id: "c".repeat(32) }))) as { reason: string }).reason, /DOMAIN_NOT_CURRENT/);
  assert.equal(await spent(), 10000n);
  assert.equal((await svc.settle(r({}))).status, "APPLIED");
  assert.equal(await spent(), 0n);
  assert.equal((await svc.settle(r({}))).status, "ALREADY_APPLIED");
  assert.equal((await svc.settle(r({ outcome: "SETTLED", reason: undefined, amount: "10000" }))).status, "REJECTED");
  assert.match(((await claim("e".repeat(32))) as { reason: string }).reason, /NOT_ELIGIBLE:RELEASED/, "a released authorization is never claimable");
  assert.equal(await spent(), 0n, "released once");
  // Without a configured domain (in-process harness), only unbound reservations; a bound one is refused.
  const unbound = createAuthorizationService({ policyVersion: POLICY_VERSION, issuer: PDP_ISSUER, audience: GATEWAY_AUDIENCE, agentId: AGENT_ID, ttlSeconds: 60, stateStore: createInMemoryPolicyStateStore(initialPolicyState()), now: () => Math.floor(Date.now() / 1000), executorReportKey: trusted });
  const u = await unbound.authorize(requestFor(SERVICES.weather));
  if (u.decision !== "ALLOW") throw new Error("expected ALLOW");
  assert.equal((await unbound.claim(signClaim({ type: CLAIM_TYPE, auth_id: u.authorization.auth_id, intent_hash: u.authorization.intent_hash, claim_id: C, journal_id: JID, executor_kid: "exec-1" }, priv))).status, "CLAIMED");
});

test("OR6 concurrent claims for one authorization: exactly one is granted; VOID burns an unclaimed authorization", async () => {
  const { svc, spent } = service();
  const d = await svc.authorize(requestFor(SERVICES.weather));
  if (d.decision !== "ALLOW") throw new Error("expected ALLOW");
  const ids = { auth_id: d.authorization.auth_id, intent_hash: d.authorization.intent_hash };
  const claimIds = Array.from({ length: 8 }, (_, i) => `${i}`.repeat(32));
  const results = await Promise.all(claimIds.map((claim_id) => svc.claim(signClaim({ type: CLAIM_TYPE, ...ids, claim_id, journal_id: JID, executor_kid: "exec-1" }, priv))));
  assert.equal(results.filter((x) => x.status === "CLAIMED").length, 1, JSON.stringify(results));
  assert.equal(await spent(), 10000n, "a claim moves no money");

  const e = await svc.authorize(requestFor(SERVICES.weather));
  if (e.decision !== "ALLOW") throw new Error("expected ALLOW");
  const local = createLocalExecutionAuthority(svc, { privateKeyPem: priv, kid: "exec-1" }, JID);
  const eids = { auth_id: e.authorization.auth_id, intent_hash: e.authorization.intent_hash };
  assert.deepEqual(await local.void({ ...eids, reason: "REJECTED_BEFORE_EXECUTION" }), { acknowledged: true });
  assert.deepEqual(await local.void({ ...eids, reason: "REJECTED_BEFORE_EXECUTION" }), { acknowledged: true }, "idempotent");
  assert.equal(await spent(), 10000n, "only the voided reservation was released");
  const late = await local.claim({ ...eids, claim_id: C });
  assert.deepEqual(late, { ok: false, definitive: true, reason: "CLAIM_REFUSED:NOT_ELIGIBLE:RELEASED" }, "a voided authorization is never claimable");
});

test("OR7 expiry: no claim at or after expiry on the service's clock; expired unclaimed reservations are released by the service itself", async () => {
  let now = 1_000_000;
  const { svc, spent } = service(undefined, () => now);
  const d = await svc.authorize(requestFor(SERVICES.weather));
  if (d.decision !== "ALLOW") throw new Error("expected ALLOW");
  const ids = { auth_id: d.authorization.auth_id, intent_hash: d.authorization.intent_hash };
  now = d.authorization.expiry;
  const late = await svc.claim(signClaim({ type: CLAIM_TYPE, ...ids, claim_id: C, journal_id: JID, executor_kid: "exec-1" }, priv));
  assert.match((late as { reason: string }).reason, /AUTH_EXPIRED_AT_CLAIM/);
  assert.equal(await spent(), 10000n);
  assert.equal(await svc.releaseExpired(), 1);
  assert.equal(await spent(), 0n);
  assert.equal(await svc.releaseExpired(), 0, "nothing released twice");
});

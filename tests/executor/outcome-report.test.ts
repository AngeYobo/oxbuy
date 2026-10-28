// SPDX-License-Identifier: MIT
/** Phase 2C (F3, CX2): outcome reports are derived only from the journal and verified strictly, including their journal (domain). */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { createAuthorizationService } from "../../src/authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../../src/authorization/policy-state.ts";
import { domainAudience } from "../../src/executor/execution-domain.ts";
import { ackKey, deriveOutcome, REPORT_TYPE, signReport, verifyReport, type OutcomeReport } from "../../src/executor/outcome-report.ts";
import type { AuthRecord, PaymentJournalRecord } from "../../src/executor/payment-journal.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, initialPolicyState, PDP_ISSUER, POLICY_VERSION, SERVICES } from "../../src/system.ts";
import { requestFor } from "../helpers.ts";

const keys = generateKeyPairSync("ed25519");
const priv = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const trusted = { publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), kid: "exec-1" };
const H = "a".repeat(64);
const JID = "b".repeat(32);
const report: OutcomeReport = { type: REPORT_TYPE, auth_id: "A", intent_hash: H, outcome: "SETTLED", amount: "10000", journal_id: JID, executor_kid: "exec-1" };

test("OR1 a valid report verifies and yields its facts and journal", () => {
  const facts = verifyReport(signReport(report, priv), trusted);
  assert.deepEqual([facts.auth_id, facts.outcome, facts.amount, facts.journal_id], ["A", "SETTLED", "10000", JID]);
  assert.match(facts.report_id, /^[0-9a-f]{64}$/);
});

test("OR2 any change to a signed report, a foreign key, or a bad shape is refused", () => {
  const signed = signReport(report, priv);
  for (const patch of [{ outcome: "NOT_EXECUTED", reason: "CANCELLED" }, { amount: "1" }, { auth_id: "B" }, { journal_id: "c".repeat(32) }, { intent_hash: "d".repeat(64) }]) {
    assert.throws(() => verifyReport({ ...signed, report: { ...report, ...patch } }, trusted), /REPORT_INVALID:signature/, JSON.stringify(patch));
  }
  const other = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  assert.throws(() => verifyReport(signReport(report, other), trusted), /REPORT_INVALID:signature/);
  assert.throws(() => verifyReport(signReport({ ...report, executor_kid: "exec-2" }, priv), trusted), /REPORT_INVALID:kid/);
  assert.throws(() => verifyReport(signReport({ ...report, extra: 1 } as never, priv), trusted), /REPORT_INVALID:keys/);
  assert.throws(() => verifyReport(signReport({ ...report, journal_id: "short" }, priv), trusted), /REPORT_INVALID:journal_id/);
  assert.throws(() => verifyReport(signReport({ ...report, outcome: "PAID" as never }, priv), trusted), /REPORT_INVALID:outcome/);
  assert.throws(() => verifyReport(signReport({ ...report, reason: "WHATEVER" as never }, priv), trusted), /REPORT_INVALID:reason/);
  assert.throws(() => verifyReport(null, trusted), /REPORT_INVALID:shape/);
});

const auth = (disposition: AuthRecord["disposition"], extra: Partial<AuthRecord> = {}): AuthRecord => ({ auth_id: "A", intent_hash: H, disposition, at: 1, ...extra });
const intent = (state: PaymentJournalRecord["state"], extra: Partial<PaymentJournalRecord> = {}): PaymentJournalRecord =>
  ({ intent_hash: H, auth_id: "A", state, request: {} as never, started_at: 1, updated_at: 1, ...extra }) as PaymentJournalRecord;

test("OR3 derivation: NOT_EXECUTED only when the journal proves `pay` did not (successfully) run", () => {
  assert.deepEqual(deriveOutcome(auth("REJECTED_BEFORE_EXECUTION"), undefined, false), { outcome: "NOT_EXECUTED", reason: "REJECTED_BEFORE_EXECUTION" });
  assert.deepEqual(deriveOutcome(auth("CANCELLED"), undefined, false), { outcome: "NOT_EXECUTED", reason: "CANCELLED" });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), undefined, false), { outcome: "NOT_EXECUTED", reason: "NOT_STARTED" });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("REFUSED_BEFORE_SIGNING"), false), { outcome: "NOT_EXECUTED", reason: "REFUSED_BEFORE_SIGNING" });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("STARTED"), true), { outcome: "EXECUTING" });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("STARTED"), false), { outcome: "UNCERTAIN" });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("UNKNOWN"), false), { outcome: "UNCERTAIN" });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("SETTLED", { receipt: { amount: "9000" } }), false), { outcome: "SETTLED", amount: "9000" });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("SETTLED", { receipt: {} }), false), { outcome: "UNCERTAIN" }, "a settlement without an amount is not trusted");
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("STARTED", { resolution: { verdict: "NOT_SETTLED", note: "n", at: 2 } }), false), { outcome: "RESOLVED_NOT_SETTLED" });
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("UNKNOWN", { resolution: { verdict: "SETTLED", note: "n", at: 2 } }), false), { outcome: "RESOLVED_SETTLED" });
  assert.equal(deriveOutcome(auth("RESERVED", { detail: "JOURNAL_RECORD_UNREADABLE", auth_id: "" }), undefined, false), null, "unreadable: held, never released");
  assert.equal(deriveOutcome(auth("RESERVED"), intent("SETTLED", { auth_id: "OTHER" }), false), null, "intent of another authorization");
  assert.deepEqual(deriveOutcome(auth("RESERVED"), intent("UNKNOWN", { detail: "JOURNAL_RECORD_UNREADABLE" }), false), { outcome: "UNCERTAIN" });
});

test("OR4 one acknowledgement key per outcome and reason", () => {
  assert.equal(ackKey({ outcome: "SETTLED" }), "SETTLED");
  assert.equal(ackKey({ outcome: "NOT_EXECUTED", reason: "CANCELLED" }), "NOT_EXECUTED-CANCELLED");
  assert.notEqual(ackKey({ outcome: "EXECUTING" }), ackKey({ outcome: "UNCERTAIN" }));
});

test("OR5 settle: the reporting journal must be the current domain and the reservation's domain; duplicates never release twice", async () => {
  const domain = { journal_id: JID, executor_uid: 994 };
  const store = createInMemoryPolicyStateStore(initialPolicyState());
  const svc = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: domainAudience(GATEWAY_AUDIENCE, domain),
    agentId: AGENT_ID,
    ttlSeconds: 60,
    stateStore: store,
    now: () => Math.floor(Date.now() / 1000),
    executorReportKey: trusted,
    executionDomain: domain,
  });
  const d = await svc.authorize(requestFor(SERVICES.weather));
  assert.equal(d.decision, "ALLOW");
  if (d.decision !== "ALLOW") return;
  const r = (patch: Partial<OutcomeReport>) => signReport({ type: REPORT_TYPE, auth_id: d.authorization.auth_id, intent_hash: d.authorization.intent_hash, journal_id: JID, executor_kid: "exec-1", outcome: "NOT_EXECUTED", reason: "CANCELLED", ...patch } as OutcomeReport, priv);
  const spent = async () => (await store.load()).state.budget.spent_in_period[AGENT_ID];
  assert.equal(await spent(), 10000n);
  assert.match(((await svc.settle(r({ journal_id: "c".repeat(32) }))) as { reason: string }).reason, /DOMAIN_NOT_CURRENT/);
  assert.equal(await spent(), 10000n);
  assert.equal((await svc.settle(r({}))).status, "APPLIED");
  assert.equal(await spent(), 0n);
  assert.equal((await svc.settle(r({}))).status, "ALREADY_APPLIED");
  assert.equal((await svc.settle(r({ outcome: "EXECUTING", reason: undefined }))).status, "REJECTED");
  assert.equal(await spent(), 0n, "released once");
  // Without a configured domain (in-process harness), reservations are unbound and never released.
  const unbound = createAuthorizationService({ policyVersion: POLICY_VERSION, issuer: PDP_ISSUER, audience: GATEWAY_AUDIENCE, agentId: AGENT_ID, ttlSeconds: 60, stateStore: createInMemoryPolicyStateStore(initialPolicyState()), now: () => Math.floor(Date.now() / 1000), executorReportKey: trusted });
  const u = await unbound.authorize(requestFor(SERVICES.weather));
  if (u.decision !== "ALLOW") throw new Error("expected ALLOW");
  assert.equal((await unbound.settle(signReport({ type: REPORT_TYPE, auth_id: u.authorization.auth_id, intent_hash: u.authorization.intent_hash, journal_id: JID, executor_kid: "exec-1", outcome: "NOT_EXECUTED", reason: "CANCELLED" }, priv))).status, "REJECTED");
});

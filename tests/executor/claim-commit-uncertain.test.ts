// SPDX-License-Identifier: MIT
/**
 * Independent audit regression AUD-01 (Phase 2D, architecture C).
 *
 * A claim whose policy-state commit fails AFTER the new state may already be
 * durable (DONE append or directory fsync error: policy-state-file.ts marks
 * the store broken and a restart COMPLETES the pending PREPARE) must never be
 * answered as a definitive refusal. A definitive refusal makes the executor
 * record CLAIM_REFUSED, send no VOID, and never report: if the claim did
 * commit, its reservation stays EXECUTING and charged forever, with no
 * supported recovery path (journal-cli resolve only accepts STARTED/UNKNOWN).
 *
 * The in-memory store below models exactly that commit outcome: the new
 * version is written, then the commit throws (as the file store does when the
 * DONE append fails), and a "restart" keeps the written version.
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import { createAuthorizationService } from "../../src/authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore, type PolicyStateStore } from "../../src/authorization/policy-state.ts";
import { createLocalExecutionAuthority } from "../../src/executor/execution-authority.ts";
import { domainAudience } from "../../src/executor/execution-domain.ts";
import { deriveOutcome, signReport, REPORT_TYPE } from "../../src/executor/outcome-report.ts";
import { createMockBuyAdapter } from "../../src/adapters/mock-buy/mock-buy.ts";
import { createPaymentExecutor } from "../../src/executor/executor.ts";
import { createInMemoryPaymentJournal } from "../../src/executor/payment-journal.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, initialPolicyState, PDP_ISSUER, POLICY_VERSION, SERVICES } from "../../src/system.ts";
import { requestFor } from "../helpers.ts";

const keys = generateKeyPairSync("ed25519");
const priv = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const execKey = { privateKeyPem: priv, kid: "exec-1" };
const trusted = { publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), kid: "exec-1" };
const JID = "b".repeat(32);
const DOMAIN = { journal_id: JID, executor_uid: 994 };
const TOKEN = "t".repeat(64);

/** Store whose next commit is written and THEN reported as failed (DONE not confirmed). */
function storeWithUnconfirmedCommit() {
  const inner = createInMemoryPolicyStateStore(initialPolicyState());
  let failNext = false;
  const store: PolicyStateStore = {
    load: () => inner.load(),
    async commit(next, expectedVersion, reservations) {
      const ok = await inner.commit(next, expectedVersion, reservations);
      if (ok && failNext) {
        failNext = false;
        throw new Error("injected DONE append failure"); // the state is in place; its confirmation is not
      }
      return ok;
    },
  };
  return { store, inner, failNextCommit: () => (failNext = true) };
}

function system() {
  const s = storeWithUnconfirmedCommit();
  const svc = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: domainAudience(GATEWAY_AUDIENCE, DOMAIN),
    agentId: AGENT_ID,
    ttlSeconds: 60,
    stateStore: s.store,
    now: () => Math.floor(Date.now() / 1000),
    executorReportKey: trusted,
    executionDomain: DOMAIN,
  });
  return { ...s, svc };
}

test("AUD01-a a claim whose commit outcome is unconfirmed is never answered as a definitive refusal", async () => {
  const { svc, inner, failNextCommit } = system();
  const d = await svc.authorize(requestFor(SERVICES.weather));
  if (d.decision !== "ALLOW") throw new Error("expected ALLOW");
  const authority = createLocalExecutionAuthority(svc, execKey, JID);
  failNextCommit();
  const c = { auth_id: d.authorization.auth_id, intent_hash: d.authorization.intent_hash, claim_id: "c".repeat(32) };
  const answer = await authority.claim(c);
  // Ground truth: the claim IS in the store (a restart completes it).
  const rec = (await inner.load()).reservations[c.auth_id]!;
  assert.equal(rec.state, "EXECUTING", "precondition: the claim was written");
  assert.equal(rec.claim?.claim_id, c.claim_id);
  assert.equal(answer.ok, false, "never acknowledged");
  assert.equal(answer.ok === false && answer.definitive, false, `an unconfirmed commit must not be definitive: ${JSON.stringify(answer)}`);
});

test("AUD01-b end to end (in process): after an unconfirmed claim commit nothing is paid, and the reservation is released by the executor's positive abandonment record, never left charged forever", async () => {
  const { svc, inner, failNextCommit } = system();
  const mock = createMockBuyAdapter(Object.values(SERVICES).map((x) => ({ ...x })));
  const journal = createInMemoryPaymentJournal();
  const executor = createPaymentExecutor({
    internalToken: TOKEN,
    adapter: mock.adapter,
    verification: {
      expectedAudience: domainAudience(GATEWAY_AUDIENCE, DOMAIN),
      trustedKeySets: [svc.trustMaterial.keySet],
      trustedAuthorizationAuthorities: [svc.trustMaterial.authority],
      now: () => Math.floor(Date.now() / 1000),
    },
    journal,
    authority: createLocalExecutionAuthority(svc, execKey, JID),
  });
  const request = requestFor(SERVICES.weather);
  const d = await svc.authorize(request);
  if (d.decision !== "ALLOW") throw new Error("expected ALLOW");
  const id = d.authorization.auth_id;
  failNextCommit();
  const res = await executor.handle({ action: { request, intent_ref: d.intent_ref }, authorization: d.authorization }, { [INTERNAL_EXECUTOR_TOKEN_HEADER]: TOKEN });
  assert.equal(res.executed, false, JSON.stringify(res.body));
  assert.equal(mock.inspect.ledger.length, 0, "nothing paid");
  const intent = journal.inspect(d.authorization.intent_hash)!;
  // What the executor's journal says must allow the authority to reach a final state:
  // either the abandonment VOID already released it, or the outcome report derived from the journal will.
  let rec = (await inner.load()).reservations[id]!;
  if (rec.state === "EXECUTING") {
    const auth = { auth_id: id, intent_hash: d.authorization.intent_hash, disposition: "RESERVED" as const, at: 0 };
    const out = deriveOutcome(auth, intent, false);
    assert.notEqual(out, null, `journal state ${intent.state}: a claimed reservation must have a reportable outcome`);
    const report = signReport({ type: REPORT_TYPE, auth_id: id, intent_hash: d.authorization.intent_hash, claim_id: out!.claim_id, outcome: out!.outcome, ...(out!.reason ? { reason: out!.reason } : {}), journal_id: JID, executor_kid: "exec-1" }, priv);
    await svc.settle(report);
    rec = (await inner.load()).reservations[id]!;
  }
  assert.equal(rec.state, "RELEASED", `never paid, so never left charged: ${rec.state}`);
  assert.equal((await inner.load()).state.budget.spent_in_period[AGENT_ID], 0n);
});

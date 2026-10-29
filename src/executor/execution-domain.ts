// SPDX-License-Identifier: MIT
/**
 * Execution domain (Phase 2C; CX2).
 *
 * An execution domain is the pair (executor OS account uid, durable journal
 * identity). The journal identity is a random 128-bit `journal_id`, written
 * once into the journal's JOURNAL.json at `init` and never changed
 * (src/executor/payment-journal.ts). The journal's exclusive writer lock
 * (src/durable/exclusive-lock.ts) means at most one executor process can use
 * a journal at a time, so what that journal durably records about an
 * auth_id is authoritative for every authorization bound to the domain.
 *
 * Binding: every authorization is bound to exactly one domain before it can
 * execute, through the existing, signed AuthorizationV1 `audience` field:
 *   audience = "<base audience>#exec-domain=<domainId>"
 *   domainId = sha256("oxdeai-celo-poc/execution-domain/v1\n" + uid + "\n" + journal_id)
 * The authorization service signs it (so nobody else can change it), the
 * gateway and the executor each require it as their expected audience, and
 * the executor derives the expected value from its OWN open journal and uid
 * at startup, refusing to start if its configuration disagrees. An
 * authorization for another domain fails `verifyAuthorization` with
 * AUTH_AUDIENCE_MISMATCH before any payment step. No new signature or key is
 * introduced; only the audience string changes. The policy id does not
 * depend on the audience, so policy state bindings are unaffected.
 *
 * Release: each reservation records its domain. The authorization service
 * accepts an outcome report only if it names the reservation's journal_id
 * AND that is the domain of the executor it currently trusts, and offers for
 * cancellation only reservations of that domain. A reservation of any other
 * domain (an earlier deployment with another journal, a lost journal) is
 * never released automatically; it stays charged until an executor running
 * on that same journal reports it.
 *
 * Trust assumptions: the operator (who provisions journals and configures
 * deployments) and root are trusted; the executor account is not shared with
 * other software; journal_id is unpredictable and never reused.
 */
import { createHash } from "node:crypto";

export type ExecutionDomain = { readonly journal_id: string; readonly executor_uid: number };

export const JOURNAL_ID = /^[0-9a-f]{32}$/;

export function domainId(d: ExecutionDomain): string {
  if (!JOURNAL_ID.test(d.journal_id) || !Number.isSafeInteger(d.executor_uid) || d.executor_uid < 0) throw new Error("EXECUTION_DOMAIN_INVALID");
  return createHash("sha256").update(`oxdeai-celo-poc/execution-domain/v1\n${d.executor_uid}\n${d.journal_id}`).digest("hex");
}

export function domainAudience(baseAudience: string, d: ExecutionDomain): string {
  return `${baseAudience}#exec-domain=${domainId(d)}`;
}

export function sameDomain(a: ExecutionDomain | undefined | null, b: ExecutionDomain | undefined | null): boolean {
  return !!a && !!b && a.journal_id === b.journal_id && a.executor_uid === b.executor_uid;
}

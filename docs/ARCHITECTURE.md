# Architecture: OxDeAI x402 Gateway, Phase 1 / 1R / 2A / 2B

Phase 1 is a local, single-process prototype. It uses the published OxDeAI
packages unmodified and a deterministic mock of the `@celo/buy` quote/pay
flow. There is no wallet, no network access, and no chain interaction.

Phase 2A (historical) ran the same components as three processes (agent, gateway,
executor) with the agent under a separate OS identity, a durable payment
journal, and executor-side verification of the signed authorization. Phase
2A-R makes trusted code launch only from a sealed, operator-approved
artifact verified before import (`src/isolation/artifact.ts`,
`src/isolation/trusted-entry.ts`). The process layout, IPC, access control,
trust store, journal, and recovery procedure are in `docs/ISOLATION.md`.

Phase 2B (current) separates four security domains under dedicated OS
accounts (`docs/ISOLATION.md` §0):
- **agent** (`oxdeai-agent`): untrusted;
- **gateway** (`oxdeai-gateway`): the PEP; it holds no signing key, no
  wallet, and no policy state;
- **auth service** (`oxdeai-auth`): the PDP and signer; it holds the
  signing key and the persistent policy state, but no wallet;
- **executor** (`oxdeai-executor`): holds the wallet, ledger, and journal,
  but no signing key.

The auth service exposes only `/v1/authorize`. It builds and signs every
authorization itself, and there is no generic signing endpoint. In the
Phase 2B-R2 review, code running as the gateway identity could not read the
signing key or wallet, pay directly, change policy state or code, or obtain
an authorization outside policy (CONFORMANCE.md, P2B-01..20). The
independent Phase 2B-R4 audit reproduced these results. Both were manual
experiments; only some of the twenty controls have automated tests in
`npm test` (CONFORMANCE.md lists which). These results hold for the
standard launch; the `OXDEAI_AGENT_UID` / `OXDEAI_AGENT_GID` override
weakens the agent/gateway boundary (limitation 16).

**Not claimed:**
- that a compromised gateway cannot cause payments. It can request any
  payment the policy allows.
- any protection against the operator, who has passwordless sudo, or
  against root. This includes the operator's launch environment (F5),
  restoring older policy state (N3), and starting services outside the
  launcher (N1).
- that the budget equals settled spending. It counts authorizations at
  decision commit (F3).
- that uncertain payment records survive a full redeployment (N2).
- readiness for real payments.

The single-process composition (`src/system.ts`)
remains the harness for the protocol tests; the executor, gateway, and PDP
code are the same in both.

Packages used (exact versions, from `package-lock.json`):

| Package | Version | Used for |
| --- | --- | --- |
| `@oxdeai/core` | 2.0.2 | `PolicyEngine` (PDP), `AuthorizationV1` issuance, `intentHash`, `sha256HexFromJson`, `verifyAuthorization` (executor, tests), `signAuthorizationEd25519` (forgery tests only) |
| `@oxdeai/guard` | 2.0.3 | `createPepGatewayExecutor` (PEP), `protectUpstreamExecution` (executor token check), `createInMemoryReplayStore` |

No OxDeAI protocol semantics are changed. The only integrator-supplied pieces
are the ones the published gateway leaves open: the action-to-intent mapping
(`hashAction`) and the executor callback.

## Components

```text
            untrusted                       trusted (Phase 1: same Node.js process)
 ┌───────────────────────┐
 │ Agent                 │   AgentGatewayClient (frozen; 3 functions)
 │ src/agent/            │──────────────┬───────────────────┬────────────────────┐
 └───────────────────────┘              │ quote (read-only) │ authorize          │ purchase
                                        v                   v                    v
                              ┌──────────────────┐ ┌──────────────────────┐ ┌──────────────────────────────┐
                              │ mock buy quote   │ │ Authorization service│ │ Gateway (PEP)                │
                              │ (no signing)     │ │ src/authorization/   │ │ src/gateway/                 │
                              └──────────────────┘ │ PolicyEngine (PDP)   │ │ createPepGatewayExecutor:    │
                                                   │ Ed25519 signing key  │ │  1 verifyAuthorization strict│
                                                   │ policy state (CAS)   │ │  2 intent_hash == hashAction │
                                                   └──────────┬───────────┘ │  3 consume auth_id (replay)  │
                                                              │ public      │  4 call executor + token     │
                                                              │ KeySet +    └──────────────┬───────────────┘
                                                              │ authority                  │ x-internal-executor-token
                                                              └──────────────>  trusted    v
                                                                               ┌──────────────────────────────┐
                                                                               │ Executor  src/executor/      │
                                                                               │ protectUpstreamExecution     │
                                                                               │ re-quote; check payee,       │
                                                                               │ network, asset, resource,    │
                                                                               │ price <= max_amount;         │
                                                                               │ journal STARTED; after pay:  │
                                                                               │ verify receipt vs binding    │
                                                                               └──────────────┬───────────────┘
                                                                                              v AuthorizedPayment
                                                                               ┌──────────────────────────────┐
                                                                               │ PaymentAdapter.pay           │
                                                                               │ re-check binding, then sign  │
                                                                               │ Phase 1: src/adapters/mock-buy│
                                                                               │ Phase 2: @celo/buy (stub)    │
                                                                               └──────────────────────────────┘
```

| Component | Path | Holds | Given to agent |
| --- | --- | --- | --- |
| Agent | `src/agent/` | nothing sensitive | n/a |
| Authorization service (PDP) | `src/authorization/authorization-service.ts` | Ed25519 authorization private key, policy state | `authorize` function only |
| Gateway (PEP) | `src/gateway/gateway.ts` | public KeySet, `(issuer, policy_id)` authority, executor token, replay store | `purchase` function only (via client) |
| Executor | `src/executor/executor.ts` | executor token, PDP trust anchor (public KeySet + authority), `PaymentAdapter`, payment journal | no |
| Payment journal | `src/executor/payment-journal.ts` | in-memory (harness) or durable file journal (executor process) | no |
| Isolated deployment | `src/isolation/` | launcher, process entry points, IPC, journal CLI (`docs/ISOLATION.md`) | public socket path only |
| Trust store / artifacts | `src/isolation/artifact.ts`, `trusted-entry.ts`, `trust-cli.ts` | sealed, approved artifact; pre-import and pre-launch verification | no (store is operator-only) |
| Mock buy | `src/adapters/mock-buy/mock-buy.ts` | mock catalog, payment ledger | no (quote is wrapped) |
| `@celo/buy` adapter | `src/adapters/celo-buy/celo-buy.ts` | interface only; throws `NOT_IMPLEMENTED` | no |
| Composition root | `src/system.ts` | creates the executor token; wires everything | returns `client` |

## Request flow

1. Agent quotes (read-only) and builds a `PurchaseRequest`: `service_id`,
   `method`, `url`, `body`, `network`, `asset`, `recipient`, `max_amount`.
2. Agent calls `authorize(request)`. The PDP validates the request, loads
   policy state, builds an OxDeAI `Intent` (below), and runs
   `PolicyEngine.evaluatePure`. On ALLOW it commits the next policy state
   (CAS) and only then returns the signed `AuthorizationV1` plus an
   `intent_ref` (`intent_id`, `agent_id`, `nonce`, `timestamp`).
3. Agent calls `purchase({request, intent_ref, authorization})`. The gateway
   takes a detached, deep-frozen JSON copy of the input, then the published
   `createPepGatewayExecutor` runs:
   1. `verifyAuthorization` in strict mode: Ed25519 signature against the
      trusted KeySet, `expectedAudience`, expiry, `issued_at` plausibility,
      and the `(issuer, policy_id)` authority pair;
   2. `authorization.intent_hash === hashGatewayAction(action)`;
   3. atomic `consumeAuthId(auth_id)`; a second use is `AUTH_REPLAY`;
   4. executor call with the internal executor token header.
4. The gateway sends `{ action, authorization }` (the guard's PEP is built
   per request so the detached authorization can be forwarded). The
   executor accepts only with the token (`protectUpstreamExecution`), then
   verifies the authorization itself (`verifyAuthorization` strict against
   its own trust anchor; `intent_hash` recomputed from the action),
   re-validates the request, re-quotes, and refuses unless the live 402
   requirements match the authorized `network`, `asset`, `recipient`, and
   resource, and the live price is `<= max_amount`.
5. The executor atomically consumes `auth_id` and records `STARTED` in its
   payment journal (keyed by `intent_hash`; a second attempt for the same
   intent or auth_id is refused), then
   calls `pay` with the full authorized binding (`AuthorizedPayment`:
   `intent_hash` plus the exact request, including `recipient`, `network`,
   `asset`, `max_amount`). The adapter contract requires `pay` to re-check
   these against the live requirements immediately before signing and to
   throw `PaymentRefusedError` on any mismatch. The mock does this.
6. After `pay` returns, the executor checks the receipt: `settled === true`,
   well-formed, and `pay_to`, `network`, `asset`, `amount <= max_amount`
   within the binding. This **detects** a bad settlement after the fact;
   it cannot prevent or undo it.

Failures in steps 1-4 return DENY and `pay` is not called. Once `pay` has
been invoked, the result is one of the outcomes below; it is never DENY
unless the adapter attests that nothing was signed.

## Payment outcomes

| Decision | `executed` | Meaning | Produced when |
| --- | --- | --- | --- |
| `DENY` | `false` | Nothing was signed or submitted. | Guard verification fails (upstream not called); executor pre-payment check fails; `pay` throws `PaymentRefusedError`. |
| `ALLOW` | `true` | Settled receipt verified against the binding. | Executor outcome `EXECUTED`. |
| `INDETERMINATE` | `"unknown"` | A payment may have occurred; final outcome not known. Reason `PAYMENT_UNKNOWN`. Not retried. | Any other error from `pay`, ambiguous or out-of-binding receipt, gateway→executor connection loss, gateway timeout, executor internal error. |

The published `createPepGatewayExecutor` reports every upstream error and
timeout as `decision: "DENY", executed: false` (`@oxdeai/guard@2.0.3`,
`dist/gateway.js` L131-178) and has no third outcome. `src/gateway/gateway.ts`
therefore adds an application-level outcome boundary (`classify`) on the
guard's *result*. It does not alter or skip any guard step: when the
upstream was not called, the guard's DENY is returned unchanged. When the
upstream was called, DENY is only returned if the executor positively
attests `NOT_EXECUTED`; anything else is `INDETERMINATE`. A gateway timeout
is `INDETERMINATE` even if the executor had not reached `pay` yet
(conservative); the executor journal resolves it. INDETERMINATE results
carry `auth_id` and `intent_hash` for reconciliation against the journal.

## Authorization binding

`src/authorization/intent.ts` is shared by the PDP and the gateway. The PDP
uses it to build the evaluated intent; the gateway uses it to recompute the
intent hash from what is presented for execution.

| Intent field | Value |
| --- | --- |
| `action_type` | `PAYMENT` |
| `amount` | `BigInt(max_amount)` (atomic units) |
| `asset` | `asset` |
| `target` | `x402:<network>:<recipient>@<origin><path>` |
| `metadata_hash` | SHA-256 (OxDeAI canonical JSON) of `{schema, service_id, method, url, body_sha256, network, asset, recipient, max_amount}` |
| `intent_id`, `agent_id`, `nonce`, `timestamp` | from `intent_ref`, issued by the PDP |
| `depth`, `tool`, `tool_call`, `type` | fixed: `0`, `x402_purchase`, `true`, `EXECUTE` |

`intentHash()` from `@oxdeai/core` covers all of these fields, and the
`AuthorizationV1` signature covers `intent_hash`. A change to any byte of the
method, URL (including query), body, network, asset, recipient, max amount,
service id, or intent_ref yields `INTENT_HASH_MISMATCH`.

Request validation is strict: exact key set, `https` only, no URL
credentials or fragment, URL must equal its WHATWG canonical serialization,
`GET` has no body, recipient is a lower-case 20-byte hex address, and
`max_amount` is a positive decimal integer string. This avoids two spellings
of one request.

Policy (in `src/system.ts`, evaluated by the published `PolicyEngine`
modules): allowlisted `action_types`, `assets`, and complete `target`
tuples; per-action cap; per-period budget; velocity; nonce replay; recursion
depth; concurrency; tool call limits. The `target` excludes the URL query,
so any query on an allowed path is authorizable (it is still bound into
`metadata_hash`).

`@oxdeai/core`'s `AllowlistModule` treats an empty or absent allowlist as
"allow all". Without changing that, the PDP refuses to evaluate policy
state unless `allowlists.action_types`, `assets`, and `targets` are each a
non-empty array of non-empty strings (`assertRequiredAllowlists`,
`src/authorization/policy-state.ts`). Otherwise it returns
`POLICY_STATE_INVALID:*` before evaluation, issues no authorization, and
commits no state.

## Trust boundaries

| Boundary | Phase 1 mechanism | Strength in Phase 1 |
| --- | --- | --- |
| Agent ↔ signing key | key generated inside the PDP closure; only the public KeySet leaves | Holds against an agent that uses only `client`. Not isolation against code in the same process. |
| Agent ↔ executor / adapter | agent receives a frozen object with `quote`, `authorize`, `purchase` only | Same as above. |
| Gateway ↔ executor | random 32-byte token in a header, checked by `protectUpstreamExecution`, plus executor-side verification of the signed authorization | Tested: missing, forged, and duplicated headers are rejected; a valid token with a missing, forged, expired, future, foreign, or mismatched authorization is refused (P2A-13). |
| Agent ↔ executor, keys, wallet, journal (Phase 2A) | separate OS identity for the agent; Unix sockets and files protected by permissions | Tested with kernel errnos from the agent identity (P2A-02, -11, -12). Gateway and executor share one identity. See `docs/ISOLATION.md`. |
| Gateway ↔ signing key, wallet, policy state, journal, ledger (Phase 2B) | separate OS accounts; each secret in a 0700 directory of its owner | Checked by kernel errnos as the gateway identity in manual experiments (R2 review, reproduced in the R4 audit: P2B-02, -03, -07, -19, -20). Not in `npm test`, except that every launch kernel-checks that no service can write the code copies or the policy state root. |
| Gateway ↔ signer (Phase 2B) | auth service accepts only an exact `PurchaseRequest` on `/v1/authorize` and evaluates policy itself | Manual experiments (R2, R4): no other route; pre-built or field-injected authorizations refused; out-of-policy requests denied (P2B-05, -06). |
| Auth ↔ wallet; executor ↔ signing key (Phase 2B) | separate OS accounts | Manual experiments by kernel errnos (R2, R4: P2B-10, -11). |
| Budget ↔ restarts, redeployments, concurrent writers (Phase 2B-R3) | persistent, operator-initialized, binding-checked state; kernel `flock` single writer for services started by the launcher | Tested with real processes (R3-F1a..F4e). Single writer not enforced for an auth process started outside the launcher's `flock` (N1); no rollback resistance (N3). |
| Authorization artifact | Ed25519 signature, audience, expiry, authority pair | Tested: tamper, forged key, wrong audience, expiry. |
| Request ↔ authorization | `intent_hash` recomputed from the presented request | Tested for every bound field. |
| Hashed object ↔ executed object | JSON round-trip + deep freeze before verification | Tested with caller mutation after submit. |
| Authorized binding ↔ payment | `pay` receives `AuthorizedPayment` and must re-check payee, network, asset, price before signing | Mock only. Tested: each changed between quote and pay is refused before signing. Not verified for `@celo/buy`. |
| Payment ↔ reported outcome | executor journal + receipt check + gateway outcome boundary | Mock only. Tested: post-settlement error, lost connection, timeout, ambiguous and out-of-binding receipts are INDETERMINATE. |

## Known limitations

These are stated as limits of Phase 1, not as solved properties.

1. **Single process (Phase 1 harness).** In `src/system.ts` all components
   run in one Node.js process; closures are not isolation. Phase 2A adds the
   process-isolated deployment (`docs/ISOLATION.md`): the agent runs as a
   different OS identity and is denied the executor socket, wallet key,
   ledger, journal, configs, and trusted code by the kernel (P2A-02, -11,
   -12). Its changes to the working tree cannot reach a later launch
   (SI-01..07). Since Phase 2B the gateway, auth service, and executor each
   run as their own account. The operator still has sudo (`docs/ISOLATION.md`
   §0.7). With real `@celo/buy`, the buy process and keychain must run under
   the executor's identity (NOT_TESTED).
2. **Agent is not authenticated.** `agent_id` is fixed by deployment
   configuration, not established from an authenticated caller.
   `createSecureGuard` / `TrustedExecutionContext` are not used: they apply to
   the inline guard path, while this design uses the gateway path where the
   authorization is issued separately and presented by the caller.
3. **Gateway replay store is in-memory.** It is lost on gateway restart and
   not shared across instances. Since Phase 2A the executor also consumes
   `auth_id` durably, so a resubmission after a gateway restart is refused
   by the executor and not paid (P2A-08). Policy state (budget) is no longer
   held by the gateway. Since Phase 2B-R3 it is persistent, operator-
   initialized, bound to the policy identity, written under a kernel lock
   taken by the launcher (single writer only for services started that way;
   N1), and never recreated automatically. It survives restarts and
   redeployments (`docs/ISOLATION.md` §0.4). It is not rollback-resistant:
   restoring an older `state.json` restores consumed capacity (N3).
4. **Authorization is spent before payment.** `auth_id` is consumed before
   the executor runs. If the executor then refuses (price or payee changed),
   the authorization is spent and the budget reserved at authorization time
   is not released. This fails closed but is not a refund mechanism.
5. **Budget is reserved at authorization, not at settlement.** An
   authorization that expires unused still counts against the budget.
6. **Payment-time binding depends on the adapter.** The executor's quote
   check alone does not bind the payment: the live 402 can change between
   quote and pay (payee, network, asset, or price). The adapter contract
   requires `pay` to re-check all of them before signing, and the mock
   does. Per `docs/FEASIBILITY.md`, `buy_curl` accepts `url`, `method`,
   `headers`, `body`, and `maxAmount`, but no recipient, network, or
   asset. Whether a `@celo/buy`-backed adapter can refuse a different
   `payTo` before signing is **not verified**. If it cannot, recipient
   binding at payment time is not provided for buy, and the receipt check
   only detects a wrong payee after funds have moved.
7. **Executor token.** A static shared secret compared with `===` inside the
   published `@oxdeai/guard` helper. In Phase 2A it travels only over the
   executor's private Unix socket, which the agent identity cannot open, and
   it is not sufficient on its own (limitation 15).
8. **Trusted clock is injected.** Tests use a fixed start time
   (`1800000000`). A deployment needs a trusted clock source.
9. **Quote endpoint is unauthenticated** and read-only.
10. **Upstream response is not verified.** The PoC binds what is paid for,
    not what is returned.
11. **Mock identifiers.** `mock-celo`, `mock-usdc`, and the `0x1111…` /
    `0x2222…` addresses are placeholders, not Celo network, token, or
    account identifiers.
12. **ERC-8021 attribution** is not implemented or tested. No claim is made.
13. **Outcome attestation is trusted.** DENY after the executor was called
    relies on the executor's `NOT_EXECUTED` attestation, and for adapter
    refusals on `PaymentRefusedError` being thrown only when nothing was
    signed. Which `@celo/buy` errors guarantee "not signed" is not verified;
    until it is, a buy adapter should map every `pay` error to unknown.
14. **Payment journal.** The executor process uses the durable file journal
    (`docs/ISOLATION.md` §5): survives executor and gateway restarts and
    crashes within one deployment (P2A-08, P2A-09), never auto-resolves
    STARTED. It is deleted with the runtime root when the deployment is torn
    down, so unresolved records do not survive redeployment (N2). Its
    pid-based stale-lock takeover can admit two writers (B6); per-intent
    O_EXCL creation still prevented duplicate reservations in the R4
    experiments. The in-process harness uses an in-memory journal with the
    same interface. Durability is bounded by the local disk; reconciliation
    is a manual operator step (`docs/ISOLATION.md` §6). A persistent journal,
    a robust exclusive lock, and durable settlement reconciliation are
    required before real payments.
15. **Executor token is no longer the executor's only credential.** Since
    Phase 2A the executor verifies the signed authorization and its
    `intent_hash` binding itself (P2A-13). This stops a token holder
    without a valid authorization. Since Phase 2B the gateway no longer
    holds the signing key and no longer shares the executor's identity, so a
    compromised gateway cannot produce valid authorizations or read the
    wallet (P2B-02..05, P2B-20). It can still request in-policy ones.
16. **Agent identity override (F5).** `OXDEAI_AGENT_UID` /
    `OXDEAI_AGENT_GID` are honored by the deployed launcher. Its
    distinctness check compares uids, not gids. In the R4 audit, an agent
    placed in the gateway's group reached the auth and executor sockets;
    the executor token and the policy still prevented an unauthorized mock
    payment. Only the operator's launch environment sets these variables.
    The four-account boundary is therefore conditional on the override not
    being set. Remove, restrict to tests, or harden before real payments.
17. **Single-writer check (N1).** The auth service's startup check does
    not prove that it owns the writer lock; an instance started outside the
    launcher's `flock` with an open descriptor on the lock file ran as a
    second writer in the R4 audit. Requires code execution as
    `oxdeai-auth` (operator or root). Hardening required before real
    payments (`docs/ISOLATION.md` §0.4).

# Architecture: OxDeAI x402 Gateway, Phase 1

Phase 1 is a local, single-process prototype. It uses the published OxDeAI
packages unmodified and a deterministic mock of the `@celo/buy` quote/pay
flow. There is no wallet, no network access, and no chain interaction.

Packages used (exact versions, from `package-lock.json`):

| Package | Version | Used for |
| --- | --- | --- |
| `@oxdeai/core` | 2.0.2 | `PolicyEngine` (PDP), `AuthorizationV1` issuance, `intentHash`, `sha256HexFromJson`, `verifyAuthorization` (tests), `signAuthorizationEd25519` (forgery tests only) |
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
                                                                               │ price <= max_amount          │
                                                                               └──────────────┬───────────────┘
                                                                                              v
                                                                               ┌──────────────────────────────┐
                                                                               │ PaymentAdapter.pay           │
                                                                               │ Phase 1: src/adapters/mock-buy│
                                                                               │ Phase 2: @celo/buy (stub)    │
                                                                               └──────────────────────────────┘
```

| Component | Path | Holds | Given to agent |
| --- | --- | --- | --- |
| Agent | `src/agent/` | nothing sensitive | n/a |
| Authorization service (PDP) | `src/authorization/authorization-service.ts` | Ed25519 authorization private key, policy state | `authorize` function only |
| Gateway (PEP) | `src/gateway/gateway.ts` | public KeySet, `(issuer, policy_id)` authority, executor token, replay store | `purchase` function only (via client) |
| Executor | `src/executor/executor.ts` | executor token, `PaymentAdapter` | no |
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
4. The executor accepts only with the token (`protectUpstreamExecution`),
   re-validates the request, re-quotes, and refuses unless the live 402
   requirements match the authorized `network`, `asset`, `recipient`, and
   resource, and the live price is `<= max_amount`. Then it calls `pay`.

Any failure at any step returns DENY and `pay` is not called.

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
depth; concurrency; tool call limits.

## Trust boundaries

| Boundary | Phase 1 mechanism | Strength in Phase 1 |
| --- | --- | --- |
| Agent ↔ signing key | key generated inside the PDP closure; only the public KeySet leaves | Holds against an agent that uses only `client`. Not isolation against code in the same process. |
| Agent ↔ executor / adapter | agent receives a frozen object with `quote`, `authorize`, `purchase` only | Same as above. |
| Gateway ↔ executor | random 32-byte token in a header, checked by `protectUpstreamExecution` | Tested: missing, forged, and duplicated headers are rejected. |
| Authorization artifact | Ed25519 signature, audience, expiry, authority pair | Tested: tamper, forged key, wrong audience, expiry. |
| Request ↔ authorization | `intent_hash` recomputed from the presented request | Tested for every bound field. |
| Hashed object ↔ executed object | JSON round-trip + deep freeze before verification | Tested with caller mutation after submit. |

## Known limitations

These are stated as limits of Phase 1, not as solved properties.

1. **Single process.** All components run in one Node.js process. Closures
   prevent the agent from being *handed* the executor, but any code running
   in the same process can import `createMockBuyAdapter` or the executor.
   Non-bypassability at the OS or process level is **not demonstrated**.
   With real `@celo/buy`, the boundary must be a separate process and OS user
   for the executor and the buy MCP server / keychain wallet (see
   `docs/FEASIBILITY.md`).
2. **Agent is not authenticated.** `agent_id` is fixed by deployment
   configuration, not established from an authenticated caller.
   `createSecureGuard` / `TrustedExecutionContext` are not used: they apply to
   the inline guard path, while this design uses the gateway path where the
   authorization is issued separately and presented by the caller.
3. **Replay store is in-memory.** Replay protection holds for one gateway
   instance lifetime. It is lost on restart and not shared across instances.
4. **Authorization is spent before payment.** `auth_id` is consumed before
   the executor runs. If the executor then refuses (price or payee changed),
   the authorization is spent and the budget reserved at authorization time
   is not released. This fails closed but is not a refund mechanism.
5. **Budget is reserved at authorization, not at settlement.** An
   authorization that expires unused still counts against the budget.
6. **Executor quote-then-pay window.** The executor re-quotes and then calls
   `pay`. The mock re-checks price inside `pay`; whether real `buy curl
   --max-amount` / `buy_curl` enforces the cap before signing is not verified.
7. **Executor token.** A static shared secret compared with `===` inside the
   published `@oxdeai/guard` helper. Adequate in-process; Phase 2 should use a
   transport the agent cannot reach (Unix socket permissions or mTLS).
8. **Trusted clock is injected.** Tests use a fixed start time
   (`1800000000`). A deployment needs a trusted clock source.
9. **Quote endpoint is unauthenticated** and read-only.
10. **Upstream response is not verified.** The PoC binds what is paid for,
    not what is returned.
11. **Mock identifiers.** `mock-celo`, `mock-usdc`, and the `0x1111…` /
    `0x2222…` addresses are placeholders, not Celo network, token, or
    account identifiers.
12. **ERC-8021 attribution** is not implemented or tested. No claim is made.

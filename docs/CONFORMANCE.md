# Conformance: Phase 1 and Phase 1R

Results are from `npm run test:evidence` on 2026-10-27 (Node.js v24.21.0,
`@oxdeai/core@2.0.2`, `@oxdeai/guard@2.0.3`), run on the Phase 1R
remediation working tree on top of git HEAD `33579f2`. Raw output:
`evidence/test-results.txt` (spec) and `evidence/test-results.tap` (TAP).
Environment and package integrity hashes: `evidence/environment.txt`.

Summary: 82 tests, 82 pass, 0 fail, 0 skipped. 43 are the original Phase 1
tests (unchanged); 39 are Phase 1R regression tests for review findings
F1-F3.

Status meanings: **PASS** = automated test executed and passed.
**FAIL** = executed and failed. **NOT_TESTED** = no executed test supports it.
**DESIGN_LIMITATION** = not provided by the Phase 1 architecture.

All results below are against the mock payment adapter in a single
process. None of them is evidence about real `@celo/buy`, Celo, or OS-level
isolation.

## Mandated tests

| # | Requirement | Status | Tests | Observed DENY reason |
| --- | --- | --- | --- | --- |
| 1 | Valid authorized request | PASS | `T1`, `T1b` (`tests/integration/allow.test.ts`) | n/a: ALLOW, 1 mock payment, artifact verifies in strict mode |
| 2 | Unauthorized service or recipient | PASS | `T2a` service, `T2b` recipient, `T2c` asset, `T2d` 402 payee changed after authorization and before the executor's quote (`tests/authorization/policy.test.ts`); payee changed between quote and pay: `R-F1a` (see below) | `ALLOWLIST_TARGET`, `ALLOWLIST_ASSET`, executor `EXECUTOR_QUOTE_RECIPIENT_MISMATCH`, `MOCK_BUY_RECIPIENT_MISMATCH` |
| 3 | Amount above the approved maximum | PASS | `T3a` per-action cap, `T3b` budget, `T3c` live price > authorized max; `T4 (max_amount raised)` | `PER_ACTION_CAP_EXCEEDED`, `BUDGET_EXCEEDED`, executor `EXECUTOR_QUOTE_EXCEEDS_AUTHORIZED_MAX`, `INTENT_HASH_MISMATCH` |
| 4 | Request body modification after authorization | PASS | `T4` x14 (`tests/security/tamper.test.ts`): body, whitespace-only body change, URL query, URL path, method, recipient, max_amount up/down, network, asset, service_id, nonce, extra field, caller mutation after submit | `INTENT_HASH_MISMATCH`, `ACTION_CANONICALIZATION_FAILED` |
| 5 | Expired authorization | PASS | `T5` at ttl+1 and at exactly ttl (`tests/security/artifact.test.ts`) | `AUTH_EXPIRED` |
| 6 | Replayed authorization | PASS | `T6` sequential and concurrent | `AUTH_REPLAY`; exactly 1 payment |
| 7 | Invalid authorization signature | PASS | `T7a` corrupted bytes, `T7b` signed field changed, `T7c` attacker key with trusted issuer/kid, `T7d` attacker-issued artifact for an unapproved request, `T7e` audience rewritten | `AUTH_SIGNATURE_INVALID`, `AUTH_AUDIENCE_MISMATCH` |
| 8 | Missing or unavailable authorization state | PASS | `T8a` policy state missing, `T8b` policy store unavailable, `T8c` structurally invalid state, `T8d` replay store unavailable; `missing authorization` | `POLICY_STATE_UNAVAILABLE:*`, `STATE_INVALID`, `REPLAY_STORE_UNAVAILABLE:*`, `INVALID_REQUEST` |
| 9a | Executor rejects calls without the internal token | PASS | `T9b` no token, `T9c` forged token, `T9d` duplicated header (`tests/security/bypass.test.ts`) | executor HTTP 403 |
| 9b | Agent-facing client exposes no executor, adapter, token, or key; foreign trust root rejected | PASS | `T9a`, `T9e` | n/a |
| 9c | Non-bypassability of the PEP (process / OS level) | DESIGN_LIMITATION | none: single process; any in-process code can import the adapter or executor | n/a |
| 10 | No mock payment execution following DENY | PASS | `T10` (7 DENY paths on one system), plus `assertNoPayment` in every DENY test | mock `signatures == 0`, `payments == 0`, ledger empty |

Scope note for #9: the tests prove the executor rejects calls without the
internal token and that the agent-facing client exposes no executor,
adapter, token, or key. They do **not** prove that agent code cannot reach
the executor or adapter by other means inside the same process (#9c).

## Phase 1R regression tests (review findings F1-F3)

All against the mock adapter in a single process. Fault injection uses
`createLocalSystem({ faults })` (`src/system.ts`), which wraps trusted-side
components only.

### F1: payment-time binding (`tests/security/payment-binding.test.ts`)

| Test | Security invariant | Observed |
| --- | --- | --- |
| `R-F1a` x4 (recipient, network, asset, price) | If the live 402 changes between the executor's quote and `pay`, `pay` refuses before signing; result is DENY. | DENY, `executed=false`, detail `MOCK_BUY_{RECIPIENT,NETWORK,ASSET}_MISMATCH` / `MOCK_BUY_PRICE_EXCEEDS_MAX_AMOUNT`; journal `REFUSED_BEFORE_SIGNING`; signatures 0, payments 0 |
| `R-F1b` | `pay` receives exactly the authorized request and the verified `intent_hash`. | argument deep-equals `{intent_hash: authorization.intent_hash, request}`; ALLOW; journal `SETTLED` |
| `R-F1c` x4 (recipient, network, asset, amount) | A settled receipt outside the binding is never reported ALLOW. This is detection, not prevention. | INDETERMINATE, `executed="unknown"`, detail `EXECUTOR_RECEIPT_*`; payments **1** (the payment happened); journal `UNKNOWN` |

### F2: indeterminate outcomes (`tests/security/payment-outcome.test.ts`)

| Test | Security invariant | Observed |
| --- | --- | --- |
| `R-F2a` | Error after settlement is not DENY (reproduces review probe P2). | INDETERMINATE, detail `EXECUTOR_PAYMENT_OUTCOME_UNKNOWN:settle_uncertain`; payments 1; journal `UNKNOWN` |
| `R-F2b` | Connection loss after submission to the payment rail is not DENY. | INDETERMINATE; payments 1; journal `UNKNOWN` |
| `R-F2c` | Executor response lost on the gateway→executor hop is not DENY. | INDETERMINATE, detail `socket hang up`; payments 1; journal `SETTLED` |
| `R-F2d` | Gateway timeout after `pay` was invoked is not DENY; `STARTED` is journaled before `pay`. | INDETERMINATE, HTTP 504, detail `UPSTREAM_TIMEOUT`; journal `STARTED` at response time, `SETTLED` after `pay` completes; payments 1 |
| `R-F2e` | Gateway timeout before `pay` is reported conservatively. | INDETERMINATE; journal empty at response time; the late executor pays once |
| `R-F2f` x4 (`settled=false`, null, empty reference, non-numeric amount) | Ambiguous settlement responses are not ALLOW or DENY. | INDETERMINATE, detail `EXECUTOR_RECEIPT_NOT_SETTLED` / `EXECUTOR_RECEIPT_AMBIGUOUS`; journal `UNKNOWN` |
| `R-F2g` | No automatic retry; resubmitting after INDETERMINATE is refused. | `pay` invoked once; second submit DENY `AUTH_REPLAY`; payments 1 |
| `R-F2h` | The executor never hands the same intent to `pay` twice, even with a valid token. | second call `NOT_EXECUTED` / `EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT`; payments 1 |

### F3: required allowlists (`tests/authorization/allowlist.test.ts`)

| Test | Security invariant | Observed |
| --- | --- | --- |
| `R-F3` x18: 9 configurations (empty and absent for each of targets, assets, action_types; targets non-array; targets with an empty-string entry; assets with a non-string entry), each for an allowed and an unlisted service | Missing, empty, or malformed required allowlists fail closed before any authorization is issued, without changing `@oxdeai/core` semantics. | DENY `POLICY_STATE_INVALID:ALLOWLIST_*_{EMPTY,MISSING,INVALID}`; policy state version unchanged (no commit); no payment |
| `R-F3 allowlists object absent` | Same, with no `allowlists` object at all. | DENY `POLICY_STATE_INVALID:ALLOWLISTS_MISSING` |

### Baseline reproduction and negative controls (manually executed)

The review probes were re-run against `git archive 33579f2` (the
unremediated baseline): P1 (payee changed between quote and pay) returned
**ALLOW** with payment to `0x2222…`; P2 (error after settlement) returned
**DENY, executed=false** with 1 mock payment; P3 (empty `targets`) returned
**ALLOW** for the unlisted service.

Each Phase 1R defence was then removed in a scratch copy of the tree (the
repository was not modified) and the suite was run:

| Defence removed | Tests failing |
| --- | --- |
| Recipient re-check in mock `pay` | 1: `R-F1a recipient` |
| Executor receipt verification | 8: `R-F1c` x4, `R-F2f` x4 |
| Gateway outcome boundary (revert to guard DENY) | 14: `R-F1c` x4, `R-F2a`-`R-F2f` |
| PDP `assertRequiredAllowlists` call | 19: all `R-F3` |
| Executor journal duplicate refusal | 1: `R-F2h` |

Not covered by an executed test: the executor's `EXECUTOR_INTERNAL_ERROR`
branch (unreachable by construction: `execute` catches all errors).

## AGENTS.md validation list

| Requirement | Status | Evidence |
| --- | --- | --- |
| Valid authorization | PASS | #1 |
| Policy denial | PASS | #2, `T3a`, `T3b` |
| Spending limit violation | PASS | #3 |
| Expired authorization | PASS | #5 |
| Replay attempt | PASS | #6 |
| Modified payment parameters | PASS | #4 |
| Invalid signature | PASS | #7 |
| Missing policy state | PASS | #8 |
| Attempted direct payment bypass | PASS for token rejection (#9a, #9b); DESIGN_LIMITATION for process/OS non-bypassability (#9c) | #9 |
| Authorization failure before any payment signing | PASS | #10, `R-F1a` |
| Payment-time recipient / network / asset / price binding (mock adapter) | PASS | `R-F1a`, `R-F1b` |
| Ambiguous payment outcome never reported as DENY | PASS | `R-F2a`-`R-F2h`, `R-F1c` |
| Empty or malformed required allowlists fail closed | PASS | `R-F3` |

## Negative controls for Phase 1 defences (manually executed, not in the suite)

Re-executed in Phase 1R on a scratch copy of the current tree (82 tests):

| Defence removed | Result |
| --- | --- |
| `body_sha256` dropped from the binding (`src/authorization/intent.ts`) | 3 tests failed: `T4 (body)`, `T4 (body whitespace only)`, `T10` |
| Gateway JSON snapshot / freeze (`src/gateway/gateway.ts`) | 1 test failed: `T4 caller mutates its request object after submit` |

(The Phase 1 version of this document reported 2 failures for the first
row; `T10`, which includes a tampered-body case, also fails.)

## Not tested

| Property | Status | Reason |
| --- | --- | --- |
| Agent cannot reach executor / adapter / keys at process or OS level | DESIGN_LIMITATION | Single process; requires Phase 2 process and OS-user separation |
| Real `@celo/buy` quote / pay behavior | NOT_TESTED | Adapter is an interface stub (`NOT_IMPLEMENTED`) |
| `buy_curl` / `buy curl --max-amount` refuses before signing when price > cap | NOT_TESTED | No live buy process |
| A `@celo/buy` adapter can refuse a different `payTo`, network, or asset before signing | NOT_TESTED | `buy_curl` takes no recipient/network/asset (FEASIBILITY.md §2); payment-time binding is proven for the mock only |
| Which `@celo/buy` errors guarantee "nothing signed" (`PaymentRefusedError` mapping) | NOT_TESTED | No live buy process; until verified, every buy `pay` error must map to PAYMENT_UNKNOWN |
| Payment journal durability / reconciliation of INDETERMINATE outcomes | NOT_TESTED | In-memory journal; reconciliation is manual |
| Real x402 402-challenge parsing | NOT_TESTED | Mock quote format is this PoC's own |
| Celo settlement | NOT_TESTED | No chain interaction by design |
| ERC-8021 attribution (`celo_9d43bf3ecad7`) | NOT_TESTED | No public evidence of support; see `docs/FEASIBILITY.md` |
| ERC-8004 agent identity | NOT_TESTED | Out of Phase 1 scope |
| Replay protection across restart or multiple gateway instances | NOT_TESTED | In-memory replay store |
| Agent authentication / multi-agent identity | NOT_TESTED | `agent_id` fixed by configuration |
| Budget release for authorizations that are spent but not paid | NOT_TESTED | Not implemented (see ARCHITECTURE.md limitation 4) |

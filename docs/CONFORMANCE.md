# Conformance: Phase 1

Results are from `npm run test:evidence` on 2026-10-27 (Node.js v24.21.0,
`@oxdeai/core@2.0.2`, `@oxdeai/guard@2.0.3`). Raw output:
`evidence/test-results.txt` (spec) and `evidence/test-results.tap` (TAP).
Environment and package integrity hashes: `evidence/environment.txt`.

Summary: 43 tests, 43 pass, 0 fail, 0 skipped.

Status meanings: **PASS** = automated test executed and passed.
**FAIL** = executed and failed. **NOT_TESTED** = no executed test supports it.

All results below are against the mock payment adapter in a single
process. None of them is evidence about real `@celo/buy`, Celo, or OS-level
isolation.

## Mandated tests

| # | Requirement | Status | Tests | Observed DENY reason |
| --- | --- | --- | --- | --- |
| 1 | Valid authorized request | PASS | `T1`, `T1b` (`tests/integration/allow.test.ts`) | n/a: ALLOW, 1 mock payment, artifact verifies in strict mode |
| 2 | Unauthorized service or recipient | PASS | `T2a` service, `T2b` recipient, `T2c` asset, `T2d` 402 payee changed after authorization (`tests/authorization/policy.test.ts`) | `ALLOWLIST_TARGET`, `ALLOWLIST_ASSET`, executor `EXECUTOR_QUOTE_RECIPIENT_MISMATCH` |
| 3 | Amount above the approved maximum | PASS | `T3a` per-action cap, `T3b` budget, `T3c` live price > authorized max; `T4 (max_amount raised)` | `PER_ACTION_CAP_EXCEEDED`, `BUDGET_EXCEEDED`, executor `EXECUTOR_QUOTE_EXCEEDS_AUTHORIZED_MAX`, `INTENT_HASH_MISMATCH` |
| 4 | Request body modification after authorization | PASS | `T4` x14 (`tests/security/tamper.test.ts`): body, whitespace-only body change, URL query, URL path, method, recipient, max_amount up/down, network, asset, service_id, nonce, extra field, caller mutation after submit | `INTENT_HASH_MISMATCH`, `ACTION_CANONICALIZATION_FAILED` |
| 5 | Expired authorization | PASS | `T5` at ttl+1 and at exactly ttl (`tests/security/artifact.test.ts`) | `AUTH_EXPIRED` |
| 6 | Replayed authorization | PASS | `T6` sequential and concurrent | `AUTH_REPLAY`; exactly 1 payment |
| 7 | Invalid authorization signature | PASS | `T7a` corrupted bytes, `T7b` signed field changed, `T7c` attacker key with trusted issuer/kid, `T7d` attacker-issued artifact for an unapproved request, `T7e` audience rewritten | `AUTH_SIGNATURE_INVALID`, `AUTH_AUDIENCE_MISMATCH` |
| 8 | Missing or unavailable authorization state | PASS | `T8a` policy state missing, `T8b` policy store unavailable, `T8c` structurally invalid state, `T8d` replay store unavailable; `missing authorization` | `POLICY_STATE_UNAVAILABLE:*`, `STATE_INVALID`, `REPLAY_STORE_UNAVAILABLE:*`, `INVALID_REQUEST` |
| 9 | Direct payment executor bypass attempt | PASS (in-process scope) | `T9a` client surface, `T9b` no token, `T9c` forged token, `T9d` duplicated header, `T9e` artifact from another trust root (`tests/security/bypass.test.ts`) | executor HTTP 403 |
| 10 | No mock payment execution following DENY | PASS | `T10` (7 DENY paths on one system), plus `assertNoPayment` in every DENY test | mock `signatures == 0`, `payments == 0`, ledger empty |

Scope note for #9: the test proves the executor rejects calls without the
internal token and that the agent-facing client exposes no executor,
adapter, token, or key. It does **not** prove that agent code cannot reach
the executor or adapter by other means inside the same process. See the
NOT_TESTED rows below.

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
| Attempted direct payment bypass | PASS (in-process scope only) | #9 |
| Authorization failure before any payment signing | PASS | #10 |

## Negative controls (manually executed, not in the suite)

To check that the tests detect broken enforcement, two defences were
removed temporarily, the relevant tests were run, and the files were
restored:

| Defence removed | Result |
| --- | --- |
| `body_sha256` dropped from the binding (`src/authorization/intent.ts`) | 2 tests failed: `T4 (body)`, `T4 (body whitespace only)` |
| Gateway JSON snapshot / freeze (`src/gateway/gateway.ts`) | 1 test failed: `T4 caller mutates its request object after submit` |

After restoring, the full suite passed again (43/43).

## Not tested

| Property | Status | Reason |
| --- | --- | --- |
| Agent cannot reach executor / adapter / keys at process or OS level | NOT_TESTED | Single process; requires Phase 2 process and OS-user separation |
| Real `@celo/buy` quote / pay behavior | NOT_TESTED | Adapter is an interface stub (`NOT_IMPLEMENTED`) |
| `buy_curl` / `buy curl --max-amount` refuses before signing when price > cap | NOT_TESTED | No live buy process |
| Real x402 402-challenge parsing | NOT_TESTED | Mock quote format is this PoC's own |
| Celo settlement | NOT_TESTED | No chain interaction by design |
| ERC-8021 attribution (`celo_9d43bf3ecad7`) | NOT_TESTED | No public evidence of support; see `docs/FEASIBILITY.md` |
| ERC-8004 agent identity | NOT_TESTED | Out of Phase 1 scope |
| Replay protection across restart or multiple gateway instances | NOT_TESTED | In-memory replay store |
| Agent authentication / multi-agent identity | NOT_TESTED | `agent_id` fixed by configuration |
| Budget release for authorizations that are spent but not paid | NOT_TESTED | Not implemented (see ARCHITECTURE.md limitation 4) |

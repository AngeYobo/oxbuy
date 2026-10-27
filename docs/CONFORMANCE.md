# Conformance: Phase 1, Phase 1R, Phase 2A, and Phase 2A-R

Results are from `npm run test:evidence` on 2026-10-27 (Node.js v24.21.0,
`@oxdeai/core@2.0.2`, `@oxdeai/guard@2.0.3`), run on the Phase 2A working
and 2A-R working tree (uncommitted) on top of git HEAD `dcfb5dd`, branch
`feat/phase-2a-process-isolation`. Raw output: `evidence/test-results.txt`
(spec) and `evidence/test-results.tap` (TAP). Environment, OS identities,
and package integrity hashes: `evidence/environment.txt`.

Summary: 119 tests, 119 pass, 0 fail, 0 skipped.
- 43 are the original Phase 1 tests.
- 39 are the Phase 1R regression tests. One of them, R-F2h, was adapted to
  the executor's new request envelope; its invariant is unchanged.
- 27 are new in Phase 2A: 17 process-isolation tests and 10 durable-journal
  tests. Since Phase 2A-R, the isolation tests launch from a sealed,
  approved artifact.
- 10 are new in Phase 2A-R: source-integrity tests SI-01..SI-07.

Status meanings:
- **PASS:** an automated test was executed and passed.
- **FAIL:** executed and failed.
- **NOT_TESTED:** no executed test supports it.
- **BLOCKED:** cannot be executed in this environment without approval or
  a missing prerequisite.
- **DESIGN_LIMITATION:** not provided by the architecture.

All results are against the mock payment adapter. None of them is evidence
about real `@celo/buy`, Celo, or a wallet. The Phase 1 and 1R sections run
in a single process. The Phase 2A section runs separate processes under two
OS identities.

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
| 9c | Non-bypassability of the PEP (process / OS level), single-process harness | DESIGN_LIMITATION | none: single process; any in-process code can import the adapter or executor | n/a |
| 9d | Agent identity cannot bypass the PEP to the executor, wallet, ledger, or journal of a **running** deployment (Phase 2A, separate OS identity) | PASS (tested scope) | `P2A-02`, `P2A-11`, `P2A-12` (see Phase 2A) | kernel `EACCES` / `EPERM` |
| 9e | Agent cannot get modified source or dependencies executed by the trusted processes at a later launch | PASS since Phase 2A-R (was FAIL at Phase 2A) | `SI-01`..`SI-07` | `ARTIFACT_NOT_APPROVED`, `ARTIFACT_HASH_MISMATCH`, `ARTIFACT_AGENT_WRITABLE`, `UNTRUSTED_LAUNCHER_LOCATION`, `SEAL_LOCKFILE_MISMATCH` |
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

## Phase 2A: process isolation (`tests/isolation/`, `tests/executor/payment-journal.test.ts`)

Commands: `npm test` (whole suite), or
`node --test tests/isolation/process-isolation.test.ts`. Each test launches
its processes through `src/isolation/launcher.ts`:
- **Agent:** `tests/isolation/agent-probe.ts`, running as `nobody` (uid
  65534, `no_new_privs`).
- **Gateway and executor:** `codespace` (uid 1000), running from a sealed,
  approved artifact in an operator-only trust store (since Phase 2A-R).

Every OS-level assertion is an errno that the kernel returned to the agent
process. Each sits next to a positive control showing the same resource
works for its intended user.

### Adversarial matrix

| ID | Test | Status | Observed result |
| --- | --- | --- | --- |
| P2A-01 | Authorized mock payment | PASS | Agent uid 65534, gateway and executor uid 1000, three distinct pids. `buy` through the public socket returned ALLOW, executed=true. The ledger gained exactly 1 entry with the matching `intent_hash`; the journal shows SETTLED. |
| P2A-02 | Direct executor access by the agent identity | PASS | Agent `connect(executor.sock)` returned `EACCES`; `connect(gateway.sock)` succeeded (control). The operator reached the executor and got 403 without the token (control). Modes: executor dir 0700, socket 0600. `ss -ltunp` shows no inet listener for the executor pid; `ss -lxp` shows its Unix socket. |
| P2A-03 | Forged authorization | PASS | Four forgeries from the agent: self-signed claiming the PDP issuer, self-signed with a foreign issuer, audience edited, signature garbled. All DENY at the gateway, with exact reasons `AUTH_SIGNATURE_INVALID`; `AUTH_ISSUER_POLICY_NOT_AUTHORIZED,AUTH_KID_UNKNOWN`; `AUTH_AUDIENCE_MISMATCH,AUTH_SIGNATURE_INVALID`; `AUTH_SIGNATURE_INVALID`. Ledger unchanged. Executor-side: see P2A-13. |
| P2A-04 | Expired authorization | PASS | TTL 1 s system, agent waited 2.1 s: DENY `AUTH_EXPIRED`, 0 payments. Operator-minted expired artifact (signed with the real PDP key): gateway DENY `AUTH_EXPIRED`; the executor, called directly with the token, returned `EXECUTOR_AUTHORIZATION_INVALID:…AUTH_EXPIRED`. Ledger unchanged. |
| P2A-05 | Wrong issuer or audience | PASS | Signed with the real PDP key but with audience `some-other-gateway`, issuer `rogue-pdp`, or a foreign `policy_id`. Each was rejected by the gateway (`AUTH_AUDIENCE_MISMATCH`; `AUTH_ISSUER_POLICY_NOT_AUTHORIZED,AUTH_KID_UNKNOWN`; `AUTH_ISSUER_POLICY_NOT_AUTHORIZED`) and by the executor directly (`EXECUTOR_AUTHORIZATION_INVALID:<same codes>`). 0 payments. |
| P2A-06 | Modified payment intent | PASS | The agent changed `recipient`, `max_amount`, `url`, or `body` after authorization: each DENY `INTENT_HASH_MISMATCH`. A modified recipient with the original authorization, sent directly to the executor: `EXECUTOR_INTENT_HASH_MISMATCH`. 0 payments. |
| P2A-07 | Replayed authorization | PASS | First submit ALLOW, second DENY `AUTH_REPLAY` (gateway). Direct executor resubmission with the token: `EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT`, `prior_state: SETTLED`. Ledger +1 only. |
| P2A-08 | Executor restart, then duplicate intent | PASS | After ALLOW: graceful restart of the executor **and** the gateway (so the gateway replay store is empty). The resubmission passed the gateway and was refused by the executor from the durable journal: DENY, detail `EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT`. Then SIGKILL and restart: stale lock recovered, direct resubmission refused. Exactly 1 payment; journal SETTLED. |
| P2A-09 | Executor failure after the payment starts | PASS | **`crashAfterPay`:** SIGKILL after the ledger write and before the journal update. The agent got INDETERMINATE, executed `"unknown"`, `PAYMENT_UNKNOWN`. Ledger 1, journal STARTED. After restart: still STARTED and listed in `needs_reconciliation`; resubmission after a gateway restart was INDETERMINATE and not paid (ledger 1). `journal-cli resolve` was refused while the executor ran (`JOURNAL_LOCKED`); after a stop it attached verdict `SETTLED` and the state stayed STARTED. **`crashBeforePay`:** identical, with ledger 0 and verdict `NOT_SETTLED`. |
| P2A-10 | IPC timeout | PASS | Gateway timeout 400 ms. **Executor holds its response 1.5 s:** INDETERMINATE, 504 `UPSTREAM_TIMEOUT`; journal already SETTLED. **`pay` held 1.5 s:** INDETERMINATE, 504; journal STARTED at response time. In both cases, 2 s later: exactly 1 payment and journal SETTLED, with no retry. |
| P2A-11 | Agent reads the protected journal | PASS | The agent got `EACCES` reading `journal.log`, an intent record, `ledger.jsonl`, `mock-wallet.key`, the executor config, and the gateway config (PDP private key and token). The operator read each one (control); the agent read a public file (control). Each file's mode has no group or other bits. Since 2A-R the artifact's `package.json` is also `EACCES` to the agent; the positive control reads the checkout's `package.json`. |
| P2A-12 | Agent invokes the adapter directly | PASS | The agent imported `createMockBuyAdapter` + `withMockSettlement` (from an agent-readable copy; the trusted artifact itself is `EACCES` to the agent since 2A-R) and called `pay` with the executor's paths: `MOCK_WALLET_UNAVAILABLE:EACCES`, and a direct ledger append gave `EACCES`. Ledger bytes were unchanged. Writing trusted code: `EACCES`. `kill` on the executor and gateway: `EPERM`. `/proc/<pid>/environ` and `mem`: `EACCES`. argv contains no secret. `sudo -n true` failed. |
| P2A-13 | Gateway bypasses executor authorization verification | PASS | Holding the valid token and calling the executor directly: no authorization field, a bare action body, `authorization: null`, self-signed with an untrusted key, a valid authorization for a different intent, expired, and `issued_at` 1 h in the future. Each was refused with HTTP 409 `NOT_EXECUTED` (`EXECUTOR_INVALID_REQUEST`, `EXECUTOR_AUTHORIZATION_MISSING`, `…AUTH_SIGNATURE_INVALID`, `EXECUTOR_INTENT_HASH_MISMATCH`, `…AUTH_EXPIRED`, `…AUTH_ISSUED_AT_IMPLAUSIBLE`); a wrong token gave 403. 0 payments, 0 journal reservations. Control: the genuine authorization on the same channel paid once. |
| P2A-14 | Concurrent duplicate requests | PASS | **Via the gateway:** 12 concurrent agent submits gave 1 ALLOW and 11 `AUTH_REPLAY`. **Directly at the executor:** 12 concurrent token-holder requests gave 1 EXECUTED and 11 `EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT`. Exactly 1 ledger entry per intent. A second executor process on the same journal exited with `JOURNAL_LOCKED`. |
| (hygiene) | Secrets in logs and responses | PASS | After a purchase, the internal token, the wallet key (hex), and any `PRIVATE KEY` PEM appear in neither agent-visible responses nor process logs. |

### Durable journal (`tests/executor/payment-journal.test.ts`)

| ID | Invariant | Status | Observed |
| --- | --- | --- | --- |
| J1 | Records survive close and reopen; a reserved intent is never reserved again | PASS | SETTLED and receipt read back after reopen; re-reserve gives `DUPLICATE_INTENT`, prior SETTLED |
| J2 | `auth_id` consumed durably | PASS | Same auth_id for another intent after reopen gives `AUTH_REPLAY` |
| J3 | Single writer; stale lock recovery | PASS | Second open gives `JOURNAL_LOCKED`; lock with a dead pid is recovered (`staleLockRecovered: true`) |
| J4 | Crash recovery never auto-converts STARTED | PASS | After simulated crash: STARTED stays STARTED; STARTED and UNKNOWN are listed in `needsReconciliation`; re-reserve gives prior STARTED |
| J5 | Only STARTED moves to a final state, once | PASS | `JOURNAL_ILLEGAL_TRANSITION:SETTLED->UNKNOWN`; path-traversal hash rejected |
| J6 | Permissions despite `/tmp` default ACL | PASS | Dirs 0700, every file 0600 |
| J7 | Unreadable record is never "absent" | PASS | Truncated record gives UNKNOWN `JOURNAL_RECORD_UNREADABLE`; re-reserve refused |
| J8 | Operator resolution rules | PASS | Only STARTED/UNKNOWN, once; state kept; SETTLED gives `JOURNAL_NOT_RECONCILABLE` |
| J9a | Journal unwritable at reservation: no `pay` | PASS | `EXECUTOR_JOURNAL_UNAVAILABLE:…EACCES`, 0 payments |
| J9b | Journal unwritable after settlement: not reported as success | PASS | `PAYMENT_UNKNOWN EXECUTOR_JOURNAL_WRITE_FAILED`, 1 payment, journal STARTED |

### Negative controls (manually executed, not in the suite)

Each defence was removed in a scratch copy of the tree under `/tmp`, and the
suites were re-run. The repository was not modified.

| Defence removed | Result |
| --- | --- |
| NC1: executor dir 0755 and socket 0666 | 1 failure: P2A-02 (agent connected). P2A-11 and -12 still pass because each file is 0600 on its own. |
| NC1b: as NC1, plus gateway dir 0755 and all private files 0644 | 3 failures: P2A-02, P2A-11, P2A-12 |
| NC2: executor `verifyAuthorization` and the `intent_hash` check disabled | 4 failures: P2A-04, P2A-05, P2A-06, P2A-13 |
| NC3: journal duplicate check removed and O_EXCL replaced by overwrite | 9 failures: J1, J2, J4, J7, P2A-07, P2A-08, P2A-09 ×2, P2A-14 |
| NC4: journal open rewrites STARTED as REFUSED_BEFORE_SIGNING | 3 failures: J4, P2A-09 ×2 |
| NC5: agent uid set to the operator uid (`OXDEAI_AGENT_UID=1000`) | 17 isolation tests **skipped as BLOCKED**, 0 passed |

### Findings and current status

This table separates when a finding was found from where it stands now.

| Finding | Found in | Status at discovery | Current status | Evidence |
| --- | --- | --- | --- | --- |
| Agent can plant source or dependencies that run as the operator at the next launch | Phase 2A pre-commit review | FAIL (reproduced: uid 1000) | **PASS** (remediated in 2A-R) | SI-01..07; mutation tests |
| Budget not enforced across gateway restart: fresh intents get a fresh budget | Phase 2A pre-commit review | FAIL (reproduced: 40,000 spent against a 20,000 budget) | **FAIL** (open) | `docs/ISOLATION.md` A8 |
| Compromised gateway can pay without the executor (reads the wallet key; holds the PDP signing key) | Phase 2A pre-commit review | FAIL (reproduced: ledger +1, no journal record) | **FAIL** (open, design) | `docs/ISOLATION.md` A1 |
| Stale-lock takeover race between two starting executors | Phase 2A pre-commit review | NOT_TESTED (not reproduced in 5 races) | NOT_TESTED | per-intent O_EXCL still prevents a duplicate payment |

### Not established by Phase 2A / 2A-R

| Property | Status | Reason |
| --- | --- | --- |
| Gateway ↔ executor OS isolation | BLOCKED | Needs dedicated OS accounts (creating users not approved). `docs/ISOLATION.md` A1 |
| Protection against a compromised gateway | FAIL | Same uid as the executor, and holds the PDP signing key (A1) |
| Budget and policy state across gateway restart | FAIL | PDP state in memory (A8); reproduced |
| Trusted processes without root-equivalent privileges | NOT_TESTED | Operator uid has passwordless sudo (A2) |
| Integrity of operator-run code from the checkout (tests, npm scripts, bootstrap seal) | NOT_TESTED | Outside the launch guarantee; runs as the operator (`docs/ISOLATION.md` §3a) |
| Durability across loss or rebuild of the Codespace | NOT_TESTED | Journal on local disk (A9) |
| Buy process / keychain under the executor identity | NOT_TESTED | No buy execution; `docs/ISOLATION.md` §7 |
| Real Celo payment binding (payTo / network / asset with `@celo/buy`) | NOT_TESTED | No buy execution; `docs/ISOLATION.md` §7 |

## Phase 2A-R: deployment source integrity (`tests/isolation/source-integrity.test.ts`)

Every attack is executed by a process running as `nobody` against a
disposable, world-writable copy of the working tree. The repository is never
modified. Injected code would write a marker file if it ever ran as the
operator. Design: `docs/ISOLATION.md` §3a.

| ID | Attack / check | Status | Observed result |
| --- | --- | --- | --- |
| SI-01 | Valid approved artifact | PASS | Launch succeeds; executor argv is inside `<store>/artifacts/<approved>/`; agent buy gives ALLOW; ledger 1 |
| SI-02 ×4 | Agent appends code to `executor-main.ts`, `gateway-main.ts`, `executor.ts`, or `launcher.ts` in the working tree | PASS | The approved artifact still launches and pays; marker absent. Re-sealing the tampered tree gives a new digest, with `changesFromApproved.changed = [<file>]`. `verifyArtifact` and the trusted entry give `ARTIFACT_NOT_APPROVED`; the runtime parent stays empty (no processes, no ledger) and the marker stays absent. |
| SI-03 | Agent plants code in the working tree's `@oxdeai/core` and `@oxdeai/guard` and disables the guard's signature check | PASS | Re-seal gives the **same** digest, because dependencies come from the verified tarballs. 4 forged authorizations: all DENY; ledger 0; marker absent. |
| SI-04 | Agent edits the lockfile (substituted integrity; downgraded version) | PASS | Seal fails closed: `SEAL_LOCKFILE_MISMATCH:@oxdeai/core` |
| SI-05 | Agent writes `approved`, an artifact file, `MANIFEST.json`, a new artifact, or the runtime executor or gateway config | PASS | All `Permission denied` (kernel); the artifact still verifies |
| SI-06 | Misdeployment: (a) store tree agent-writable, and the agent modifies `executor-main.ts`; (b) content intact but a non-sticky ancestor directory is agent-writable | PASS | (a) `ARTIFACT_HASH_MISMATCH`; (b) `ARTIFACT_AGENT_WRITABLE:<ancestor>`, from the kernel check as the agent. Both refused before any runtime directory or process; marker absent. |
| SI-07 | Launcher loaded from the working tree; no approved artifact | PASS | `UNTRUSTED_LAUNCHER_LOCATION`; `ARTIFACT_NO_APPROVAL`; nothing created. No fallback. |

Pre-launch tampering reproduction (manual), repeated against the corrected
implementation:
- **Baseline at Phase 2A:** the agent appended code to the checkout's
  `executor-main.ts` and patched `@oxdeai/guard`. At the next launch the
  code ran as uid 1000, and the patched guard was in the snapshot (FAIL).
- **During Phase 2A-R development, SI-02 (`executor.ts`) found a second
  path:** importing an *unapproved* artifact's `launcher.ts` evaluated its
  import graph, and the planted code ran before the launcher's self-check.
  Fixed by `src/isolation/trusted-entry.ts`, which verifies before any
  import.
- **Now:** SI-02 and SI-03 above.

Mutation tests (manual, on disposable copies; the repository was not
modified):

| Mutation (source-integrity defence disabled) | Result (`tests/isolation/source-integrity.test.ts`) |
| --- | --- |
| M1: trusted-entry `verifyArtifact` and the launcher's self-verification removed | 7 failures: SI-01, SI-02 ×4, SI-06, SI-07 (unapproved and tampered artifacts launched) |
| M2: seal copies the working tree's `node_modules` instead of the verified tarball | 1 failure: SI-03 (digest changed by agent-planted dependency code) |
| M3: kernel writability check as the agent removed | 1 failure: SI-06 (store under an agent-writable ancestor launched) |
| M4: trusted entry imports the launcher before verifying | 2 failures: SI-02 for `executor.ts` and `launcher.ts` (planted code ran as the operator on import). The `*-main.ts` variants are not in the launcher's import graph, so they are not caught by this mutation, which is the expected scope |
| M5: lockfile cross-check removed | 1 failure: SI-04 |

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
| Attempted direct payment bypass | **By the agent:** PASS. Token rejection (#9a, #9b). The OS blocks the agent identity from the executor socket, wallet, ledger, journal, configs, and trusted code of a running deployment (#9d: P2A-02, -11, -12) and from later launches (#9e: SI-01..07). **By a token holder without a valid authorization:** PASS, refused (P2A-13). **By a compromised gateway:** FAIL. **Single-process harness:** DESIGN_LIMITATION (#9c). | #9, Phase 2A, 2A-R |
| Authorization failure before any payment signing | PASS | #10, `R-F1a` |
| Payment-time recipient / network / asset / price binding (mock adapter) | PASS | `R-F1a`, `R-F1b` |
| Ambiguous payment outcome never reported as DENY | PASS | `R-F2a`-`R-F2h`, `R-F1c` |
| Empty or malformed required allowlists fail closed | PASS | `R-F3` |
| Executor independently verifies the signed authorization | PASS | `P2A-04`, `P2A-05`, `P2A-06`, `P2A-13` |
| Durable payment journal: restart, crash recovery, duplicate rejection, no auto-retry | PASS (mock, local disk) | `P2A-08`, `P2A-09`, `P2A-14`, `J1`-`J9b` |

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
| Agent cannot reach executor / adapter / keys at process or OS level | PASS in Phase 2A (#9d); DESIGN_LIMITATION in the single-process harness | Gateway ↔ executor separation NOT_TESTED (same uid) |
| Real `@celo/buy` quote / pay behavior | NOT_TESTED | Adapter is an interface stub (`NOT_IMPLEMENTED`) |
| `buy_curl` / `buy curl --max-amount` refuses before signing when price > cap | NOT_TESTED | No live buy process |
| A `@celo/buy` adapter can refuse a different `payTo`, network, or asset before signing | NOT_TESTED | `buy_curl` takes no recipient/network/asset (FEASIBILITY.md §2); payment-time binding is proven for the mock only |
| Which `@celo/buy` errors guarantee "nothing signed" (`PaymentRefusedError` mapping) | NOT_TESTED | No live buy process; until verified, every buy `pay` error must map to PAYMENT_UNKNOWN |
| Payment journal durability / reconciliation of INDETERMINATE outcomes | PASS (mock, local disk) | `J1`-`J9b`, `P2A-08`, `P2A-09`; reconciliation remains a manual operator step (`docs/ISOLATION.md` §6) |
| `PurchaseRequest` binds the HTTP request headers that buy forwards | NOT_TESTED | Headers are not part of the binding (`docs/ISOLATION.md` §7) |
| Real x402 402-challenge parsing | NOT_TESTED | Mock quote format is this PoC's own |
| Celo settlement | NOT_TESTED | No chain interaction by design |
| ERC-8021 attribution (`celo_9d43bf3ecad7`) | NOT_TESTED | No public evidence of support; see `docs/FEASIBILITY.md` |
| ERC-8004 agent identity | NOT_TESTED | Out of Phase 1 scope |
| Replay protection across restart or multiple gateway instances | PASS for duplicate *payment* across gateway and executor restarts (executor durable `auth_id`, P2A-08); NOT_TESTED for the gateway replay store itself and for multiple executor instances on separate storage | Gateway replay store is in memory |
| Agent authentication / multi-agent identity | NOT_TESTED | `agent_id` fixed by configuration |
| Budget release for authorizations that are spent but not paid | NOT_TESTED | Not implemented (see ARCHITECTURE.md limitation 4) |

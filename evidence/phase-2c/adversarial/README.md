# Phase 2C process-level adversarial tests (FI-nn)

New tests in `tests/isolation/financial-integrity.test.ts`, section
"Mandate §6". `FI-nn` = the mandate §6 case number. Real processes under the
four accounts, disposable policy and executor state roots, mock payments,
synthetic keys. Each test ends with `assertConsistent` (invariants I1-I5 at
the top of the file).

| Test | Fault / setup | Asserted |
| --- | --- | --- |
| FI-02 (×2) | executor restarted with `quoteDrift` or `refuseBeforeSigning` | no payment; RELEASED with reason REJECTED_BEFORE_EXECUTION / REFUSED_BEFORE_SIGNING; charge 0; the authorization stays refused after the fault is removed; the freed capacity is usable once |
| FI-03 | `crashAfterAuthRecord` (SIGKILL after consuming the auth_id, before the intent record) | no payment; still charged while the executor is down; after restart RELEASED (NOT_STARTED); journal holds the auth, no intent; resubmission refused |
| FI-04/08 (×2) | `crashBeforePay` / `crashAfterPay` | UNCERTAIN with full charge after executor restart, auth restart, and a full redeployment; no automatic retry; resubmission refused; only remaining capacity usable; operator `resolve` NOT_SETTLED → RELEASED, SETTLED → CONFIRMED |
| FI-05a | `crashBeforeAck` (executor SIGKILL after the auth service applied SETTLED) | redelivery after restart; ack recorded; exactly one CONFIRMED in history; charge = price |
| FI-05b | `crashAfterSettleCommit` (auth SIGKILL after committing a report) | payment once; CONFIRMED once after auth restart; a repeated SETTLED is ALREADY_APPLIED; a contradictory NOT_EXECUTED is not applied; budget unchanged |
| FI-07a | auth, executor, gateway restarted within one deployment with an outstanding authorization | still RESERVED and charged; pays exactly once; replay refused |
| FI-07b | whole deployment replaced (same state roots) | old authorization refused `AUTH_KID_UNKNOWN`; charged until its own domain cancels it after expiry (CANCELLED); never paid |
| FI-09 | one settled and two STARTED payments; then garbled intent record, auth record truncated to 0 bytes, intent record truncated mid-JSON; then corrupt `JOURNAL.json`, then `auths/` removed | damaged records are UNKNOWN, never released, never re-paid, CONFIRMED never moves back; budget unchanged; structural damage: exit 78 `JOURNAL_CORRUPT`, nothing recreated |
| FI-10 | journal directory moved away | exit 78 `JOURNAL_MISSING`; not recreated; no purchase pays; after restoring it the consumed authorization is still refused |
| FI-12/13 | second executor while one runs; two executors started at the same moment; SIGKILL of the holder | second exits 75 `JOURNAL_LOCKED` before `ready`; exactly one of two becomes ready; after SIGKILL the next start acquires the lock and pays |
| FI-15 | agent and gateway identities | every write, create, and unlink on policy state, anchor, journal, ledger, and lock files is refused; all files byte-identical; nothing created |

## Runs

- `fi-run1.tap`: first run, 11/12 pass. The failing test was the first
  version of FI-07, which expected an authorization issued by one deployment
  to pay in a *new* deployment. It was refused `AUTH_KID_UNKNOWN`: each
  deployment generates its own PDP key (the existing T9e behavior;
  confirmed with a scratch probe that printed different `kid`s). That is
  fail-closed, not a financial-integrity counterexample: the reservation
  stayed charged and nothing paid. The test was a new, unapproved test of
  this session, and its expectation was wrong; it was replaced by FI-07a
  (restart within one deployment: pays once) and FI-07b (new deployment:
  refused, charged until cancelled by its own domain).
- `fi07-run2.tap`: FI-07a and FI-07b, 2/2 pass.
- `fi15-run2.tap`: FI-15 extended from the agent to the gateway identity, pass.
- Final: all FI tests in the full suite, `../final/`.

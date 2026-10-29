# Financial integrity: Phase 2C (mock only)

This document describes how the Phase 2C mock keeps budget accounting, payment
records, and policy state consistent through crashes, restarts, redeployments,
stale-state restoration, and concurrent access. Everything here was exercised
with mock payments, synthetic keys, and disposable state. Real `@celo/buy`
behavior is not covered (docs/FEASIBILITY.md).

Test identifiers refer to `npm test`; the results are in docs/CONFORMANCE.md
(Phase 2C) and the evidence in `evidence/phase-2c/` (MANIFEST.md).

## 1. Components and state

| State | Owner (OS account) | Location | Written by |
| --- | --- | --- | --- |
| Policy state: budget charge, nonces, reservations (`state.json`) | `oxdeai-auth` 0600 | `<policyStateRoot>/<binding>/` | auth service, commit protocol (§4) |
| Rollback anchor (hash-chained, append-only) | `oxdeai-auth` 0600, `chattr +a` | `<policyStateRoot>.anchor/<binding>.log` | auth service (append), operator (append as root) |
| Policy writer lock | `oxdeai-auth` | `<policyStateRoot>/<binding>/writer.lock` | flock(2), held by the running auth service |
| Payment journal (auth dispositions, intents, acks, audit log) | `oxdeai-executor` 0700/0600 | `<executorStateRoot>/journal/` | executor |
| Journal writer lock | `oxdeai-executor` | `<executorStateRoot>/journal/journal.lock` | flock(2), held by the running executor |
| Mock ledger | `oxdeai-executor` 0600 | `<executorStateRoot>/ledger.jsonl` | mock settlement |

Both state roots are provisioned and initialized once by the operator and live
outside every deployment's runtime directory. A teardown and redeployment
keep them. Nothing creates a missing journal, state file, or anchor
automatically; each is refused at startup (exit 78).

```sh
node src/isolation/policy-cli.ts provision <policyStateRoot>
node src/isolation/policy-cli.ts init <policyStateRoot> <budget>      # once
node src/isolation/executor-cli.ts provision <executorStateRoot>
node src/isolation/executor-cli.ts init <executorStateRoot>           # once (JOURNAL_EXISTS afterwards)
```

## 2. Financial-state machine

Budget is charged when an authorization is issued, not when it is paid. Every
ALLOW creates a reservation, committed atomically with the charge
(`spent_in_period += max_amount`) in the same policy-state version. The
reservation then moves only on signed executor outcome reports
(`src/authorization/reservations.ts`):

```text
              EXECUTING                SETTLED(a)
  RESERVED ─────────────► EXECUTING ─────────────► CONFIRMED   charge = a (releases max - a)
     │  │                    │  │
     │  │ SETTLED(a)         │  └─ NOT_EXECUTED(REFUSED_BEFORE_SIGNING) ─► RELEASED
     │  └──────────────► CONFIRMED
     │
     ├─ NOT_EXECUTED(REJECTED_BEFORE_EXECUTION | CANCELLED | NOT_STARTED | REFUSED_BEFORE_SIGNING) ─► RELEASED  (charge 0)
     │
     └─ UNCERTAIN (from RESERVED or EXECUTING) ─► UNCERTAIN   full charge held, never released automatically
                                                     ├─ RESOLVED_SETTLED     ─► CONFIRMED (charge = max)
                                                     └─ RESOLVED_NOT_SETTLED ─► RELEASED
```

| Mandate term | Representation |
| --- | --- |
| Authorization issued | ALLOW returned only after the commit's DONE is durable (§4) |
| Budget reserved | reservation RESERVED, charged `max_amount` |
| Payment execution started | journal intent STARTED; reservation EXECUTING (while in flight) |
| Payment confirmed | journal SETTLED with a receipt inside the binding; reservation CONFIRMED |
| Rejected before execution | journal auth disposition REJECTED_BEFORE_EXECUTION or intent REFUSED_BEFORE_SIGNING; reservation RELEASED |
| Outcome uncertain | journal STARTED after a crash, or UNKNOWN; reservation UNCERTAIN |
| Released or reconciled | RELEASED (provably never paid) or CONFIRMED; UNCERTAIN only by operator resolution |

Rules:

- **Release needs proof of non-execution.** NOT_EXECUTED is reported only for
  an auth_id the executor has consumed durably in its journal without (or
  before) calling `pay`. A consumed auth_id is refused forever
  (AUTH_REPLAY), so a released reservation can never become a payment.
- **Uncertainty is held.** STARTED without an in-flight `pay`, UNKNOWN, a
  settlement without a usable amount, or an unreadable record keep the full
  charge. Nothing retries a payment automatically.
- **Idempotent and monotone.** The same report again is ALREADY_APPLIED; an
  older one (e.g. EXECUTING after CONFIRMED) is STALE; a contradictory one is
  refused (REPORT_CONFLICT) without changes.
- **Bound to identifiers.** A reservation is keyed by `auth_id` and records the
  immutable `intent_hash`, `amount`, `expiry`, and execution domain (§3). A
  report whose `intent_hash` does not match, or whose settled amount exceeds
  the reservation, is refused.
- **Auditable.** Every transition is appended to the reservation's `history`
  (state, outcome, reason, report id, time) and committed through §4.

Tests: RS1-RS7, OR1-OR5 (unit); FI-02, FI-03, FI-04/08, FI-05a/b, FI-07a/b,
CX1b, CX2a-d (process level).

## 3. Outcome reports and execution domains

The executor's outcome reporter (`src/executor/outcome-reporter.ts`) derives
each auth_id's outcome from its durable journal only, signs it with the
executor's report key, and sends it to the auth service over the settle
channel. The ack is journaled only after the auth service committed the
outcome, so a crash in between causes a redelivery that is answered
ALREADY_APPLIED (FI-05a, FI-05b).

It also cancels expired, unused authorizations: it asks the auth service for
RESERVED reservations past expiry plus a grace period, consumes each auth_id
durably as CANCELLED, and reports NOT_EXECUTED(CANCELLED).

Settle-channel access control (`src/isolation/settle-channel.ts`): the socket
is reachable only by the executor's group; each request carries a proof file
that only the executor identity can create, owned by its uid and containing
the request hash; and the report signature must verify. Gateway and agent
identities cannot connect (CX2d).

**Execution domain** (CX2; `src/executor/execution-domain.ts`): the pair
(executor uid, journal_id). The signed authorization audience names exactly
one domain, so an authorization verifies only at an executor running on that
journal. The auth service accepts a report, and offers a reservation for
cancellation, only for the reservation's own domain and only while that is the
domain it currently trusts. A reservation of an earlier deployment's journal
stays charged until an executor on that same journal reports it (CX2a, CX2b).
An executor refuses to start if its configuration does not match its own
journal and uid (CX2c).

Each deployment generates a new PDP signing key. An authorization issued by
an earlier deployment is therefore refused by a new one (AUTH_KID_UNKNOWN)
even on the same journal; its reservation stays charged until that journal's
executor cancels it after expiry (FI-07b). Within one deployment, restarting
the auth service, executor, and gateway keeps outstanding authorizations
valid (FI-07a).

## 4. Policy-state durability and rollback detection (N3)

Commit protocol (`src/authorization/policy-state-file.ts`,
`src/authorization/policy-anchor.ts`):

1. append `PREPARE v+1` (with the new state hash and charge) to the anchor, fsync;
2. write the new state to a temp file, fsync;
3. rename it over `state.json`;
4. fsync the directory;
5. append `DONE v+1`, fsync;
6. only then return an authorization or acknowledge a report.

The anchor is a hash chain kept outside the state directory and marked
append-only by the operator (`chattr +a`): the auth service can only append;
truncating, rewriting, or deleting it first requires removing the attribute
(CAP_LINUX_IMMUTABLE).

At startup, the state file is reconciled against the anchor:

| Anchor tail | state.json | Action |
| --- | --- | --- |
| DONE v | v | accept |
| DONE v, PREPARE v+1 | v | ABORT the PREPARE, accept v (no authorization was released) |
| DONE v, PREPARE v+1 | v+1 | append DONE v+1, accept (its reservation stays charged) |
| DONE v+1 | v or older | REFUSE `POLICY_STATE_ROLLBACK` |
| anything else | | REFUSE `POLICY_STATE_ANCHOR_MISMATCH` / `POLICY_ANCHOR_INCONSISTENT` |

While running, `state.json` must equal the anchor head. The anchor parser
enforces strict version progression (CX3): every PREPARE after the genesis is
for exactly the latest completed version + 1, with no other PREPARE open;
DONE and ABORT must match the open PREPARE; a torn final line is accepted
only until an ABORT names it. `reconcile` enforces the same version rule
independently. Damage (missing anchor, not append-only, broken chain,
reordering, truncation at the start) fails closed.

Tests: AN1-AN10 (unit); CX1a-CX1d (process); evidence of CX1 and CX3 in
`evidence/phase-2c/`.

**N3 is CONDITIONAL.** The anchor does not protect against root or the
operator (who can remove the attribute and rewrite both files), a rollback of
the whole filesystem or VM snapshot, or the loss of both files. A process
crash at each commit step is tested (CX1b); power loss (unflushed directory
entries) is reasoned from the fsync protocol, not tested.

## 5. Journal durability and recovery (N2)

Records are written with `src/durable/durable-file.ts`: a new record is a
fsync'd temp file published with `link(2)` (EEXIST if it exists, so it is
both exclusive and only ever complete), then the directory is fsync'd; a
state change is a fsync'd temp file renamed over the record. A crash leaves at
most an orphan `.tmp-*` file, which is never read as a record.

- `reserve` consumes the auth_id (`auths/`) and then creates the STARTED intent
  (`intents/`); `pay` is called only after both are durable. A crash between
  them leaves the auth consumed with no intent: reported NOT_EXECUTED
  (NOT_STARTED), never payable (FI-03).
- STARTED is never converted automatically. After a restart it is reported
  UNCERTAIN; replays of that authorization are refused (FI-04/08, P2A-09).
- An unreadable intent record is UNKNOWN; an unreadable auth record is still
  consumed and is never reported, so its reservation is never released
  (J7, FI-09).
- A missing journal, a corrupt `JOURNAL.json`, or a missing `auths/`,
  `intents/`, or `acks/` directory makes the executor refuse to start
  (exit 78); nothing is recreated (FI-09, FI-10).
- `journal.log` is an append-only audit trail; it is not used for recovery
  and is not integrity-checked.

Crash-consistency assumptions: a local POSIX filesystem (ext4 here) on which
`rename(2)` and `link(2)` are atomic and fsync of a file and of its directory
make the data and the entry durable. Not valid for NFS or filesystems that
ignore fsync. Disk-full and I/O errors are handled fail-closed (J9a, J9b) but
power loss is not tested.

## 6. Writer locking (B6, N1)

Both writers (auth service on `writer.lock`, executor on `journal.lock`) use
`src/durable/exclusive-lock.ts`: a kernel `flock(2)` on an open file
description the process opened itself, taken non-blocking. Opening the lock
file is not ownership: a failed `flock` closes the descriptor and refuses
(another holder: exit 75; lock file unopenable or `flock` failing: the
service refuses to start with another non-zero code). Every journal mutation
re-checks ownership (`assertOwned`) on the held descriptor. The kernel
releases the lock when the holder dies, including on SIGKILL; there is no
pid-based takeover.

Tests: J3 (unit); R3-F4a-e (auth, process); FI-12/13 (executor, process: a
second executor exits 75 before serving; two started at once, exactly one
becomes writer; after SIGKILL the next start acquires the lock).

Assumption: flock(2) works on the filesystem (not NFS) and `/usr/bin/flock`
is a trusted root-owned binary.

## 7. Identity configuration (F5)

Identities are looked up only by account name (`oxdeai-agent`, `-gateway`,
`-auth`, `-executor`); the former `OXDEAI_AGENT_UID` / `OXDEAI_AGENT_GID`
overrides are ignored. Before anything starts, `validateIdentities`
(`src/isolation/identity.ts`) rejects: a missing account or unexpected name;
a uid or gid shared with root, the operator, or another role; a missing
primary group or one with supplementary members; and a role listed in another
role's group. Tests: ID1-ID4. The agent and gateway identities cannot
create, modify, or delete any financial-state file (FI-15; agent also
P2A-11).

## 8. Operational recovery procedure

Run journal commands as `oxdeai-executor` from the executor's deployed code
copy (`sudo -n setpriv --reuid=oxdeai-executor --regid=oxdeai-executor
--clear-groups --no-new-privs --reset-env -- node <app>/src/isolation/journal-cli.ts ...`)
and policy commands as the operator.

1. **Executor or auth service crashed.** Restart it. The kernel has released
   its lock. The auth service applies the crash-state table (§4); the
   executor lists open records (`needs_reconciliation` in its log) and
   reports them UNCERTAIN.
2. **Uncertain payment** (reservation UNCERTAIN, journal STARTED or UNKNOWN):
   ```sh
   node journal-cli.ts <executorStateRoot>/journal pending
   node journal-cli.ts <executorStateRoot>/journal show <intent_hash>
   ```
   Establish the truth out of band (mock: `ledger.jsonl` keyed by
   `intent_hash`; real buy: the payer's token transfers). Stop the executor
   (resolve takes the journal lock), then
   ```sh
   node journal-cli.ts <executorStateRoot>/journal resolve <intent_hash> SETTLED|NOT_SETTLED "<evidence>"
   ```
   and restart it. It reports RESOLVED_SETTLED (→ CONFIRMED) or
   RESOLVED_NOT_SETTLED (→ RELEASED). The intent can never be paid again.
3. **Reservation of another execution domain** (an earlier journal): start an
   executor on that journal; it reports or cancels its own reservations. If
   that journal is lost, the reservation stays charged; there is no automatic
   release.
4. **Auth service refuses to start** (`POLICY_STATE_ROLLBACK`,
   `POLICY_STATE_ANCHOR_MISMATCH`, `POLICY_ANCHOR_*`): do not edit the files.
   Inspect with `node src/isolation/policy-cli.ts verify <policyStateRoot>`.
   To restore a verified backup (auth service stopped):
   `node src/isolation/policy-cli.ts restore <policyStateRoot> <backup.json>`.
   It accepts only a state that the anchor proves existed, carries the
   anchor head's charge forward (no capacity comes back), and freezes the
   backup's open reservations as UNCERTAIN (CX1c).
5. **Executor refuses to start** (`JOURNAL_MISSING`, `JOURNAL_CORRUPT`,
   `EXECUTION_DOMAIN_MISMATCH`): restore the original journal directory from
   a backup of that same journal (same `journal_id`); never initialize a new
   journal in its place while reservations of the old domain are open.
   Damaged individual records are UNKNOWN and need step 2.

## 9. Remaining risks

| # | Risk |
| --- | --- |
| R1 | Root and the operator are trusted. They can rewrite the anchor after `chattr -a`, edit state, journal, or ledger, and resolve payments arbitrarily (N3 CONDITIONAL). |
| R2 | Whole-filesystem or VM snapshot rollback restores state and anchor together; not detectable locally. An external anchor (another trust domain) would be needed. |
| R3 | Power loss and storage that ignores fsync are not tested. |
| R4 | A compromised gateway can still exhaust the budget with in-policy authorizations (B3); a compromised auth service holds the signing key (B5). |
| R5 | A lost journal leaves its reservations charged indefinitely (fail-closed, but capacity is lost until an operator decision). There is no operator command to write off a reservation of a lost domain. |
| R6 | Budget is reserved capacity, not settled spend; a CONFIRMED charge comes from the executor's receipt amount, which with real buy would come from settlement data not verified here. |
| R7 | Each deployment generates a new PDP key, so authorizations do not survive a redeployment; this is fail-closed (FI-07b), not a feature. |
| R8 | `journal.log` and `decisions.jsonl` are audit trails without integrity protection. |
| R9 | All of this is mock behavior. Whether real `@celo/buy` errors can be classified as "refused before signing" is NOT_TESTED (docs/ISOLATION.md §7). |

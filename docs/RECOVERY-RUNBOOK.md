# Executor journal rollback: detection and recovery runbook

Phase 2D remediation of AUD-02, AUD-03 and AUD-04. Mock payments only. This runbook covers the executor
side. Policy-state recovery (`policy-cli verify|rebuild`) is described in `FINANCIAL-INTEGRITY.md`.

## 1. What protects the executor journal

| Store | Location | Owner / mode | Rolled back by an executor-state restore? |
| --- | --- | --- | --- |
| Payment journal | `<executorStateRoot>/journal/` | oxdeai-executor 0700/0600 | **yes** |
| Mock ledger, wallet key | `<executorStateRoot>/` | oxdeai-executor 0600 | **yes** (stands in for the chain) |
| **Consumption checkpoint** | `<executorStateRoot>.anchor/<journal_id>.log` | dir root 0755; file oxdeai-executor 0600, `chattr +a` | **no** (outside the state root, append-only) |

The checkpoint is an append-only, hash-chained log (`src/executor/executor-anchor.ts`). Its first entry
(GENESIS) binds it to exactly one journal (`journal_id`, the execution domain). Every consumption of an
authorization (reserved for payment, or rejected before execution), every final payment state, and every
operator settlement resolution is appended to it **after** the journal write and **before** the executor
acts on it (requests a claim, calls `pay`, answers or VOIDs a rejection).

**Single writer (0007).** Every process that writes the journal (the executor, `journal-cli resolve | seal |
recover`) takes an exclusive lock on the checkpoint file itself, in addition to `journal/journal.lock`.
The checkpoint cannot be replaced, renamed or unlinked (append-only), so a journal directory that is
swapped while the executor runs cannot admit a second writer. The second writer is refused
`CHECKPOINT_LOCKED` (exit 75 for an executor). A journal can no longer be opened for writing without its
checkpoint (`CHECKPOINT_REQUIRED`).

**Backup scope (0007, F-SIBLING).** The checkpoint root `<executorStateRoot>.anchor/` sits next to the
executor state root. **Exclude it from every backup and restore of the executor state**, and never back up
or restore their common parent directory as a unit. A restore that brings back an older checkpoint
together with the journal cannot be detected locally. If the auth service was unreachable when an
authorization was rejected, nothing else holds that fact (§8). Restores performed with `cp -a` or `tar` do
not carry the append-only attribute: such a file shows up as `CHECKPOINT_NOT_APPEND_ONLY`, and it must be
treated as a possible rollback (§3).

**Trust assumption:** only root (CAP_LINUX_IMMUTABLE) can remove `+a` and rewrite or delete the checkpoint.
Root and the operator are trusted, exactly as for the policy anchor (N3 CONDITIONAL). Restoring the
checkpoint itself, or a whole-filesystem or VM snapshot, is **outside** the supported model and is not
detected.

## 2. Provisioning and migration

```sh
node src/isolation/executor-cli.ts provision <executorStateRoot>   # state root (executor 0700) + checkpoint root (root 0755)
node src/isolation/executor-cli.ts init <executorStateRoot>        # journal + wallet key + sealed checkpoint (once)
```

A journal created before this remediation has no checkpoint, and the executor refuses to start
(`CHECKPOINT_MISSING`, exit 78). To migrate, with the executor stopped and after checking that the journal is
the latest one (sealing trusts the journal as it is now; a journal already rolled back before it is sealed
cannot be detected later):

```sh
node src/isolation/executor-cli.ts provision <executorStateRoot>   # creates <executorStateRoot>.anchor
node src/isolation/executor-cli.ts seal <executorStateRoot>        # creates, chattr +a, seals (GENESIS + all current facts)
```

`executor-cli seal` also **completes** a checkpoint that exists but is not sealed yet: empty, or holding only
the torn line of an interrupted `init`/`seal`. It refuses a sealed checkpoint (`CHECKPOINT_ALREADY_SEALED`).
It also refuses an existing checkpoint without `+a` (`CHECKPOINT_NOT_APPEND_ONLY`), which it never re-arms.

## 3. Startup refusal (exit 78 with `"event":"refused"`)

| Reason | Meaning | Action |
| --- | --- | --- |
| `EXECUTION_DOMAIN_MISMATCH:journal` | The journal belongs to another execution domain (for example another deployment's journal restored here). | Restore this domain's own journal. Never point a domain at another's journal. |
| `CHECKPOINT_MISSING` / `CHECKPOINT_UNREADABLE` | Checkpoint absent or unreadable. | Investigate. Do **not** create a new one over an existing journal unless you have proved the journal is current (§2 `seal`). |
| `CHECKPOINT_NOT_APPEND_ONLY` | `+a` was removed, or the file was restored by a backup tool. | **Never re-arm it (`chattr +a`) and never re-seal.** A truncated checkpoint is still a valid chain, so an "integrity check" cannot tell an older one from the current one. Treat it as a possible rollback: escalate, recover the genuine current checkpoint from where it was moved, and only then resume. Out of model if it cannot be found (§8). |
| `CHECKPOINT_UNSEALED` | Empty checkpoint, or only the torn line of an interrupted seal. | `executor-cli seal <executorStateRoot>` (executor stopped), only if the journal is proved current. |
| `CHECKPOINT_LOCKED` (exit 75) | Another process holds the checkpoint: an executor is still running (possibly on a swapped journal directory), or a `journal-cli` write command is running. | Stop the other writer. Never work around the lock. |
| `CHECKPOINT_REQUIRED` | A tool tried to open the journal for writing without its checkpoint. | A defect in that tool; it must pass the checkpoint. |
| `CHECKPOINT_DOMAIN_MISMATCH` | The checkpoint belongs to another journal. | Restore the right checkpoint (root). |
| `CHECKPOINT_CORRUPT` | Hash chain broken, or an unparsable line that is not the last one. | Treat as tampering. Escalate (out of model). |
| **`JOURNAL_ROLLBACK_DETECTED:<n> ...`** | The checkpoint holds facts the journal lost (a restore of an older journal, or deleted records). | Follow §5. |

Torn **trailing** checkpoint lines (a crash during an append, possibly repeated) are not a refusal. It is acknowledged with a TORN
entry at the next start. A journal **ahead** of the checkpoint (crash between the two writes) is not a
refusal either: the missing entries are appended (catch-up), and those facts were never acted on.

## 4. Detection while running

If a journal record disappears while the executor runs and the same authorization is presented again, the
executor refuses before any claim (`JOURNAL_ROLLBACK_DETECTED`) and emits
`{"event":"journal_rollback_detected"}`. From then on it refuses every journal write (`JOURNAL_UNAVAILABLE`),
so nothing is paid. Stop it and follow §5.

## 5. Safe reconciliation after a detected rollback

All commands run as the executor identity, from the executor's deployed code copy, with **the executor
stopped** (they take the journal's and the checkpoint's writer locks; they are refused `CHECKPOINT_LOCKED`
while an executor runs):

```sh
EX="sudo -n setpriv --reuid=oxdeai-executor --regid=oxdeai-executor --clear-groups --no-new-privs --reset-env --"
$EX node <app>/src/isolation/journal-cli.ts <executorStateRoot>/journal verify      # read-only: outcome + list
$EX node <app>/src/isolation/journal-cli.ts <executorStateRoot>/journal recover "<ticket / reason>"
$EX node <app>/src/isolation/journal-cli.ts <executorStateRoot>/journal verify      # must be SAFE_TO_RESUME
```

`recover` re-imports every fact the checkpoint holds and the journal lost, and appends a RECOVERED entry
(note plus the list of restored facts) to the checkpoint:

| Lost fact | Restored as | Effect |
| --- | --- | --- |
| Consumption REJECTED_BEFORE_EXECUTION | auth record, same disposition | The authorization is never payable again (AUTH_REPLAY). Its reservation, never claimed, is released by the auth service at expiry. |
| Consumption RESERVED with a final state (SETTLED, REFUSED_BEFORE_SIGNING, CLAIM_ABANDONED, CLAIM_REFUSED, UNKNOWN) | auth + intent in that final state, with its receipt | The reporter redelivers the positive record. Duplicates are ALREADY_APPLIED/STALE/NOT_CLAIMED; nothing moves twice. |
| Consumption RESERVED **without** a final state (process killed after the claim, or after `pay`) | auth + intent **UNKNOWN**, bound to its claim id and request | The reservation becomes UNCERTAIN and stays **fully charged**. Never treated as non-execution (D5). |
| Settlement resolution | the resolution, verbatim | — |

Then start the executor. `recover` never releases budget, never contacts the auth service, and never calls
`pay`.

## 6. Resolving an unknown payment (AUD-04)

For an intent left UNKNOWN or STARTED (reservation UNCERTAIN), with the executor stopped:

```sh
$EX node <app>/src/isolation/journal-cli.ts <executorStateRoot>/journal pending
$EX node <app>/src/isolation/journal-cli.ts <executorStateRoot>/journal resolve <intent_hash> SETTLED "<ticket / evidence ref>"
```

`resolve` accepts **only** exactly one mock-ledger entry for that intent whose HMAC under the persistent
wallet key binds the intent, this record's claim id and this journal (domain), with a settled receipt
inside the authorized binding (recipient, network, asset; amount ≤ the authorization). It refuses:

| Evidence | Refusal |
| --- | --- |
| no entry (missing or rolled-back ledger) | `NO_SETTLEMENT_EVIDENCE` (absence is never proof of non-execution) |
| two or more entries | `CONFLICTING_EVIDENCE` |
| bad MAC (forged) | `EVIDENCE_INVALID:mac` |
| another claim / another journal | `EVIDENCE_INVALID:claim_id` / `EVIDENCE_INVALID:journal_id` |
| wrong recipient, network or asset | `EVIDENCE_INVALID:outside the authorized binding` |
| amount above the authorization | `EVIDENCE_INVALID:amount exceeds the authorization` |
| receipt not settled | `EVIDENCE_INVALID:receipt` |
| a second resolution | `JOURNAL_ALREADY_RESOLVED` |
| `NOT_SETTLED` | `RESOLUTION_REFUSED` (no non-execution resolution exists) |
| a rolled-back journal | `JOURNAL_ROLLBACK_DETECTED` (recover first) |

The accepted resolution is written to the journal **and** appended to the checkpoint (RESOLVED, with the
evidence), which is the auditable record of the decision. After a restart the executor reports
RESOLVED_SETTLED. The auth service confirms the reservation only for the claim it committed, and charges
exactly the evidenced amount. The intent can never be paid again.

Outcomes, distinguished:

- **Confirmed payment:** a verified resolution, then CONFIRMED with the evidenced charge.
- **Confirmed non-execution:** only from a positive executor record (REFUSED_BEFORE_SIGNING or
  CLAIM_ABANDONED, restored from the checkpoint), then RELEASED by the auth service if that claim was
  committed.
- **Unresolved:** UNCERTAIN, fully charged, indefinitely. There is no timeout and no operator override.

## 7. Limits of the mock evidence (F-LEDGER)

The mock ledger and its wallet key live **inside** the executor state root, so a restore of the whole state
root also rolls back the settlement evidence. A payment made just before the restore then has no
evidence: it stays UNCERTAIN and fully charged (fail-safe). It can never be confirmed or released, and
never re-paid. AUD-04 recovery with evidence is therefore supported for journal-only restores, or when the
ledger is restored from a copy no older than the payments. On a real rail the evidence is the chain, which
no local restore can roll back.

## 8. What is not detected (by design or out of model)

- An older checkpoint restored together with an older journal (F-SIBLING), and a rejection made while the
  auth service was unreachable: no store anywhere still holds that rejection. The authorization can pay
  once, within its binding and budget, and is charged once. Prevention is operational: the backup scope
  above, and never re-arming `+a`. Closing it needs a witness outside the executor that is reachable when the
  rejection happens. None exists in this PoC.

  **Since 0008, that rejection is never presented as final.** Every executor DENY carries `final`:
  - `final: true`: the auth service durably confirmed that the authorization can never be claimed again
    (VOID acknowledged, or a claim refused because the reservation already left RESERVED or expired). That
    rejection survives any executor restore, the checkpoint included (test RB6-a).
  - `final: false`: nothing was paid, but the auth service has not confirmed it (outage, timeout, journal
    failure, a replay answer, an unauthentic request). Treat the authorization as live until it expires.
    After a full executor restore it can still pay once, as above (test RB6-b).

  0008 does not change any payment or budget behaviour; it removes a guarantee the answer used to imply.
- A journal rolled back **before** it was sealed (migration).
- A fact written to the journal and lost in a crash before its checkpoint entry, followed by a rollback.
  That fact was never acted on (the claim and `pay` come after the checkpoint), so nothing becomes payable
  twice.
- Root rewriting the checkpoint after `chattr -a`, or a whole-machine snapshot rollback.

## 9. Operational dependencies and trade-offs

- Every payment and every pre-execution rejection adds one fsync'd append to the checkpoint.
- A failed checkpoint append marks the journal unavailable until restart, which catches up. The executor
  then refuses work (fail closed): an availability trade-off.
- The checkpoint grows without bound (one line per consumption or final state). No compaction is
  implemented.
- After `recover`, outstanding rejected authorizations stay charged until they expire. No automatic VOID
  retry was added.
- "Checkpoint before acting" covers consumptions (every claim, `pay`, rejection answer and rejection VOID).
  One exception: when a claim's answer is lost, the executor writes CLAIM_ABANDONED and sends its VOID even
  if that final state's checkpoint append failed. The VOID releases only a claim that this process will
  never pay, so this has no financial effect.

## 10. x402 testnet rail: reconciling an INDETERMINATE payment

With `ExecutorConfig.payment.kind = "x402-evm"`, the settlement evidence is the chain
(`docs/TESTNET-X402.md` §3.3).

1. Find the transaction. The journal record of the intent (`journal-cli show <intent_hash>`) holds the payer,
   the nonce and `validBefore` in its detail (and the tx hash when one was returned). The explorer
   (https://celo-sepolia.blockscout.com) lists the token's `AuthorizationUsed` events for that payer.
2. Executor stopped, as the executor identity:
   `node src/isolation/journal-cli.ts <journalDir> resolve-x402 <intent_hash> <tx_hash> <rpcUrl> <walletKeyPath> "<note>"`.
   It refuses a pending, reverted or unrelated transaction.
3. Start the executor. The reporter sends `RESOLVED_SETTLED`, and the reservation is confirmed at the settled
   amount.
4. No transaction found: do nothing. The reservation stays UNCERTAIN and fully charged. A reverted transaction
   or a "not settled" answer is not proof: the signed authorization can still settle until `validBefore`.

### 10.1 Order of reporting and resolution (patch 0010, XR-01)

Before 0010, a resolution recorded while the auth service still held the reservation EXECUTING (no UNCERTAIN
report delivered yet, e.g. the executor never restarted after a crash) was refused forever and the budget stayed
charged. Since 0010 the service confirms `EXECUTING --RESOLVED_SETTLED--> CONFIRMED` with the same evidence rules
(claim id, amount <= reservation). The order of `resolve-x402` and the first report no longer matters.

### 10.2 Files that hold signed payments (XR-04)

The journal record and the checkpoint keep the signed EIP-3009 authorization of every x402 payment (R-02). Until
its `validBefore` (at most the OxDeAI authorization expiry) anyone holding it could submit exactly that transfer
once. Keep both executor-private, and back up or export them only after `validBefore` has passed.

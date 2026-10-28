# Phase 2C mutation checks

`run-mutations.ts` copies the working tree (rsync, without `.git`,
`evidence`, `.agents`, `.claude`) into a disposable directory per mutant,
applies the edit (each `find` string must match exactly once), and runs the
named tests with `--test-name-pattern`. The repository and the original
evidence are never modified. An unmutated copy is run first (BASELINE) and
must pass.

    node evidence/phase-2c/mutation/run-mutations.ts            # all
    node evidence/phase-2c/mutation/run-mutations.ts M07 M13    # selected

## Results

| Mutant | Protection disabled | File | Detected by (failing tests) | Verdict |
| --- | --- | --- | --- | --- |
| M01 | CX3 strict PREPARE version progression | policy-anchor.ts | AN4, AN6, AN10 | KILLED |
| M02 | CX1: state one commit behind the head accepted (original CX1) | policy-anchor.ts | AN2, CX1a | KILLED |
| M03 | F3: UNCERTAIN outcome releases the reservation | reservations.ts | RS2, FI-04/08 (×2) | KILLED |
| M04 | F3: STARTED-not-in-flight reported NOT_EXECUTED | outcome-report.ts | OR3, FI-04/08 (×2) | KILLED |
| M05 | CX2: cancellation listing and release not restricted to the reservation's domain (original CX2) | authorization-service.ts | CX2a, CX2b | KILLED |
| M06 | CX2: reports from a non-current domain accepted | authorization-service.ts | OR5, CX2d | KILLED |
| M07 | B6/N1: a failed `flock` treated as ownership | exclusive-lock.ts | J3, FI-12/13, R3-F4a, R3-F4b | KILLED (run 3, 4/4, timed out; see run notes) |
| M08 | N2: journal AUTH_REPLAY on a consumed auth_id | payment-journal.ts | J2 | KILLED |
| M09 | N2: unreadable record treated as absent | payment-journal.ts | J7, FI-09 | KILLED |
| M10 | N3: auth service ignores a REFUSE from anchor reconciliation | policy-state-file.ts | CX1a | KILLED |
| M11 | F5: identity validation always passes | identity.ts | ID2 | KILLED |
| M12 | Executor quote above the authorized maximum | executor.ts | FI-02 (quoteDrift) | KILLED |
| M13 | Executor ignores its own authorization verification verdict | executor.ts | P2A-04, P2A-05, P2A-13, CX2e | KILLED (run 2) |

Baselines (unmutated copy, selected tests): run 1, 54/54 pass
(`baseline-run1.log`); run 2, 9/9 (`results-run2.json`); run 3, 4/4
(`results-run3.json`, `baseline.log`).

## Run notes

- **Run 1** (`run1.log`, `results-run1.json`, one `M*.log` per mutant).
  - M07 was reported SURVIVED with no counts. That was a harness defect, not
    a surviving mutant: the log (`M07-run1-timeout.log`) shows all four
    selected tests `not ok`; with the lock check disabled, a second writer
    leaves a child process running, so the test run was cut off by the
    harness's 900 s timeout before TAP printed its summary, and the
    classifier required a summary. In R3-F4b the per-mutation
    `assertOwned` re-check still caught the second writer
    (`LOCK_HELD ... not owned (status 75)`), which is the defence-in-depth
    layer behind the acquisition check.
  - M13 originally set the executor's `requireSignatureVerification` to
    false and SURVIVED (`M13-run1-equivalent.log`). That was an
    **equivalent mutant**: the executor calls `verifyAuthorization` with
    `mode: "strict"`, and `@oxdeai/core@2.0.2` makes the signature check
    mandatory in strict mode regardless of that flag
    (`dist/verification/verifyAuthorization.js`: `requireSig = mode === "strict" || ...`).
    It was replaced by a mutant that ignores the verdict altogether.
  - M12 is caught only by FI-02: with the executor's quote check removed,
    the mock adapter's `pay` still refuses a price above `max_amount` before
    signing (`src/adapters/mock-buy/mock-buy.ts:69`), so T3c and R-F1a stay
    green. FI-02 inflates only the quote, which only the removed check sees.
- **Run 2** (`run2.log`, `results-run2.json`): replaced M13 KILLED (4/5).
  M07 again cut off by the timeout (`M07-run2-timeout.log`, same four
  failures); the first classifier fix (status null) did not match how the
  cut-off run exited.
- **Run 3** (`run3.log`, `results-run3.json`): M07 with the final classifier
  (KILLED whenever any selected test is `not ok`; timeout detected from the
  spawn error or signal): **KILLED, 4/4 failed, `timed_out: true`**.
  Afterwards three mutant auth processes left running by the M07 runs
  (one per run, in deleted disposable copies) were stopped with SIGTERM.

## Files

- `results.json` and `baseline.log` are overwritten by each run; they now
  hold run 3. `results-run1.json`, `results-run2.json`, `results-run3.json`
  are the per-run copies.
- `M07.log` is the run-3 log; `M07-run1-timeout.log` and
  `M07-run2-timeout.log` are the earlier cut-off runs.
- `M13.log` is the run-2 log of the replacement mutant;
  `M13-run1-equivalent.log` is the original, equivalent mutant.
- `run1.log`, `run2.log`, `run3.log`: harness stdout. `run.log` is a copy of
  run 1's stdout.
- The campaign was not re-run after the FI-07b TTL change, which touches no
  mutated source line and no test selected by any mutant.

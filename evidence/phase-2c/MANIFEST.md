# Phase 2C evidence manifest

Branch `feat/phase-2c-financial-integrity`, base `a2b85c1`, validated as an
uncommitted working tree and then committed as the Phase 2C checkpoint
(`checkpoint/`), 2026-10-28, Node.js v24.21.0, `@oxdeai/core@2.0.2`,
`@oxdeai/guard@2.0.3`. Mock payments only: no real wallet, no Celo
transaction, no external signing. Test and demo state was disposable (temp
roots under `/tmp`).

Commands run from the repository root as the operator (passwordless sudo,
the four `oxdeai-*` accounts present). Results and the requirement matrix:
`docs/CONFORMANCE.md`, "Phase 2C". Design: `docs/FINANCIAL-INTEGRITY.md`.
Resume point after a restart: `RECOVERY.md`.

## Final validation (current)

| Check | Exit | Result | File |
| --- | --- | --- | --- |
| Full suite `node --test "tests/**/*.test.ts"` | 0 | 184 tests, 184 pass, 0 fail, 0 cancelled, 0 skipped, 0 todo | `fi07b-remediation/full-suite.tap`, `full-suite.txt` |
| Typecheck `npx tsc -p tsconfig.json` | 0 | clean | `fi07b-remediation/typecheck.log` |
| FI-07b alone, 3 runs | 0, 0, 0 | 1/1 each | `fi07b-remediation/fi07b-alone-run{1,2,3}.tap` |
| Mutation M01-M13 | | all KILLED | `mutation/README.md`, `mutation/results-run{1,2,3}.json` |

## Directories

| Directory | What | Reproduce | Status |
| --- | --- | --- | --- |
| `counterexamples/` | CX1, CX2 as found (original reproducer and logs) | `node evidence/phase-2c/counterexamples/reproduce.ts cx1\|cx2` | original; unchanged |
| `counterexamples-after-fix/` | CX1, CX2 reproducer re-run after remediation | same | history |
| `counterexamples-cx3/` | CX3 as found (failing AN4 TAP, pure reproducer) | `node evidence/phase-2c/counterexamples-cx3/reproduce.ts` | original; unchanged |
| `counterexamples-cx3-after-fix/` | CX3 reproducer after remediation; AN4 fixture correction record | same | history |
| `an4-fixture-reverify/` | AN4 fixture correction re-verification: AN4, anchor suite, CX1/CX2/CX3 original reproducers, typecheck, full suite 171/171 (before the FI tests existed) | see its README | history |
| `adversarial/` | development runs of the new process-level tests FI-02..FI-15 | `node --test --test-name-pattern='^FI-' tests/isolation/financial-integrity.test.ts` | history; `fi-run1.tap` has the first, wrong FI-07 (see README) |
| `mutation/` | 13 mutants in disposable copies, three runs | `node evidence/phase-2c/mutation/run-mutations.ts [M01 ...]` | current; see README for the M07 timeout and M13 equivalent-mutant history |
| `demo/` | `demo:isolated` ×3 on persistent state, BLOCKED case, `npm run demo`, `policy-cli verify` | `docs/DEMO.md`; see README | current (manual) |
| `final/` | first two "final" full-suite runs (183/184, FI-07b failed on its 3 s TTL), FI-07b alone with the unchanged test (`fi07b-after-fix.tap`, misnamed), baseline, protected-file check, file inventory | `npm test` | **superseded** by `fi07b-remediation/`; kept as history |
| `fi07b-remediation/` | FI-07b cause (timing probe), test-only TTL diff, FI-07b ×3, typecheck, full suite 184/184 | see its README | **current final validation** |
| `checkpoint/` | committed file inventory and SHA-256 of every source and test file in the Phase 2C checkpoint commit | see its README | current |

`final/run1-*` is the first final run; `final/test-results.*`,
`final/exit-codes.txt`, and `final/typecheck.log` are the second. Files
named `verification-*` in `final/` are from the documentation finalization
(Scope 3) and record working-tree status and protected-file integrity.

`final/verification-code-unchanged.txt` contains only `exit=0`; the command
was not recorded with it. Per `RECOVERY.md` (3c) it is the exit status of
re-checking the 31 repository entries of `fi07b-remediation/sha256.txt`
(recorded 14:12:03 UTC, before the final suite run at 14:20:23 UTC). It
covers only those 31 files. It says nothing about the other 33 source and
test files: 12 in `src/` (`adapters/*`, `agent/*`, `durable/*`,
`gateway/*`, `demo.ts`, `demo-isolated.ts`, `system.ts`) and all 21 under
`tests/` except `tests/isolation/financial-integrity.test.ts`. For those, correspondence with the final run rests on file
modification times only; `checkpoint/source-sha256.txt` lists which files
fall in which group.

### Evidence inventory snapshots

The file counts in the snapshots differ because each was taken at a
different time, and none counted git-ignored files:

| Snapshot | Time (UTC) | Untracked evidence files | Note |
| --- | --- | --- | --- |
| `final/file-inventory.txt` | 13:34:48 | 46 | before `fi07b-remediation/` and the FI-07b test fix |
| `final/verification-working-tree.txt` | 15:08:04 | 66 | `final/verification-code-unchanged.txt` was written 6 s later, making 67 |
| `checkpoint/commit-inventory.txt` | checkpoint | all committed files | adds `checkpoint/` and the 37 `*.log` files |

The 37 `*.log` files (typecheck logs, mutation logs, CX reproducer logs,
`demo/provision.log`, `fi07b-remediation/timing-probe-before.log`) match
the repository's `*.log` ignore rule. They were reviewed and force-added by
explicit path; `.gitignore` is unchanged.

## Not evidence

- `/tmp/oxdeai-demo-*` (demo trust store and state): gone with the Codespace
  restart of 2026-10-28 14:34 UTC, not deleted by the agent (`demo/README.md`).
- Agent scratchpad files under `/tmp/claude-1000/`: working copies only.

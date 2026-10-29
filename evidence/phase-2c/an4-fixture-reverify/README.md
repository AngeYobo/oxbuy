# AN4 fixture correction: re-verification (2026-10-28)

Approved by the owner (option 1): construct a valid, sequentially completed
anchor history in AN4 and keep the CX3 assertion unchanged.

## Exact change (tests/authorization/policy-anchor.test.ts, AN4, line 71 only)

    - const down = build([...genesis, prepare(3), done(3)]);
    + const down = build([...genesis, prepare(1), done(1), prepare(2), done(2), prepare(3), done(3)]);

Rationale: the old fixture jumped from completed version 0 to PREPARE 3. The
CX3-corrected parser rejects that while the fixture is being built
(`PREPARE 2 for version 3, expected 1`), so the test failed in its setup and
never reached the CX3 assertion. The new fixture completes versions 0, 1, 2,
3 in order, which the parser must accept.

Unchanged:
- the CX3 assertion on line 72 (stale PREPARE for version 2 after DONE 3 must
  throw an error starting with `POLICY_ANCHOR_CORRUPT`). It is the same line
  that failed in the original CX3 finding (`../counterexamples-cx3/unit-tests-run1.tap`,
  stack `policy-anchor.test.ts:72:10`);
- every other AN4 assertion;
- `src/authorization/policy-anchor.ts` (no change for this fixture).

`an4-current-source.txt` is AN4 as run; `sha256-before.txt` the hashes of the
test file, the anchor implementation, and both original reproducers at the
time of this run.

## Results

| Check | Command | Result | File |
| --- | --- | --- | --- |
| AN4 | `node --test --test-name-pattern='^AN4 ' tests/authorization/policy-anchor.test.ts` | 1/1 pass | `an4.tap` |
| Anchor unit suite | `node --test tests/authorization/policy-anchor.test.ts` | 10/10 pass (AN1-AN10) | `anchor-suite.tap` |
| Original CX3 reproducer | `node evidence/phase-2c/counterexamples-cx3/reproduce.ts` | exit 1, `POLICY_ANCHOR_CORRUPT:PREPARE 8 for version 2, expected 4` (fails safely: the stale entry is rejected while the anchor is built; `reconcile` is never reached) | `cx3-original-reproducer.log` |
| Original CX1 reproducer | `node evidence/phase-2c/counterexamples/reproduce.ts cx1` | auth refuses to start (code 78, `POLICY_STATE_ROLLBACK:state version 1, anchor head version 2`); no third ALLOW | `cx1-original-reproducer.log` |
| Original CX2 reproducer | `node evidence/phase-2c/counterexamples/reproduce.ts cx2` | reservation RESERVED, 10000 charged; new deployment `BUDGET_EXCEEDED`; 1 payment | `cx2-original-reproducer.log` |
| Typecheck | `npx tsc -p tsconfig.json` | exit 0 | `typecheck.log` |
| Full suite (before the new Phase 2C adversarial tests) | `node --test "tests/**/*.test.ts"` | 171 tests, 171 pass, 0 fail, 0 skipped, 0 cancelled; includes CX1a-d, CX2a-e | `full-suite.tap` |

Exit codes: `exit-codes.txt`. The reproducers' exit codes are 0 for CX1/CX2
(they report what happened) and 1 for CX3 (the parser throws).

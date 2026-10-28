# CX3 reproducer after remediation

The ORIGINAL reproducer, unchanged (`../counterexamples-cx3/reproduce.ts`),
run against the corrected tree on 2026-10-28:

    node evidence/phase-2c/counterexamples-cx3/reproduce.ts > cx3-after-fix.log 2>&1   (exit 1)

`parseAnchor` now rejects the stale entry while the anchor is being built:
`POLICY_ANCHOR_CORRUPT:PREPARE 8 for version 2, expected 4`. `reconcile` is
never reached with that anchor; it also refuses such a pending transition on
its own (POLICY_ANCHOR_INCONSISTENT; tests/authorization/policy-anchor.test.ts AN8).

## AN4 fixture correction (approved by the owner, option 1)

`tests/authorization/policy-anchor.test.ts`, AN4, setup line only:

    - const down = build([...genesis, prepare(3), done(3)]);
    + const down = build([...genesis, prepare(1), done(1), prepare(2), done(2), prepare(3), done(3)]);

Rationale: the old fixture jumped from version 0 to 3, which the corrected
parser rejects while building (`PREPARE 2 for version 3, expected 1`), so the
test stopped before its assertion. The new fixture is a valid history with
versions 0, 1, 2, 3 completed in order. The CX3 assertion on the next line is
unchanged: a stale PREPARE for version 2 after DONE 3 must be rejected with
POLICY_ANCHOR_CORRUPT. The anchor implementation was not changed for this.

# CX1 / CX2 reproducers after remediation

The ORIGINAL reproducer, unchanged (`../counterexamples/reproduce.ts`, sha256
recorded before this run), executed against the corrected working tree on
2026-10-28. Commands, from the repository root:

    node evidence/phase-2c/counterexamples/reproduce.ts cx1 2> cx1-after-fix.log
    node evidence/phase-2c/counterexamples/reproduce.ts cx2 2> cx2-after-fix.log

- CX1: auth refuses to start (exit 78, `POLICY_STATE_ROLLBACK:state version 1,
  anchor head version 2`); no third authorization is issued.
- CX2: the reservation stays RESERVED and charged (10000) while the old
  executor completes its payment; the new deployment answers
  `BUDGET_EXCEEDED`. No budget reuse.

The permanent regression tests are in `tests/isolation/financial-integrity.test.ts`
(CX1a-CX1d, CX2a-CX2e) and `tests/executor/execution-domain.test.ts`.

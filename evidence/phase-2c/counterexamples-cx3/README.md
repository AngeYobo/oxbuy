# CX3: anchor accepts a PREPARE below the completed head (found 2026-10-28; work stopped)

Found by the new unit test `tests/authorization/policy-anchor.test.ts` (AN4,
"Missing expected exception"; `unit-tests-run1.tap`). Confirmed with the pure
reproducer `reproduce.ts` (no processes, no state written):

    node evidence/phase-2c/counterexamples-cx3/reproduce.ts   ->  cx3-run1.log

Anchor: completed versions 0..3 (DONE 3 = head), then an open PREPARE for
version 2 (an older state, less spent). `parseAnchor` accepts it, and
`reconcile` answers COMPLETE_PENDING for a state.json at that version 2: an
auth service starting on it would append DONE 2 and run from a state OLDER
than the latest completed DONE. That violates CX1 invariant 2.

Reachability: the anchor file is append-only (`chattr +a`) and writable only
by `oxdeai-auth` (or root). The auth service itself always prepares
head + 1. So this needs code running as oxdeai-auth, or root: outside the
current threat model, but a defect in the anchor's own verification (it should
not depend on the appender being honest about version order).

Proposed fix (not applied): `parseAnchor` rejects any PREPARE whose version is
not greater than the latest completed version (POLICY_ANCHOR_CORRUPT), and
`reconcile` additionally requires pending.version === head.version + 1 for
COMMIT / RESTORE before completing it.

# Phase 2C counterexamples (found before the adversarial suite; implementation path stopped)

Mock only, disposable state, real processes under the four accounts, working
tree on `feat/phase-2c-financial-integrity` (uncommitted), base `a2b85c1`,
2026-10-28. Reproduce with `node evidence/phase-2c/counterexamples/reproduce.ts [cx1|cx2]`
from the repository root (operator with passwordless sudo).

## CX1: one-step state rollback accepted as an interrupted commit (N3)
`cx1-run1.log`. Budget 20000, two ALLOWs (spent 20000), a third request is
DENY BUDGET_EXCEEDED. Auth stopped; `state.json` replaced by the copy taken
after the first ALLOW (one commit earlier). Auth starts, appends ABORT, and
issues a third ALLOW: 30000 authorized against 20000.
Cause: `openFilePolicyStateStore` treats "anchor head is a COMMIT for v+1 and
the file is version v" as a crash between anchor append and rename. That is
indistinguishable from restoring the immediately previous state.

## CX2: reservation released while an older deployment's executor pays it (F3)
`cx2-run2.log` (run 1, `cx2-run1-not-reproduced.log`, did not reproduce only
because an EXECUTING report reached the old auth service first).
Deployment 1 (executor journal E1, pay delayed 9 s) accepts authorization X
and starts paying; its auth service is killed. Deployment 2 (same policy
state, new executor journal E2) starts; after X expires its executor cancels
X in E2 and the auth service releases the reservation (spent 10000 -> 0). The
old executor completes the payment (ledger 1), and deployment 2 issues a new
ALLOW: one uncharged payment plus a new 10000 authorization against 10000.
Cause: cancellation proves non-execution only for the cancelling executor's
journal; any executor that trusts the issuing key and uses another journal
can still execute.

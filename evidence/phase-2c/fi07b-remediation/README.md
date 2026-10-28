# FI-07b targeted test remediation (2026-10-28)

## Cause (confirmed: expiration)

FI-07b used a 3 s authorization TTL. `issued_at` is whole seconds and the
authorization was issued 0.84-0.96 s into that second, so it had about 2.1 s
of real validity. Stopping deployment 1 and launching deployment 2 takes
2.09-2.30 s on its own (`timing-probe-before.log`, 3 runs of
`timing-probe.test.ts`, which mirrors the FI-07b setup). In 2 runs the
authorization had expired before the submit began, in 1 it expired during
it. Verification then returned `AUTH_EXPIRED,AUTH_KID_UNKNOWN`: the key check
fired in every run; expiry was added by timing. Same result in the isolated
run (`../final/fi07b-after-fix.tap`, which ran the UNCHANGED test despite its
name) and the full suite (`../final/run1-test-results.tap`,
`../final/test-results.tap`).

## Change (test only; `fi07b.diff`)

TTL 3 -> 15 in the FI-07b policy-state root and both launches (the policy
binding includes the TTL, so all three must agree), plus a comment. 15 s
keeps the authorization valid when deployment 2 verifies it (about 3 s in)
and still lets it expire for the cancellation step (expiry + 1 s grace,
about 16 s), inside the unchanged 30 s wait.

Unchanged: the exact assertion `r.reason === "AUTH_KID_UNKNOWN"`, the DENY,
"still charged" (`BUDGET_EXCEEDED`), CANCELLED by its own domain, ledger 0,
`assertConsistent`, and all production code (`sha256.txt`).

## Results

| Check | Exit | Result | File |
| --- | --- | --- | --- |
| FI-07b alone, run 1-3 | 0, 0, 0 | 1/1 pass each | `fi07b-alone-run{1,2,3}.tap` |
| Typecheck (`npx tsc -p tsconfig.json`) | 0 | clean | `typecheck.log` |
| Full suite (`node --test "tests/**/*.test.ts"`) | 0 | 184 tests, 184 pass, 0 fail, 0 cancelled, 0 skipped, 0 todo (424 s) | `full-suite.tap`, `full-suite.txt` |

`exit-codes.txt` has all exit codes. Earlier evidence in `../final/` is
kept unchanged: `run1-*` (183/184, FI-07b failed) and `test-results.*` /
`fi07b-after-fix.tap` (unchanged test, 183/184).

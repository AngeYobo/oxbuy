# Phase 2C checkpoint

One local commit on `feat/phase-2c-financial-integrity` (base `a2b85c1`),
approved by the owner on 2026-10-28, freezing the Phase 2C source, tests,
documentation, and evidence as a candidate for independent security review.
Readiness stays CONDITIONAL GO FOR INDEPENDENT REVIEW (MOCK ONLY): no
independent audit, no production readiness, no deployment authorization.
The commit was not pushed or merged. Find it with
`git log -1 -- evidence/phase-2c/checkpoint/`.

| File | What |
| --- | --- |
| `source-sha256.txt` | SHA-256 of all 64 `src/` and `tests/` files in the commit, their status against `a2b85c1`, and how each corresponds to the final validation run (see its header) |
| `commit-inventory.txt` | every path in the commit, with `A`/`M` against `a2b85c1`; `force` marks the 37 git-ignored `*.log` evidence files added by explicit path |
| `verify-docs-recheck.txt` | `final/verify-docs.py` re-run against the corrected docs before the commit |

## Two kinds of evidence

- **Current-file integrity.** The hashes in `source-sha256.txt` are those of
  the committed content. Check with
  `grep -v '^#' evidence/phase-2c/checkpoint/source-sha256.txt | awk '{print $1"  "$5}' | sha256sum -c`.
- **Correspondence with the final run** (`fi07b-remediation/full-suite.tap`,
  184/184, 14:20:23 UTC). 31 files are `HASH`: equal to the record taken at
  14:12:03 UTC, before the run. 33 are `MTIME`: no earlier hash exists, and
  only their modification times (all before the run) link them to it. Nothing
  was re-run for the checkpoint; the suite and mutation results are those
  recorded on 2026-10-28.

## Excluded from the commit

`AGENTS.md`, `.agents/`, `.claude/` (owner-maintained, untracked, as in
the Phase 2B commit). `.gitignore`, `LICENSE`, `package.json`,
`package-lock.json`, and `tsconfig.json` are unchanged.

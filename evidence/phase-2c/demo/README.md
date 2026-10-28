# Phase 2C mock demonstration (manual)

2026-10-28. Disposable trust store and state roots, mock payments only.
`setup.txt` names the directories used (under `/tmp`).

| Step | Command | Exit | File |
| --- | --- | --- | --- |
| Seal / approve the working tree into the disposable store | `node src/isolation/trust-cli.ts seal "$PWD"`, `approve <digest>` | 0 | `seal.json`, `approve.json` |
| Provision and initialize state (budget 20000) | `policy-cli.ts provision/init`, `executor-cli.ts provision/init` | 0 | `provision.log` |
| `npm run demo:isolated`, runs 1-3 on the same state | `OXDEAI_TRUST_STORE`, `OXDEAI_POLICY_STATE_ROOT`, `OXDEAI_EXECUTOR_STATE_ROOT` set | 0, 0, 0 | `demo-run{1,2,3}.json` |
| Without `OXDEAI_EXECUTOR_STATE_ROOT` | `npm run demo:isolated` | 2 (BLOCKED) | `demo-blocked-no-executor-state.json` |
| Single-process demo | `npm run demo` | 0 | `demo-inprocess.json` |
| Policy state vs anchor after run 3 | `node src/isolation/policy-cli.ts verify <policyStateRoot>` | 0 | `policy-verify-after-run3.json` |

Results: run 1 ALLOW (ledger 1, charge 10000, reservation CONFIRMED), run 2
ALLOW (ledger 2, charge 20000), run 3 DENY `BUDGET_EXCEEDED` (ledger 2). In
every run `unlisted` is denied `ALLOWLIST_TARGET`, and the agent gets
`EACCES` on the executor socket and the wallet key. `verify`: version 4,
state matches the anchor head, append-only. Exit codes: `exit-codes.txt`.

## Disposable directories

`/tmp/oxdeai-demo-trust-QGgI` and `/tmp/oxdeai-demo-state-as5t` were not
removed by a cleanup step. When they were inventoried for removal
(2026-10-28 14:54 UTC) they no longer existed: the Codespace had restarted
(boot time 14:34:16 UTC) and `/tmp` had been recreated after 14:46. No
`/tmp/oxdeai-*` entry and no demo or service process remained. Nothing was
deleted by the agent. The artifact digest that was approved is in
`seal.json`; the demo can be reproduced with `docs/DEMO.md`.

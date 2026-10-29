# Demo: Phase 1 and Phase 2A/2B/2C (local, mock only)

Everything here runs offline against a mock payment adapter. No wallet is
created or imported, no network request is made, and nothing touches Celo.

## Requirements

- Node.js 22.18 or later (runs `.ts` files directly via type stripping;
  evidence was produced on v24.21.0)
- npm

## Commands

```sh
npm ci                 # install exact versions from package-lock.json
npm run typecheck      # tsc --noEmit
npm test               # 131 tests (includes the Phase 2A / 2A-R / 2B-R3 isolation suites)
npm run demo           # scenario table (single process)
npm run demo:isolated  # Phase 2B: agent, gateway, auth service, executor under four OS accounts
```

Regenerate the evidence files:

```sh
npm run test:evidence                          # evidence/test-results.txt, .tap
node src/demo.ts --json > evidence/demo-output.json
npm run --silent demo:isolated > evidence/demo-isolated-output.json   # needs an approved artifact and initialized policy state
```

`auth_id`, signatures, intent ids, and mock settlement references are random
per run. Decisions and reasons are deterministic.

## Expected demo output

```text
MOCK ONLY: no wallet, no network, no chain.

OK  Authorized payment                   ALLOW executed=true  payments=1
OK  Unauthorized service                 DENY  executed=false payments=0 PDP:ALLOWLIST_TARGET
OK  Unauthorized recipient               DENY  executed=false payments=0 PDP:ALLOWLIST_TARGET
OK  Amount exceeds policy cap            DENY  executed=false payments=0 PDP:PER_ACTION_CAP_EXCEEDED
OK  Body modified after authorization    DENY  executed=false payments=0 INTENT_HASH_MISMATCH
OK  Expired authorization                DENY  executed=false payments=0 AUTH_EXPIRED
OK  Replayed authorization (2nd use)     DENY  executed=false payments=1 AUTH_REPLAY
OK  Invalid signature                    DENY  executed=false payments=0 AUTH_SIGNATURE_INVALID
OK  Policy state unavailable             DENY  executed=false payments=0 PDP:POLICY_STATE_UNAVAILABLE:POLICY_STATE_UNAVAILABLE
OK  Direct executor call, no token       DENY  executed=false payments=0 EXECUTOR_HTTP_403
```

Each scenario uses a fresh system. In the replay row, `payments=1` is the
legitimate first use; the second use is denied and adds no payment.
`PDP:` means the authorization service denied and no artifact was issued.
Other reasons come from the gateway or executor.

The script exits non-zero if any scenario's decision differs from the
expected one.

## Isolated demo (Phase 2B, durable state since 2C)

`npm run demo:isolated` launches only an operator-approved artifact from the
trust store (`$OXDEAI_TRUST_STORE`, default `~/.oxdeai-celo-poc/trust`),
verified before import. If none is approved, it prints
`{"status":"BLOCKED"}` and exits 2. Seal and approve once (see
`docs/ISOLATION.md` §3a):

```sh
node src/isolation/trust-cli.ts seal "$PWD"     # prints the digest and the changes vs the approved artifact
node src/isolation/trust-cli.ts approve <digest> "reviewed"
```

It also needs initialized persistent policy state (Phase 2B-R3). The root
must be reachable by `oxdeai-auth`, so not under your home directory:

```sh
sudo install -d -m 0711 /var/tmp/oxdeai              # operator-owned parent (example)
node src/isolation/policy-cli.ts provision /var/tmp/oxdeai/policy
node src/isolation/policy-cli.ts init /var/tmp/oxdeai/policy 50000   # once; fails if already initialized
export OXDEAI_POLICY_STATE_ROOT=/var/tmp/oxdeai/policy
```

Phase 2C: it also needs an initialized executor state root (payment journal
and mock ledger), reachable by `oxdeai-executor`:

```sh
node src/isolation/executor-cli.ts provision /var/tmp/oxdeai/executor
node src/isolation/executor-cli.ts init /var/tmp/oxdeai/executor     # once; JOURNAL_EXISTS afterwards
export OXDEAI_EXECUTOR_STATE_ROOT=/var/tmp/oxdeai/executor
```

Without either, the demo prints BLOCKED and exits 2. The four dedicated accounts
(`oxdeai-agent`, `-gateway`, `-auth`, `-executor`) must exist. It starts
the auth service (under `flock`), the executor, and the gateway, each as its
own account, from that artifact. The budget persists across runs: once it
is spent, later runs are denied with `BUDGET_EXCEEDED` until the operator
initializes a new policy identity. The runtime directory is deleted when the demo
stops; the policy state (budget, reservations, anchor) and the executor state
(journal, ledger) persist (Phase 2C, docs/FINANCIAL-INTEGRITY.md). It then runs `src/isolation/agent-main.ts`
as the `oxdeai-agent` account through `sudo setpriv --no-new-privs`. This needs
passwordless sudo; without it the demo prints `{"status":"BLOCKED"}` and
exits 2 rather than running everything as one user. The agent:
- buys the weather service: ALLOW, 1 ledger payment, journal SETTLED;
- tries the unlisted service: PDP DENY `ALLOWLIST_TARGET`;
- tries to connect to the executor socket and to read the mock wallet key:
  both `EACCES`.

The output also reports the journal (intents and consumed auth_ids), and the
policy state: version, budget limit, charge, and each reservation's state
(CONFIRMED after a settled payment). Recorded runs with a 20000 budget on the
same state roots (`evidence/phase-2c/demo/`): run 1 and 2 ALLOW (ledger 1, 2;
charge 10000, 20000), run 3 `BUDGET_EXCEEDED` (ledger 2); every run denies
`unlisted` with `ALLOWLIST_TARGET`.

Pids, `auth_id` and `intent_hash` differ per run. See `docs/ISOLATION.md`.

## Mock configuration

Defined in `src/system.ts`:

| Item | Value |
| --- | --- |
| Allowed services | `weather-api` (price 10000), `premium-api` (price 30000), both paying `0x1111…1111` |
| Not allowed | `unlisted-api`, paying `0x2222…2222` |
| Per-action cap | 20000 atomic units |
| Period budget | 50000 atomic units |
| Authorization TTL | 60 s |
| Clock start | `1800000000` (fixed) |
| Network / asset | `mock-celo` / `mock-usdc` (placeholders) |

## Evidence files

| File | Content |
| --- | --- |
| `evidence/test-results.txt` | spec reporter output of the full suite |
| `evidence/test-results.tap` | TAP output of the same run |
| `evidence/demo-output.json` | `node src/demo.ts --json` |
| `evidence/demo-isolated-output.json` | `npm run --silent demo:isolated` (Phase 2B-R3 run, scratch trust store; artifact digest recorded in the file) |
| `evidence/environment.txt` | Node/npm versions, git HEAD, OS identities used, `npm ls`, OxDeAI package integrity hashes |

See `docs/CONFORMANCE.md` for the requirement-to-test mapping and
`docs/ARCHITECTURE.md` and `docs/ISOLATION.md` for trust boundaries and
limitations.

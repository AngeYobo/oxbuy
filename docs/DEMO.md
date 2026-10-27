# Demo: Phase 1 (local, mock only)

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
npm test               # 82 tests
npm run demo           # scenario table
```

Regenerate the evidence files:

```sh
npm run test:evidence                          # evidence/test-results.txt, .tap
node src/demo.ts --json > evidence/demo-output.json
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
| `evidence/environment.txt` | Node/npm versions, git HEAD, `npm ls`, OxDeAI package integrity hashes |

See `docs/CONFORMANCE.md` for the requirement-to-test mapping and
`docs/ARCHITECTURE.md` for trust boundaries and limitations.

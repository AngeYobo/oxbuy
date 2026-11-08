# OxBuy web app

A page judges and users can try in the browser: `node src/web/server.ts` (default port 3000).

## What it serves

| Section | What runs | Network or wallet |
| --- | --- | --- |
| Playground (8 scenarios) | The real OxDeAI authorization service, gateway, executor, journal, x402 EIP-3009 adapter and x402 seller (`src/web/scenarios.ts`, built on `tests/x402/harness.ts`) | None. SimChain and SimFacilitator, a random throwaway key per run |
| Live purchase | `runBuyer`, the same code path as `npm run oxbuy` | Celo Sepolia, or Celo mainnet under the constraints below. OFF unless `OXBUY_LIVE=1` |

Playground scenarios and where each one stops:

| Scenario | Result | Stopped by | Key reads |
| --- | --- | --- | --- |
| Approved purchase | ALLOW, one transfer, nonce bound to the intent | - | 1 |
| Service the operator never approved | DENY `ALLOWLIST_TARGET` | Policy (PDP) | 0 |
| Price above the per-call limit | DENY `PER_ACTION_CAP_EXCEEDED` | Policy (PDP) | 0 |
| Request changed after authorization | DENY `INTENT_HASH_MISMATCH` | Gateway (PEP) | 0 |
| Seller's 402 swaps the payout address | DENY `EXECUTOR_QUOTE_RECIPIENT_MISMATCH` | Executor | 0 |
| Seller raises the price | DENY `EXECUTOR_QUOTE_EXCEEDS_AUTHORIZED_MAX` | Executor | 0 |
| Same authorization used twice | first ALLOW, second DENY `AUTH_REPLAY`, one transfer | Gateway (PEP) | 1 |
| Authorization used after it expired | DENY `AUTH_EXPIRED` | Gateway (PEP) | 0 |

`tests/web/web.test.ts` checks all of the above (W1), the server and its validation (W2), and the live endpoint end
to end against a simulated chain and seller (W3).

## Live purchase limits

Off by default (`OXBUY_LIVE=1` turns it on). `OXBUY_LIVE_NETWORK` selects `testnet` (default) or `mainnet`.

### Testnet (Celo Sepolia)

* `OXBUY_PAYER_KEY` (hex, written to a private 0600 file at start) and the catalog (`OXBUY_CATALOG_JSON`, or
  `OXBUY_CATALOG_FILE`, default `config/usebuy-celo-sepolia.json`).
* `OXBUY_LIVE_MAX_PURCHASES` per server process (default 10), `OXBUY_LIVE_PER_CLIENT` (default 2).

### Mainnet (real money): strong constraints

The server refuses to start unless every one of these holds (`tests/web/web.test.ts` W4):

| Constraint | Why |
| --- | --- |
| `OXBUY_LIVE_NETWORK=mainnet` and `OXDEAI_ENABLE_CELO_MAINNET=I_ACCEPT_REAL_MONEY_RISK` in the process environment | two explicit operator opt-ins, the second one also required by the network code |
| `OXBUY_MAINNET_PAYER_KEY` (a dedicated hot wallet), and `OXBUY_PAYER_KEY` not set | no testnet/mainnet key confusion; a mainnet key without mainnet mode is refused too |
| no `OXBUY_CATALOG_FILE` / `OXBUY_CATALOG_JSON` | the catalog is pinned to `config/usebuy-celo-mainnet.json`, and `runBuyer` pins its profile: one service, recipient `0x20fa…333b`, Celo USDC, 0.005 USDC, one call per run |
| `OXBUY_LIVE_MAX_PURCHASES` set explicitly, 1 to 50 | no default spending cap on mainnet |
| `OXBUY_LIVE_PER_CLIENT` at most 2 (default 1), `OXBUY_LIVE_COOLDOWN_SECONDS` at least 30 (default 60) | rate limits that cannot be loosened by mistake |

At run time (W5): the visitor must tick an explicit confirmation; one purchase at a time and one per cooldown across
all visitors; the wallet's USDC balance is read on chain before each purchase, and a failed read refuses the
purchase (fail closed). A purchase refused before signing gives its allowance back; any other outcome keeps it used,
since money may have moved.

### What these limits do not cover

* The in-memory counters reset when the server restarts (a free Render instance restarts after idling).
  **The durable cap is the wallet balance**: fund the dedicated wallet with only what you accept to spend
  (for example 0.10 USDC is 20 purchases).
* Per-client limits use the right-most `X-Forwarded-For` entry (the one added by the hosting proxy). They slow a
  single visitor down; the global cap, cooldown and balance are what bound the spending.
* Same security limits as the CLI: the live path runs the agent, PDP, gateway, executor and wallet key in one
  process. It is not the process-isolated deployment (`src/isolation/`).

## Deploy on Render

1. Push this branch to GitHub.
2. Render dashboard: New, Blueprint, select the repository (it reads `render.yaml`).
3. The playground works immediately.
4. Testnet live purchases: create a dedicated testnet wallet, fund it with a little Celo Sepolia USDC (EIP-3009
   payments need no CELO for gas), then set `OXBUY_PAYER_KEY`, `OXBUY_CATALOG_JSON` and `OXBUY_LIVE=1`.
5. Mainnet live purchases instead: create a NEW dedicated wallet, register its ERC-8004 identity if it is the
   agent wallet you declare, fund it with a small amount of Celo USDC, then set `OXBUY_LIVE=1`,
   `OXBUY_LIVE_NETWORK=mainnet`, `OXDEAI_ENABLE_CELO_MAINNET=I_ACCEPT_REAL_MONEY_RISK`,
   `OXBUY_MAINNET_PAYER_KEY` and `OXBUY_LIVE_MAX_PURCHASES`; remove `OXBUY_PAYER_KEY` and `OXBUY_CATALOG_JSON`.
   To stop spending at once, set `OXBUY_LIVE=0` (or empty the wallet).
6. The free plan sleeps after inactivity: the first request can take up to a minute.

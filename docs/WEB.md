# OxBuy web app

A page judges and users can try in the browser: `node src/web/server.ts` (default port 3000).

## What it serves

| Section | What runs | Network or wallet |
| --- | --- | --- |
| Playground (8 scenarios) | The real OxDeAI authorization service, gateway, executor, journal, x402 EIP-3009 adapter and x402 seller (`src/web/scenarios.ts`, built on `tests/x402/harness.ts`) | None. SimChain and SimFacilitator, a random throwaway key per run |
| Live purchase | `runBuyer`, the same code path as `npm run oxbuy` | Celo Sepolia, the configured testnet wallet. OFF unless `OXBUY_LIVE=1` |

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

* OFF by default. `OXBUY_LIVE=1` plus `OXBUY_PAYER_KEY` (hex, written to a private 0600 file at start) and the
  catalog (`OXBUY_CATALOG_JSON`, or `OXBUY_CATALOG_FILE`, default `config/usebuy-celo-sepolia.json`).
* `OXBUY_LIVE_MAX_PURCHASES` per server process (default 10), `OXBUY_LIVE_PER_CLIENT` per client IP (default 2),
  one live purchase at a time. A refused purchase does not use the allowance.
* These counters live in memory and reset when the server restarts (a free Render instance restarts after idling).
  **The durable cap is the wallet balance**: use a dedicated demo wallet funded with only what you accept to spend.
* Same security limits as the CLI: the live path runs the agent, PDP, gateway, executor and wallet key in one process.
  It is not the process-isolated deployment (`src/isolation/`). The web app is testnet only and never exposes a mainnet wallet.

## Deploy on Render

1. Push this branch to GitHub.
2. Render dashboard: New, Blueprint, select the repository (it reads `render.yaml`).
3. The playground works immediately. For live purchases: create a dedicated testnet wallet, fund it with a little
   Celo Sepolia USDC (EIP-3009 payments need no CELO for gas), then set `OXBUY_PAYER_KEY`, `OXBUY_CATALOG_JSON`
   (the content of your reviewed catalog) and `OXBUY_LIVE=1`, and redeploy.
4. The free plan sleeps after inactivity: the first request can take up to a minute.

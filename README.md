# OxBuy

**AI agents that buy. You set the rules.**

- **Public demo:** https://oxbuy.onrender.com
- **Source:** https://github.com/AngeYobo/oxbuy
- **Hackathon:** [Agents on Open Rails](https://www.loops.house/agents-on-open-rails/)
- **Track:** Build with buy
- **Status:** Proof of Concept with demonstrated Celo mainnet activity

> **Simulated vs real.** Purchases you run on the public demo are **simulated**: real OxDeAI and x402 code against a
> simulated chain, no funds involved. The Celo mainnet transactions listed below are **historical**, made once by the
> operator from the command line. Live purchasing is **turned off** on the public server (`OXBUY_LIVE=0`).

OxBuy is an AI purchasing agent that discovers and buys paid API services through x402 on Celo, with deterministic
authorization powered by [OxDeAI](https://github.com/oxdeai/oxdeai).

## Try OxBuy

On the public demo you can run eight authorization scenarios against the real code: one approved purchase and seven
attacks. Each run shows every step from the agent's proposal to the chain. The first request can take up to a minute
while the free Render instance wakes up.

1. Open https://oxbuy.onrender.com and go to the **Playground**.
2. Run **Approved purchase**. The agent proposes a purchase of an approved service at the catalog price.
3. Watch the **OxDeAI decision**: `ALLOW`, with a signed `AuthorizationV1` bound to the exact intent hash.
4. Inspect the **simulated x402 payment**. The gateway verifies the authorization, the executor checks the seller's live
   402 against it, and the wallet key is read once to sign one EIP-3009 transfer. Its nonce is derived from the intent,
   and it is mined on the simulated chain.
5. Run **Service the operator never approved**. It is `DENY` at the policy step, before any payment: the key is read
   0 times and nothing is transferred.
6. Explore the other scenarios: price above the per-call limit, request changed after authorization, seller swaps
   the payout address, seller raises the price, same authorization used twice, and authorization used after expiry.
   Every one ends in `DENY` with no transfer.

The playground shows the authorization and payment path. It does not yet return the purchased service's content.
The page's **Make one real purchase** panel reports that live purchases are off on this server.

## Verified Celo Mainnet Evidence

Three separate transactions on Celo mainnet (chain ID 42220). Each was checked on Blockscout, and all three have the
status *success*. They serve different purposes and are listed separately.

**1. ERC-8004 agent identity**

| Field | Value |
|---|---|
| Agent ID | `10057` ([token on Blockscout](https://celo.blockscout.com/token/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432/instance/10057)) |
| Registry | [`0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`](https://celo.blockscout.com/address/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432) (AgentIdentity) |
| Agent wallet | [`0xDDc224cBf39471673F3948385Aa65E967df7C50a`](https://celo.blockscout.com/address/0xDDc224cBf39471673F3948385Aa65E967df7C50a) |
| Agent URI | https://oxbuy.onrender.com/agent-registration.json |
| Registration transaction | [`0x4e4f0628…0f034`](https://celo.blockscout.com/tx/0x4e4f0628c9bba4a57514a4dbfb892a00acb863a3d600d1552290383500d0f034) (`register(agentURI)`, block 82277050) |

**2. ERC-8021 attribution**

| Field | Value |
|---|---|
| Tag | `celo_9d43bf3ecad7` |
| Transaction | [`0xe0643c10…a6279`](https://celo.blockscout.com/tx/0xe0643c105e31e3da62283ff1659ad1252a75a1f85250348059b9eacee4ea6279) (block 82277561) |

This is a zero-value transaction from the agent wallet to itself. Its calldata is the ERC-8021 suffix: the tag
`celo_9d43bf3ecad7`, then a length byte, schema ID `0x00` and the `0x8021…8021` marker. It is not the payment
transaction, and the payment below does not carry the tag.

**3. Historical x402 payment**

| Field | Value |
|---|---|
| Network | Celo mainnet |
| Amount | 0.005 USDC (`5000` atomic units, 6 decimals) |
| Token | [USDC `0xcebA9300f2b948710d2653dD7B07f33A8B32118C`](https://celo.blockscout.com/token/0xcebA9300f2b948710d2653dD7B07f33A8B32118C) |
| Payer → recipient | agent wallet `0xDDc2…C50a` → buy seller [`0x20fa…333B`](https://celo.blockscout.com/address/0x20faAca5F980E29639A0FCC6dcA6988E18ed333B) |
| Transaction | [`0x6c7cb96e…d1b59`](https://celo.blockscout.com/tx/0x6c7cb96e3dd7d92da2ed26374b4c22445b860bd20b69ad28b837be16f1fd1b59) (`transferWithAuthorization`, block 82244163) |

This is a confirmed on-chain settlement: an EIP-3009 `transferWithAuthorization` submitted by the x402 facilitator.
The on-chain `from`, `to`, `value`, `nonce` and `validBefore` match what the OxBuy executor signed after OxDeAI
returned `ALLOW` for the `usebuy-x-posts-search` service. In the same run, a purchase from an unapproved service was
denied (`ALLOWLIST_TARGET`) before any payment. The purchase was made once by the operator with the purchasing CLI.
That path does not have OS-level isolation (see [Verification and Limitations](#verification-and-limitations)).

**Historical testnet evidence (Celo Sepolia)**

| Field | Value |
|---|---|
| Agent ID | `890` |
| Network | Celo Sepolia |
| Wallet | `0xAE1C830076fE626610A9c24C92180bcF97c9e924` |
| Attribution | `celo_9d43bf3ecad7` |

[View registration transaction](https://celo-sepolia.blockscout.com/tx/0x5038b66feabaf883abb07cb57404395de579b6745e9ac0e5f2e41e040973a2e2).
It was registered under the test identity **OxDeAI Guarded Buyer (PoC)**.

## Why OxBuy?

AI agents can access wallets and pay for services, but having payment credentials does not mean having permission to spend.

OxBuy is designed to let users define approved providers, spending limits and payment conditions before an agent can execute purchases.

**The agent chooses what to buy. OxDeAI verifies whether it is authorized.**

## Use Case

A small business asks OxBuy to monitor its brand and competitors.

The agent discovers paid information services, purchases relevant data within an approved budget and produces a concise intelligence brief.

Example:

> Research my competitors, use approved providers only, and spend no more than 1 USDC today.

This is the target product workflow. One mainnet purchase of this kind has been made from the command line (see
above). Live purchasing from the public website is turned off.

## How It Works

```text
User Task + Budget
        |
        v
     OxBuy Agent
        |
        v
  Purchase Request
        |
        v
  OxDeAI Authorization
        |
   +----+----+
   |         |
  DENY      ALLOW
   |         |
 No Payment  v
       Protected Executor
             |
          x402 / buy
             |
         Celo Network
             |
        Paid API Result
```

OxDeAI evaluates the payment authorization before execution. The protected executor must verify that the actual transaction matches the authorized action.

## Security

The integration is designed to enforce:

- Exact payment authorization and provider restrictions
- Spending limits and authorization expiration
- Replay protection and fail-closed behavior
- Payment credential isolation
- Safe handling of uncertain settlement outcomes

Security remediation and independent verification remain in progress. These objectives are not all independently validated.

## Project Status

| Milestone | Status |
|---|---|
| Celo Sepolia integration | Completed |
| ERC-8004 testnet registration (Agent ID `890`) | Completed |
| ERC-8004 mainnet registration (Agent ID `10057`) | Completed |
| ERC-8021 mainnet attribution | Completed |
| Historical mainnet x402 payment (one purchase, 0.005 USDC, operator-run CLI) | Completed |
| Eight-scenario authorization playground (public, simulated) | Completed |
| Interactive autonomous purchase demo (service result returned in the browser) | In progress |
| Public mainnet purchasing | Disabled |
| Independent security verification | Pending |

## Technology

TypeScript, Node.js, OxDeAI, Celo, x402, ERC-8004, ERC-8021 and viem.

## Next Milestones

1. Deploy the interactive autonomous purchase demo, returning the purchased service result.
2. Complete critical authorization and recovery fixes, including F-SIBLING.
3. Complete independent security verification.
4. Deliver a useful result to a real user.
5. Only after the above, consider a controlled public mainnet demonstration.

## Quick Start

**Requirements:** Node.js 22.18+ and npm.

```sh
npm ci
npm run typecheck
npm test
npm run demo
npm run web    # http://localhost:3000
```

The default demo and the web app use **simulated payments**. They need no funded wallet, no private key and no Celo
network access.

### Web app

`npm run web` serves the same site as the public demo. Its eight scenarios (an approved purchase and seven attacks)
run on the real OxDeAI and x402 code against a simulated chain. An optional, capped live purchase is off unless
`OXBUY_LIVE=1`. See [docs/WEB.md](docs/WEB.md) for what is real, the limits, and deployment on Render (`render.yaml`).

### Test Coverage

The default test suite can run without live wallet credentials.

Latest local run (supplied by the developer, not independently reproduced in CI):

- **335 tests discovered**
- **236 passed**
- **0 failed**
- **99 skipped**

The skipped tests include OS-isolation and recovery scenarios requiring dedicated `oxdeai-*` system accounts, plus live Celo Sepolia tests requiring explicit opt-in and testnet credentials.

A successful default test run does not establish that the OS-isolated or live-payment scenarios have passed in the current environment.

See [Isolation](docs/ISOLATION.md) and [Testnet x402](docs/TESTNET-X402.md) for the additional setup requirements.

### Isolated Security Demo

Run `npm run demo:isolated` after completing the setup in [ISOLATION.md](docs/ISOLATION.md).

This demonstration uses separate OS identities and mock payments. It requires an operator-approved artifact and initialized persistent policy and executor state.

### x402 Purchase Demo

The OxBuy purchasing CLI targets Celo Sepolia by default:

```sh
npm run oxbuy -- --catalog <catalog.json> --topic "competitor research" --deny-demo
```

This command requires a configured service catalog and a funded Celo Sepolia test wallet.

The purchasing CLI uses `createGuardedStack()` and does not provide the same OS-level isolation as the isolated security demo.

See [OXBUY.md](docs/OXBUY.md) for configuration and execution instructions.

## Verification and Limitations

- **Public demo:** simulated payments only. It is not production-ready for real payments.
- **Public mainnet purchasing:** disabled on the public server (`OXBUY_LIVE=0`). Mainnet needs further explicit
  operator opt-ins (see [docs/WEB.md](docs/WEB.md)).
- **Public web purchasing controls (P1):** not durable. The purchase counters and rate limits are in memory and reset
  when the server restarts. The only durable cap is the balance of the dedicated wallet.
- **Mainnet activity:** one historical x402 payment of 0.005 USDC, made by the operator with the purchasing CLI.
  It demonstrates the flow. It is not evidence of independent security verification.
- **Credential isolation:** OS-level isolation is not established for all execution paths. The OS-isolated
  demonstration uses mock payments, and equivalent isolation is not established for the purchasing CLI or the web app.
- **Financial integrity:** F-SIBLING remains an unresolved risk.
- **Independent security verification:** Incomplete.

See [F-SIBLING Assessment](docs/F-SIBLING-ASSESSMENT.md) and [Conformance](docs/CONFORMANCE.md).

## Built with OxDeAI

OxBuy is an application built on top of OxDeAI's deterministic authorization protocol.

**OxBuy handles purchasing. OxDeAI enforces authorization.**

Protocol: https://github.com/oxdeai/oxdeai

## License

MIT, subject to the included LICENSE file.

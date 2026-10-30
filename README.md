# OxBuy

**AI agents that buy. You set the rules.**

OxBuy is an AI purchasing agent that discovers and buys paid API services through x402 on Celo, with deterministic authorization powered by [OxDeAI](https://github.com/oxdeai/oxdeai).

**Website:** oxbuy.ai (planned)
**Hackathon:** [Agents on Open Rails](https://www.loops.house/agents-on-open-rails/)
**Track:** Build with buy
**Status:** Proof of Concept

## Why OxBuy?

AI agents can access wallets and pay for services, but having payment credentials does not mean having permission to spend.

OxBuy is designed to let users define approved providers, spending limits and payment conditions before an agent can execute purchases.

**The agent chooses what to buy. OxDeAI verifies whether it is authorized.**

## Use Case

A small business asks OxBuy to monitor its brand and competitors.

The agent discovers paid information services, purchases relevant data within an approved budget and produces a concise intelligence brief.

Example:

> Research my competitors, use approved providers only, and spend no more than 1 USDC today.

This is the target product workflow. Live third-party x402 purchasing remains under development.

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

## Celo Integration

OxBuy uses x402 for paid API access and ERC-8004 for agent identity.

**ERC-8004 registration completed on Celo Sepolia:**

| Field | Value |
|---|---|
| Agent ID | `890` |
| Network | Celo Sepolia |
| Wallet | `0xAE1C830076fE626610A9c24C92180bcF97c9e924` |
| Attribution | `celo_9d43bf3ecad7` |

[View registration transaction](https://celo-sepolia.blockscout.com/tx/0x5038b66feabaf883abb07cb57404395de579b6745e9ac0e5f2e41e040973a2e2)

The registration was completed under the test identity **OxDeAI Guarded Buyer (PoC)**. This does not yet demonstrate an end-to-end x402 purchase.

## Project Status

| Milestone | Status |
|---|---|
| Celo Sepolia integration | Completed |
| ERC-8004 testnet registration | Completed |
| OxDeAI payment authorization PoC | Implemented, under review |
| Independent security verification | Pending |
| Live x402 service purchase | Pending |
| User-facing intelligence brief | Planned |
| Mainnet demonstration | Pending |

## Technology

TypeScript, Node.js, OxDeAI, Celo, x402, ERC-8004, ERC-8021 and viem.

## Next Milestones

1. Integrate a verified paid service from the buy ecosystem.
2. Complete critical authorization and recovery fixes.
3. Demonstrate an authorized purchase and a blocked purchase.
4. Deliver a useful result to a real user.
5. Prepare a controlled mainnet demonstration.

## Built with OxDeAI

OxBuy is an application built on top of OxDeAI's deterministic authorization protocol.

**OxBuy handles purchasing. OxDeAI enforces authorization.**

Protocol: https://github.com/oxdeai/oxdeai

## License

MIT, subject to the included LICENSE file.

# OxDeAI x402 Authorization Gateway

**Pre-execution authorization for AI-agent payments on Celo.**

A proof-of-concept project exploring how OxDeAI can enforce deterministic authorization decisions before AI agents execute paid API requests through x402 and Celo.

**Hackathon:** Agents on Open Rails  
**Target track:** Build with buy  
**Status:** Proof of Concept (Integration feasibility under evaluation)

## The Problem

AI agents can increasingly discover services, call paid APIs, and initiate payments autonomously.

However, access to a wallet or valid payment credentials does not necessarily mean that an agent is authorized to perform a specific transaction.

A spending limit alone does not establish whether a particular payment is permitted under the current policy, context, and execution state.

## Our Approach

OxDeAI provides a deterministic pre-execution authorization layer designed to evaluate specific agent actions before they reach protected execution systems.

This PoC aims to integrate that authorization layer with Celo's agentic payment ecosystem.

The proposed flow is:

1. An AI agent requests a paid API service.
2. OxDeAI evaluates the proposed action against authorization policy and relevant state.
3. A Policy Enforcement Point (PEP) verifies the authorization before payment execution.
4. An isolated payment executor initiates the approved x402 payment through the supported integration.
5. Unauthorized, expired, replayed, or modified requests are rejected.

The integration must prevent agents from bypassing the enforcement point and accessing payment credentials directly.

## Proposed Architecture

```text
AI Agent
   |
   v
Payment Request
   |
   v
OxDeAI Authorization Layer
   |
   +-- Policy Decision Point (PDP)
   |
   +-- Signed Authorization
   |
   v
Policy Enforcement Point (PEP)
   |
   +-- DENY --> No payment
   |
   +-- ALLOW --> Controlled Payment Executor
                         |
                         v
                    buy / x402
                         |
                         v
                    Celo Network
```

## Security Objectives

The PoC will evaluate:

- Deterministic authorization before execution
- Binding authorization to the specific payment action
- Verification of service, recipient, amount, and relevant policy constraints
- Expiration and replay protection
- Fail-closed behavior when authorization cannot be verified
- Isolation of wallet credentials from the AI agent
- Prevention of direct payment paths that bypass the PEP

## Demonstration Goals

The intended demonstration includes:

| Scenario | Expected result |
| --- | --- |
| Authorized payment | ALLOW, followed by payment execution |
| Unauthorized payment | DENY, no payment |
| Payment exceeds policy limit | DENY |
| Expired authorization | DENY |
| Replayed authorization | DENY |
| Modified payment parameters | DENY |
| Attempted PEP bypass | Blocked by the execution architecture |

These are target acceptance criteria, not claims of completed implementation.

## Technology

- **OxDeAI:** Deterministic authorization protocol
- **Celo:** Blockchain payment network
- **x402:** HTTP payment protocol
- **buy:** Target integration for paid API services
- **TypeScript / Node.js:** Proposed implementation environment

## Project Status

This repository is a hackathon-specific integration project.

The first milestone is to verify whether the payment execution path can be reliably gated by OxDeAI before signing or settlement.

Implementation and mainnet demonstrations will follow only if that enforcement boundary is technically feasible.

## Relationship to OxDeAI

This project is an independent integration PoC.

The OxDeAI core protocol is maintained separately:

<https://github.com/oxdeai/oxdeai/>

## Hackathon

Agents on Open Rails, Celo ecosystem

<https://www.loops.house/agents-on-open-rails/>

## License

MIT, subject to the repository's included LICENSE file.

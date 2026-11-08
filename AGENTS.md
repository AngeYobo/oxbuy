# OxBuy: Agent Development Instructions

## Project Mission

Build an independently verifiable proof of concept integrating OxDeAI pre-execution authorization with paid x402 services on Celo.

Target hackathon: Agents on Open Rails.

Proposed track: Build with buy.

## Core Security Principles

1. OxDeAI authorization must occur before any protected payment execution.
2. The AI agent must not have direct access to payment signing credentials.
3. Every authorized payment must be bound to its exact action, recipient, service, amount, and relevant execution context.
4. Missing, invalid, expired, replayed, or mismatched authorization must result in DENY.
5. A valid API key, wallet credential, or payment capability is not equivalent to authorization.
6. The PEP must be positioned at an enforceable execution boundary, not merely used for logging or monitoring.
7. No payment execution path may bypass the PEP within the defined trust boundary.
8. Do not claim non-bypassability without evidence from architecture review and adversarial tests.

## Integration Requirements

- Inspect the actual buy and x402 payment execution flow before implementation.
- Identify the point where payment parameters become final.
- Verify whether authorization can be enforced before signing or settlement.
- Keep wallet signing isolated from the agent.
- Reuse the existing OxDeAI protocol where appropriate.
- Do not modify OxDeAI core protocol semantics without explicit approval.
- Document any integration limitation or unsupported security guarantee.

## Hackathon Requirements

- Follow the official Loops House skill for event requirements.
- Celo mainnet is disabled by default. Do not enable mainnet or execute real-money transactions without explicit operator approval, a documented security review, and resolution or explicit acceptance of all applicable blocking risks.
- Obtain the official project attribution tag before eligible mainnet transactions.
- Verify the compatibility of attribution tagging with the selected x402 payment flow.
- Register the agent's ERC-8004 identity as required.
- Never expose private keys, seed phrases, or production credentials.
- Never submit or update the hackathon entry without explicit approval.

## Validation

Implement automated tests covering:

- Valid authorization
- Policy denial
- Spending limit violation
- Expired authorization
- Replay attempt
- Modified payment parameters
- Invalid signature
- Missing policy state
- Attempted direct payment bypass
- Authorization failure before any payment signing

Report PASS, FAIL, or NOT_TESTED for each applicable requirement.

## Engineering Workflow

1. Inspect documentation and existing code.
2. Produce a feasibility report before implementation.
3. Define architecture and trust boundaries.
4. Propose the minimal PoC scope.
5. Request approval before implementing.
6. Implement and test the approved scope.
7. Provide reproducible evidence.
8. Prepare a submission draft for approval.

## Constraints

- Keep this PoC independent from the main OxDeAI repository.
- Do not introduce unnecessary protocol changes.
- Do not commit secrets or wallet private keys.
- Do not execute real-money transactions without explicit approval.
- Do not make unsupported security or interoperability claims.
- Prefer precise technical evidence over marketing claims.

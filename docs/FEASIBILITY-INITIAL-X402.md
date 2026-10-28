# OxDeAI x402 Authorization Gateway feasibility for Build with Buy

## Scope and method

This report is intentionally limited to the sponsor-specific Build with Buy / BuyWhere integration path and the generic x402 payment execution path that could be used underneath it.

We did not find an official sponsor package or payment SDK for the Build with Buy challenge in the public repo or package metadata inspected. The sponsor challenge materially appears to be an MCP commerce integration, not a wallet / x402 payment SDK:

- BuyWhere challenge repo: https://github.com/BuyWhere/challenge-build-with-buywhere/blob/main/README.md
- BuyWhere MCP example repo: https://github.com/BuyWhere/buywhere-mcp-example-v2/blob/main/README.md
- BuyWhere MCP endpoint: https://api.buywhere.ai/mcp
- BuyWhere auth registration: https://api.buywhere.ai/v1/auth/register

This means the sponsor-specific integration is currently marked as NOT_TESTED for payment execution unless the sponsor publishes the actual payment/settlement SDK and API contract.

## Findings summary

| Status | Finding |
|---|---|
| VERIFIED | BuyWhere sponsor challenge is an MCP commerce integration using `search_products_v2` / `get_product_v2` and requires `deliver_to`. |
| VERIFIED | The public x402 protocol flow is an HTTP 402 client-signs-verifier-settles lifecycle. |
| VERIFIED | The client wallet private keys are modeled as client-side credentials in the x402 E2E docs. |
| VERIFIED | x402 does not define an ERC-8021 attribution tag in the protocol contract docs inspected. |
| INFERRED | A custom OxDeAI policy enforcement point can gate a wallet-signed payment before execution if the wallet boundary is trusted and isolated. |
| BLOCKED | Sponsor-specific BuyWithBuy payment SDK / wallet / facilitator contract is not verified in public docs. |
| NOT_TESTED | Loops project attribution and the exact meaning of `celo_9d43bf3ecad7` under the sponsor rules remain unverified. |

## 1) Sponsor-specific Build with Buy evidence

### 1.1 Sponsor challenge is not a payment SDK

The public challenge repo states that it is a Build With BuyWhere AI agent challenge and that the agent uses BuyWhere MCP. It specifies the required tools and API access, but it does not define an x402 payment SDK or wallet payment flow.

Source:
- https://github.com/BuyWhere/challenge-build-with-buywhere/blob/main/README.md#L1-L48

Important lines:
- “Build an AI agent that uses BuyWhere MCP to search, compare, find best prices, or recommend products.”
- “Add this to your `claude_desktop_config.json` or MCP client config” with `"url": "https://api.buywhere.ai/mcp"` and `"BUYWHERE_API_KEY"`.

This is a commerce MCP integration, not a payment execution endpoint.

### 1.2 Actual sponsor example is a product-search MCP client, not a wallet API

The example repo says it is a minimal Node client for BuyWhere v2 `search_products_v2` with required `deliver_to` parameter. It also lists the endpoint and auth flow. No payment package, wallet client, x402 endpoint, facilitator, or transaction signing API is included.

Source:
- https://github.com/BuyWhere/buywhere-mcp-example-v2/blob/main/README.md#L1-L59
- https://github.com/BuyWhere/buywhere-mcp-example-v2/blob/main/README.md#L61-L94

Relevant snippet:
- MCP server: `https://api.buywhere.ai/mcp`
- Docs: `https://buywhere.ai/docs/guides/mcp`
- Free key registration: `https://api.buywhere.ai/v1/auth/register`
- `search_products_v2 requires deliver_to` and `deliver_to` is required for v2 tools.

### 1.3 Package metadata does not expose a sponsor payment SDK or wallet SDK

The example package metadata confirms a tiny Node 18 client with zero runtime dependencies and a minimal `start` script.

Source:
- https://github.com/BuyWhere/buywhere-mcp-example-v2/blob/main/package.json#L1-L40

It has:
- `name: "buywhere-mcp-example-v2"`
- `dependencies: {}`
- `optionalDependencies: { "@modelcontextprotocol/sdk": "^1.30.0" }`
- no wallet / payment / facilitator package

### 1.4 Status for sponsor-specific integration

Conclusion: the public sponsor documentation supports only MCP product discovery and recommendation. It does not document a sponsor-specific x402 payment, authorization, or payment facilitator SDK. Therefore:

- Build with Buy sponsor payment API: NOT_TESTED
- Sponsor x402 SDK / wallet package / API version: NOT_TESTED
- Sponsor-specific authorized settlement flow: NOT_TESTED

## 2) Real x402 payment execution lifecycle (verified)

The official x402 documentation and E2E harness describe the actual payment execution model used by x402. These are the primary sources we used.

### 2.1 x402 protocol flow

Source:
- https://github.com/x402-foundation/x402/blob/main/README.md#L122-L151

Relevant flow:
1. Client makes an HTTP request.
2. Resource server responds with `402 Payment Required` and a `PAYMENT-REQUIRED` header containing a base64 payment object.
3. Client selects one `PaymentRequirements` entry.
4. Client creates a `PaymentPayload` based on the selected `scheme` + `network`.
5. Client submits the request with `PAYMENT-SIGNATURE`.
6. Server verifies the payload through local verification or a facilitator `/verify` call.
7. If valid, the server serves the request.
8. The payment is settled either directly or via a facilitator `/settle` call.
9. A `PAYMENT-RESPONSE` header returns settlement status.

### 2.2 x402 scheme and requirement selection

Source:
- https://github.com/x402-foundation/x402/blob/main/README.md#L7-L18
- https://github.com/x402-foundation/x402/blob/main/README.md#L153-L168

The protocol is designed so the client receives the `PaymentRequirements` and chooses one of the accepted `scheme` / `network` combinations. It is not a fixed one-size-fits-all payment object.

### 2.3 Wallet key ownership in the x402 E2E docs

Source:
- https://github.com/x402-foundation/x402/blob/main/e2e/README.md#L197-L251

This file clearly distinguishes:
- `CLIENT_*` keys as payer-side wallet credentials
- `FACILITATOR_*` keys as the verification / settlement side

For example:
- `CLIENT_EVM_PRIVATE_KEY`
- `FACILITATOR_EVM_PRIVATE_KEY`

This shows the wallet credentials are the client-side payer credentials, not the server-side resource server or protocol layer.

### 2.4 x402 EVM settlement guardrails

Source:
- https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md#L7-L20
- https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md#L337-L378

The EVM contract docs state that:
- the contracts are witness-bound
- facilitators cannot redirect funds
- the destination is locked by witness pattern
- the protocol is designed to be trust-minimizing

## 3) Mandatory authorization boundary analysis

### 3.1 Required properties for a safe pre-signing authorization system

The design question is whether OxDeAI can enforce a mandatory pre-signing authorization boundary for an untrusted AI agent and a trusted payment executor.

This is a valid architecture if the system enforces the following:

- The AI agent does not have direct access to wallet credentials.
- A separate trusted payment executor holds the signer or signs on its behalf under explicit policy.
- A policy evaluation point (PEP) validates the exact recipient, network, asset, amount, service and request before signing.
- Fail-closed behavior prevents signing or forwarding when authorization fails.
- The exact payment requirement is presented to the payer before signing, not silently altered.

### 3.2 Verified x402 behavior relevant to this design

The x402 protocol is compatible with this boundary because the protocol explicitly exposes the payment requirement to the client and makes the client create the signed payload.

- Payment requirement selection happens before the signed payload is created:
  - https://github.com/x402-foundation/x402/blob/main/README.md#L129-L145
- Client-side signers are explicitly modeled in the E2E docs:
  - https://github.com/x402-foundation/x402/blob/main/e2e/README.md#L197-L251

This means a trusted payment executor can be the component that receives the requirement and decides to sign, as long as it does so as the client-side signer in the x402 model.

### 3.3 Inference: OxDeAI can enforce these controls as a policy boundary

INFERRED, not protocol-required:

- A custom OxDeAI PEP can validate the exact target recipient, chain/network, asset, amount, service identifier, and request context before signing.
- A fail-closed policy engine can reject signing when any field mismatches the authorize decision.
- The agent can remain untrusted while the trusted signer stays isolated and limited to the exact approved payment parameters.

This is an application security architecture, not an x402 requirement.

### 3.4 Important caveat: no sponsor payment API is verified

The sponsor-specific Build with Buy path does not publish an x402 payment API, SDK version, or facilitator contract in public docs. That means the actual policy/authorization boundary for the sponsor flow is not verified. The generic pattern is valid, but the sponsor implementation remains BLOCKED until the sponsor publishes the real SDK / API contract.

### 3.5 Decision for authorization boundary

- For generic x402: CONDITIONAL GO, assuming the trusted wallet boundary is isolated and fail-closed.
- For the sponsor-specific Build with Buy flow: BLOCKED / NOT_TESTED because no sponsor payment API or wallet contract is publicly verified.

## 4) ERC-8021 attribution analysis and Loops interpretation

This part is separate from x402 payment authorization.

### 4.1 x402 does not define a built-in ERC-8021 tag

We inspected the official x402 docs and contract docs and found no ERC-8021 attribution field or tag in the defined payment flow.

- https://github.com/x402-foundation/x402/blob/main/README.md#L122-L151
- https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md#L7-L20
- https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md#L337-L378

There is no supported field equivalent to `celo_9d43bf3ecad7` in the inspected x402 payment execution lifecycle. This is a VERIFIED finding.

### 4.2 Facilitator-submitted transactions

A facilitator can verify and settle on behalf of the client, but that does not erase the distinction between:

- the wallet that signed the payment intent; and
- the wallet or relayer that submitted the transaction.

The EVM contract docs state that the facilitator cannot redirect funds and the payment is witness-bound. That preserves the client’s payment intent, but it does not guarantee that a third-party rule engine will count the attribution based on the witness-owner wallet rather than the tx sender.

Source:
- https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md#L7-L20
- https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md#L337-L378

### 4.3 Loops / attribution rule basis remains unverified

We did not find public sponsor or Loops documentation in the inspected repositories that says whether Loops counts:

- payer wallet from the signed payment witness,
- transaction sender address,
- another verified relationship,
- or a metadata tag outside the x402 protocol.

This part is therefore NOT_TESTED / not verified from public docs.

### 4.4 Conclusion for attribution

- x402 payment authorization and ERC-8021 attribution are distinct concerns.
- x402 can authorize a payment without carrying a built-in `celo_9d43bf3ecad7` tag.
- Whether Loops attributes the payment to the agent wallet, tx sender, or another verified relationship is a separate rule system and remains NOT_TESTED.

## 5) Evidence classification

### VERIFIED

- BuyWhere challenge uses MCP commerce endpoints and `deliver_to`-required product search tools:
  - https://github.com/BuyWhere/challenge-build-with-buywhere/blob/main/README.md#L1-L48
  - https://github.com/BuyWhere/buywhere-mcp-example-v2/blob/main/README.md#L1-L59
- x402 payment lifecycle is HTTP 402 -> select requirement -> sign -> verify -> settle -> response:
  - https://github.com/x402-foundation/x402/blob/main/README.md#L122-L151
- client keys are client-side in x402 E2E docs:
  - https://github.com/x402-foundation/x402/blob/main/e2e/README.md#L197-L251
- x402 settlement contracts are witness-bound and prevent facilitator fund redirection:
  - https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md#L7-L20
  - https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md#L337-L378
- x402 does not define an ERC-8021 attribution tag in the inspected protocol sources.

### INFERRED

- A custom OxDeAI gateway may enforce policy checks before signing if the wallet signer is isolated and fail-closed.
- This is a security architecture pattern that is compatible with the x402 model but not protocol-mandated.

### BLOCKED

- Sponsor-specific Build with Buy payment SDK / wallet API / settlement flow is not verified in the public sponsor docs.
- An actual x402 payment execution path for the sponsor cannot be confirmed from the public repo alone.

### NOT_TESTED

- Any sponsor-specific or Loops-specific attribution semantics for `celo_9d43bf3ecad7`.
- Whether Loops counts payments by payer wallet, transaction sender, or another verified relationship.
- Whether a sponsor SDK exists behind private APIs not public to this repo.

## 6) Decision

### Decision: CONDITIONAL GO (generic x402 architecture only)

A generic x402-style authorization gateway can be designed as a valid architecture when all of the following are true:

1. The AI agent has no direct wallet credentials.
2. A separate trusted payment executor owns the signing keys.
3. A fail-closed PEP validates the exact recipient, network, asset, amount, service and request before signing.
4. The wallet signer only signs an exact approved payment requirement and nothing else.
5. The sponsor or challenge rules accept the payment witness / approved payer relationship, not only the transaction sender address.
6. The sponsor-specific Build with Buy API is publicly documented and verified before deployment.

### Blocking conditions

The project is NOT GO if any of the following are true:

- the sponsor’s actual payment API / SDK is not published or verified;
- the wallet credentials are reachable from the untrusted AI agent;
- the PEP cannot evaluate the exact recipient, network, asset, amount, service and request before signing;
- the architecture relies on a signer that is not fail-closed;
- the challenge requires tx-sender attribution only and does not accept witness-owner or verified payment authorization;
- the sponsor requires a specific ERC-8021 or Loops attribution mechanism that is not published and verified.

### Sponsor-specific result

Given the public evidence reviewed, the sponsor-specific Build with Buy integration remains NOT_TESTED and is therefore not eligible for a definitive sponsor-specific GO decision. The only defensible decision is: CONDITIONAL GO for a generic x402 security architecture, but BLOCKED for sponsor-specific Build with Buy payment execution until the sponsor publishes the actual SDK / wallet / settlement contract and attribution rules.

## 7) Implementation boundary we would accept

This report is not a code implementation. It is a design boundary only.

The acceptable design is:

- AI agent: untrusted, no wallet credentials
- PEP: authorized decision engine on exact payment parameters
- Payment executor: trusted signer / wallet boundary
- x402 verifier / facilitator: verify signed payload and submit settlement
- no OxDeAI core change required for a thin integration layer

This boundary is compatible with the x402 docs but is not equivalent to a verified sponsor integration.

## 8) Final conclusion

The public sponsor challenge and the generic x402 protocol are not the same thing. The sponsor challenge documentation is an MCP commerce integration with `deliver_to`-bound product search and no verified wallet or payment API. The x402 protocol itself is a real, documented, client-signed HTTP-402 payment flow, but it does not define the sponsor-specific Build with Buy API, does not define a built-in ERC-8021 attribution tag, and does not answer whether Loops attributes to the payer wallet or transaction sender.

Therefore:

- Generic x402 authorization boundary: CONDITIONAL GO
- Sponsor-specific Build with Buy payment flow: BLOCKED / NOT_TESTED
- ERC-8021 attribution and Loops counting logic: NOT_TESTED
- Final project decision before sponsor docs are published: NO definitive sponsor approval; proceed only as an architecture prototype, not as a production payment claim.

This is the evidence-based position that matches the actual public sources inspected.

## Reference URLs

- Build with BuyWhere challenge: https://github.com/BuyWhere/challenge-build-with-buywhere/blob/main/README.md
- Build with BuyWhere MCP example: https://github.com/BuyWhere/buywhere-mcp-example-v2/blob/main/README.md
- BuyWhere MCP endpoint: https://api.buywhere.ai/mcp
- BuyWhere auth: https://api.buywhere.ai/v1/auth/register
- x402 README: https://github.com/x402-foundation/x402/blob/main/README.md
- x402 E2E docs: https://github.com/x402-foundation/x402/blob/main/e2e/README.md
- x402 EVM contracts: https://github.com/x402-foundation/x402/blob/main/contracts/evm/README.md

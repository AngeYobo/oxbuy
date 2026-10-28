# Feasibility: OxDeAI pre-execution authorization for `@celo/buy`

Target: Loops House "Agents on Open Rails", bounty "Build with buy".
Sponsor integration: `@celo/buy` (CLI and MCP server), documented in
`celo-org/buy-skill`. Earlier drafts analyzed a different product (BuyWhere
MCP); that analysis does not apply to this bounty and has been removed.

## Evidence labels

- **VERIFIED**: stated in a source listed below, at the cited lines.
  Documentation only: not observed in a running system.
- **INFERRED**: an architectural conclusion drawn from VERIFIED facts. Not
  demonstrated.
- **NOT_TESTED**: requires running real `@celo/buy`, a wallet, or a payment.
  Not executed.
- **BLOCKED**: a prerequisite that is unresolved and outside this
  repository's control.

No `@celo/buy` command was run for this report. No wallet was created or
imported and no payment was made.

## Sources inspected

Inspected 2026-10-27.

- `celo-org/buy-skill` repository at commit
  `20329cef3965f17af4367dd432581079a9cf05a6` (2026-10-23):
  - `README.md` (105 lines)
  - `skills/use-api-gateway/SKILL.md` (284 lines)
  - `skills/order-compute/SKILL.md` (601 lines)
  - `skills/file-feedback/SKILL.md` (336 lines)
  - `.github/ISSUE_TEMPLATE/list-your-service.yml`
- npm registry metadata for `@celo/buy` (`npm view`, no install): `latest` =
  `0.8.4`; versions 0.6.0 … 0.8.4; `bin: buy`; no `repository` field.
- Loops event skill in this repo,
  `.agents/skills/loops-agents-on-open-rails/SKILL.md` (identical copy in
  `.claude/skills/`).

Line references below use `README`, `GW` (use-api-gateway), `OC`
(order-compute), `FB` (file-feedback) and `LOOPS` (the Loops skill).
Permalink base:
`https://github.com/celo-org/buy-skill/blob/20329cef3965f17af4367dd432581079a9cf05a6/`.

Not inspected: the `@celo/buy` source code (the repository above contains
skills, not the CLI; the npm package lists no source repository), the
gateway implementation, and the facilitator.

## 1. What `@celo/buy` is (VERIFIED)

- An x402 payment client for Celo that lets a CLI or AI agent pay for HTTP
  APIs in stablecoins (README L3).
- MCP tools: `buy_pay_quote`, `buy_curl`, `buy_balance`, `buy_whoami`,
  `buy_verify_status` (README L37-38), plus `buy_discover` (GW L32-44).
- Setup creates a wallet in the OS keychain: `npx --yes @celo/buy@0.8.4
  setup --name <name>` (README L41, OC L145-148). Documentation pins
  `0.8.4` throughout; the gateway skill requires 0.8.4 or newer (GW L14).
- "The server signs with the keychain wallet in its own process; the agent
  never receives key material." (README L45-46, OC L185-186)
- The CLI does everything the MCP tools do; MCP is optional (README L48-49,
  OC L177-178).
- Gateways: `https://gateway.usebuy.ai` for APIs (GW L8-10) and
  `https://usebuy.ai/google/vm` for compute (OC L11-13). Upstream provider
  credentials stay on the gateway (GW L9, GW L22-23).
- Settlement is real USDC, USDT, or USAT on Celo mainnet, irreversible, with
  no refund primitive in x402 (README L56, L61-64; OC L15). There is no
  testnet deployment (OC L44-47).

## 2. Payment execution flow (VERIFIED)

1. Discover the capability (`buy_discover` or the free `GET /v1/catalog`)
   (GW L30-75).
2. Quote the exact method, URL, headers, and body without paying:
   - MCP `buy_pay_quote` with `url`, `method`, optional `headers`, and `body`
     as a raw JSON string (GW L173-181, OC L239-248);
   - CLI `buy quote …` or an unpaid `curl` (GW L160-166, OC L304-322).
   `buy_pay_quote` "is read-only and does not sign or pay" (GW L185-186,
   OC L251-252). `buy quote` "needs no wallet and never signs" (OC L307).
3. Read the price: `price.atomic` / `price.token` from the MCP quote, which
   is the selected requirement's `maxAmountRequired` from the raw 402
   (GW L183-185, OC L250-251). The 402 challenge is the price authority;
   catalog prices are indicative (GW L28, OC L75-76).
4. Obtain approval for the exact token and maximum "unless the user's
   request already authorizes that spend" (GW L20-21, OC L42-43, L252-253).
5. Pay by repeating the identical request:
   - MCP `buy_curl` with the same `url`, `method`, `headers`, `body`, and
     `maxAmount` (GW L189-197, OC L255-264);
   - CLI `buy curl --max-amount <amount> …` (GW L215-223, OC L271-286).
6. The response carries the transaction hash and result; never retry
   ambiguous outcomes (`500 settle_uncertain`, network loss after sending)
   (GW L263-280, OC L540-567).

### Point where payment parameters become final

The paid call in step 5 is where method, URL, headers, body, token, and
`maxAmount` are fixed and the wallet signs. A pre-execution authorization
gate must sit **before** `buy_curl` / `buy curl` is invoked. Quoting (step 2)
does not need to be gated for funds safety because it never signs.
(INFERRED from the facts above.)

### Amount units differ by interface (VERIFIED, security-relevant)

- MCP `maxAmount`, `price.atomic`, and the raw 402 `maxAmountRequired` are
  **atomic** units (GW L199, OC L266, OC L290-291).
- CLI `--max-amount` is a **decimal token amount** (GW L225, OC L290). The
  docs warn that `--max-amount 16753` "would authorize 16,753 USDC"
  (OC L292-293).

A PEP that authorizes an atomic amount must convert it exactly when it
drives the CLI. A unit error here turns a cent into thousands of dollars.

### Controls that `@celo/buy` itself provides (VERIFIED)

- A daily spend cap per account, in whole stablecoin units, across all
  stablecoins: `buy account cap <name> 1.00` (OC L156-168). A cap refusal is
  "refused client-side before signing" (FB L147).
- A client-side balance check before signing (OC L545; FB L147).
- `no_matching_requirements` when the account's network does not match;
  nothing is signed (OC L555).

What `@celo/buy` does **not** provide, per its own docs:

- Per-payment approval. "Nothing prompts per payment." (README L74) The
  approval step in the skills is guidance to the agent, and it is waived
  when "the user's request already authorizes that spend" (GW L20-21).
- Any binding of a payment to a specific approved request, recipient, or
  service beyond what the agent chooses to pass to `buy_curl`.

This is the gap OxDeAI addresses: buy limits *how much* per day; it does not
decide *whether this specific payment* is authorized. (INFERRED)

### Settlement transaction (VERIFIED)

- The gateway's sponsor wallet pays gas for x402 settlements (README
  L56-58, OC L153-154).
- "The facilitator broadcasts the settlement, so it never appears in the
  payer's Transactions list"; the payment appears only as a token transfer
  from the payer to the gateway's `payTo` (OC L587-592).
- The `usebuy.ai` gateway returns `"x402Version": 1`; Celo's public
  facilitator and `@x402/express` issue version 2 (OC L298-302).

## 3. Trust boundary and enforceability

### Trust boundary: VERIFIED

- The signing key lives in the OS keychain, and the MCP server or CLI signs
  in its own process (README L45-46).
- The documented MCP registration launches the server through the agent
  client: `claude mcp add -s user buy -- npx --yes @celo/buy@0.8.4 mcp serve`
  (README L53, OC L191).

### Trust boundary: INFERRED

- "The agent never receives key material" is not the same as "the agent
  cannot pay". Any process that can call `buy_curl` or run `buy curl` with
  the same OS user and keychain can make payments up to the daily cap.
- In the documented default setup the MCP server is started by the agent's
  MCP client under the same OS user. An agent with shell access in that user
  context can therefore run `buy curl` directly. This is a bypass of any PEP
  that sits only in front of the MCP tools.
- OxDeAI can be a mandatory pre-execution gate only if:
  1. the agent is not given the `buy_curl` tool, the `buy` CLI, or the
     keychain;
  2. the buy process (MCP server or CLI) runs as a separate OS user or
     sandbox that the agent cannot execute as or read from;
  3. the only caller of that process is a trusted executor that runs after
     OxDeAI verification;
  4. the executor passes exactly the authorized method, URL, headers, body,
     token, and `maxAmount`, converting units correctly for the CLI.
- The buy daily cap remains useful as a second, independent ceiling.

### Bypass paths that must be closed

- **Agent has `buy_curl` in its MCP tool list**: pays any request without
  OxDeAI.
- **Agent can run `buy` / `npx @celo/buy` as the wallet's OS user**: same
  keychain wallet, same signing path.
- **Agent can read the keychain entry, or run `setup --import`**: holds or
  replaces the key.
- **Executor forwards fields the agent can change after authorization**:
  pays for a different request than the one authorized.
- **CLI used with an atomic value passed to `--max-amount`**: ceiling raised
  by 10^6.

### Generic x402 binding (INFERRED, independent of buy)

Because the 402 price depends on the request body (README L67-68, OC L41),
an authorization must bind the exact method, URL, headers, and body, plus
network, token, recipient (`payTo`), and maximum amount. Retries are new
payments (OC L561-567), so each authorization should be single-use; this
matches OxDeAI's `auth_id` replay consumption.

## 4. ERC-8021 attribution and Loops rules

### Attribution: VERIFIED (Loops skill in this repository)

- A transaction is credited only if "its calldata carries the entry's
  ERC-8021 attribution tag", and untagged transactions are never credited
  (LOOPS L239).
- The tag must be read from `loops project get` and never derived (LOOPS
  L243-249).
- The "agent wallet" is "the public address the agent sends its
  transactions from" (LOOPS L286). For smart-account wallets, whose bundler
  sends the transaction, the hash must be pasted manually (LOOPS L284).
- The Build with buy bounty is measured by "verified paid calls from the
  project's tagged wallet on Celo mainnet" (LOOPS L153, L156).
- ERC-8004 identity must be registered from the agent wallet (LOOPS L295).

### Attribution: VERIFIED (buy-skill)

- No file in `celo-org/buy-skill` mentions ERC-8021, attribution tags, or a
  data suffix. The only related field is an optional "ERC-8004 agent id on
  Celo" in the service-listing form (`list-your-service.yml` L99-101).

### Attribution: INFERRED

- A buy payment is an off-chain authorization signed by the payer and
  broadcast by the facilitator, with gas paid by the gateway sponsor. The
  agent wallet does not send that transaction and does not build its
  calldata. `withAttribution` / `dataSuffix` as described in LOOPS L251-270
  therefore cannot be applied by the project to buy settlement
  transactions.
- Whether "paid calls from the project's tagged wallet" means the payer
  address of facilitator-sent transfers, or requires a tag in the
  settlement calldata, is not stated in either source.

### Attribution: BLOCKED

- How Loops credits buy payments for this bounty, given that the payer
  does not send the settlement transaction. Needs an answer from Loops or
  the sponsor (for example via `loops knowledge query --sponsor
  build-with-buy`) before any mainnet payment.
- The project's official tag. The value `celo_9d43bf3ecad7` cited in an
  earlier draft was not re-read from `loops project get` in this review.

## 5. Evidence summary

### Summary: VERIFIED

Everything in sections 1, 2, the VERIFIED part of section 3, and the
VERIFIED parts of section 4, at the cited lines.

### Summary: INFERRED

- The gating point is before `buy_curl` / `buy curl`.
- OxDeAI fills a gap buy does not cover: per-payment, request-bound
  authorization.
- The documented default MCP setup lets an agent with shell access bypass a
  tool-level PEP. Enforcement requires OS-level separation.
- The project cannot attach an ERC-8021 tag to buy settlement transactions.

### Summary: NOT_TESTED

- Any real `buy_pay_quote`, `buy_curl`, `buy quote`, or `buy curl` call.
- Whether `buy_curl` / `buy curl` refuses before signing when the live
  price exceeds `maxAmount`. The docs call it the approved maximum (GW L271,
  OC L292-293) but do not state the refusal behavior.
- MCP response schemas beyond `price.atomic` / `price.token`.
- Running the buy MCP server or CLI under a separate OS user from the agent.
- Daily-cap behavior in practice.
- Celo mainnet settlement, ERC-8021 tagging, ERC-8004 registration.

### Summary: BLOCKED

- Loops crediting rule for facilitator-broadcast buy payments (section 4).
- Official attribution tag, read from `loops project get`.
- Explicit approval to spend real funds on mainnet (required by AGENTS.md).
- A funded agent wallet, which does not exist and must not be created
  without that approval.

## 6. Local prototype results (Phase 1)

The local prototype implements the architecture above with the published
OxDeAI packages (`@oxdeai/core@2.0.2`, `@oxdeai/guard@2.0.3`) and a **mock**
buy adapter. The suite was executed: 43 tests, 43 pass. Details:
`docs/CONFORMANCE.md`, `docs/ARCHITECTURE.md`, `evidence/test-results.txt`.

These results are evidence about the OxDeAI gateway logic only. They are
not evidence about `@celo/buy`, the gateway, Celo, or OS-level isolation.
The `@celo/buy` adapter in `src/adapters/celo-buy/` is an interface stub.

## 7. Acceptance criteria for live integration

These are criteria for Phase 2. None has been executed against real buy.

| Criterion | Status |
| --- | --- |
| Mismatched request denied; `buy_curl` / `buy curl` not invoked | NOT_TESTED |
| PEP allows an exact, capped request; buy executes it unchanged | NOT_TESTED |
| Policy cap exceeded: PEP denies before buy signs | NOT_TESTED |
| Agent cannot run `buy`, call `buy_curl`, or read the keychain | NOT_TESTED |
| CLI path converts atomic amounts to decimal exactly | NOT_TESTED |
| Live price above authorized max: no settlement | NOT_TESTED |
| Settlement is credited by Loops to this entry | BLOCKED |

## 8. Decision

### Local prototype feasibility: GO (demonstrated)

The OxDeAI gateway pattern of binding, expiry, replay, signature, and
fail-closed checks before a payment adapter is implemented and tested
locally with a mock adapter (section 6). The buy interfaces it must drive
are documented well enough to define the adapter contract (section 2).

### Live `@celo/buy` integration readiness: NOT READY

Technically, the integration is CONDITIONAL: feasible if the conditions in
section 3 hold, which requires OS-level separation of the buy process from
the agent. None of this has been built or tested.

It is NOT READY for hackathon mainnet activity because of the BLOCKED
items:

1. The Loops crediting rule for facilitator-broadcast buy payments is
   unconfirmed. The project cannot tag those transactions itself.
2. The official tag has not been read from Loops in this review.
3. No approval exists to spend real funds, and no wallet exists.

### Claims not supported

Do not claim that:

- `@celo/buy` payments carry an ERC-8021 tag or are credited by Loops;
- the OxDeAI gate is non-bypassable against real buy (not tested);
- `buy_curl` enforces `maxAmount` before signing (not documented, not tested).

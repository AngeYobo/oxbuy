# x402 / EIP-3009 on Celo Sepolia under the OxDeAI authorization boundary

Status (2026-10-29). Every item is classified as follows:
* **VERIFIED**: implemented and exercised by a test that ran and passed.
* **IMPLEMENTED, NOT VERIFIED**: written, but its live behaviour has not run.
* **LIMITATION**.
* **FUTURE**.

Testnet only. Celo mainnet is refused in code (§3.4). No mainnet transaction was made or is authorized.

## 1. Summary

| | Status |
| --- | --- |
| x402 v2 `exact` / EIP-3009 payment path (adapter, seller, facilitator client, JSON-RPC client) | **VERIFIED offline**: simulator with real EIP-3009 semantics, over real HTTP |
| EIP-712 digest byte-exact with another implementation | **VERIFIED**: the signed example of the x402 spec recovers to its stated payer (EV1) |
| Payment bound to the OxDeAI authorization (network, chain id, token, EIP-712 domain, recipient, amount, resource, expiry, nonce) | **VERIFIED offline**: X1-X7, X17 |
| Replay, duplicates, timeouts, revert, lying servers, crash, restarts, outage, rollback, concurrency | **VERIFIED offline**: X8-X16 in process; XP1-XP5 with the four OS identities |
| Real Celo Sepolia transaction | **IMPLEMENTED, NOT VERIFIED**: this environment cannot reach Celo (§2.3). Run `npm run testnet:live` (§5); the dry run of the same script against the simulator passes (LD1) |
| F-SIBLING | **OPEN**, see `docs/F-SIBLING-ASSESSMENT.md` |
| Mainnet | **NOT AUTHORIZED**. No configuration exists, and the code refuses it |

## 2. Feasibility checks (2026-10-29)

### 2.1 Components

| Component | Finding | Source |
| --- | --- | --- |
| Celo Sepolia | chain id 11142220, CAIP-2 `eip155:11142220`, RPC `https://forno.celo-sepolia.celo-testnet.org` | Celo docs (x402 page, agent skill) |
| Testnet token with EIP-3009 | USDC `0x01C5C0122039549AD1493B8220cABEdD739BC44E`, 6 decimals, EIP-712 name `USDC`, version `2` | Circle USDC contract list; Blockscout token API (`name USDC, type ERC-20, decimals 6`); facilitator `/supported` |
| x402 facilitator | `https://api.x402.sepolia.celo.org` (Celo Core Co., built on x402-rs). `/health` answered `{"status":"ok","network":"testnet"}`. `/supported` lists `x402Version 2, scheme exact, network eip155:11142220`, default asset USDC with `assetTransferMethod: eip3009`, and signer `0x0d74D5Cefd2e7F24E623330ebE3d8D4cB45fFB48` | live GET via the web tool, 2026-10-29 |
| Settlement auth | `/settle` needs an API key (`X-API-Key`), created on https://x402.celo.org with a wallet signature. `/verify` and `/supported` are open. Errors: 401 (key), 402 (out of credits), 429 (rate limit) | Celo docs, x402 page |
| Test funds | Circle faucet (https://faucet.circle.com) lists Celo Sepolia: 20 USDC per address every 2 hours. The payer needs USDC only; the facilitator pays the gas | Circle faucet page; Celo docs |
| Wire format | x402 v2: `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE` (base64 JSON); `settlement_pending` is non-terminal | coinbase/x402 `specs/` at commit `0e6e8c55` (2026-10-15) |

Conclusion: a complete x402 integration on Celo Sepolia is feasible. Option 1 (a direct ERC-20 transfer) is not
needed as a fallback.

### 2.2 Choices

* The payer is the OxDeAI executor. It signs EIP-3009 `TransferWithAuthorization` and never broadcasts: the
  facilitator does.
* The seller is a minimal x402 resource server (`src/x402/seller.ts`), run by the operator for the demonstration.
* `@celo/buy` is **not** used. Its pre-signing constraints on payTo, network and asset are unverified
  (`docs/FEASIBILITY.md`), and the mandate requires the executor itself to enforce them.

### 2.3 What this environment could not do

The sandbox proxy refuses `forno.celo-sepolia.celo-testnet.org`, `rpc.ankr.com` and
`celo-sepolia.blockscout.com` (403), and the npm and PyPI registries are unreachable. Consequences:
* No live transaction was sent.
* The dependencies were built from their git tags (§8).
* The live test `LIVE-1` is skipped here (**NOT_TESTED**).

## 3. Architecture and transaction flow

```mermaid
sequenceDiagram
    participant A as Agent (no key)
    participant P as Auth service (PDP)
    participant G as Gateway (PEP)
    participant E as Executor (holds testnet key)
    participant S as x402 seller
    participant F as Facilitator
    participant C as Celo Sepolia (USDC)
    A->>P: purchase request (network, asset, recipient, max_amount, url, body)
    P-->>A: signed single-use authorization (budget reserved)
    A->>G: request + authorization
    G->>E: verified request (internal token)
    E->>E: verify signature, audience, expiry, intent hash
    E->>S: request without payment
    S-->>E: 402 PAYMENT-REQUIRED (accepts)
    E->>E: quote check vs authorization
    E->>P: CLAIM (once, ever)
    P-->>E: CLAIMED (durable)
    E->>C: eth_chainId == 11142220? authorizationState(payer, nonce) == unused?
    E->>S: re-fetch 402; check every field; sign EIP-3009 (nonce = f(intent))
    E->>S: request + PAYMENT-SIGNATURE
    S->>F: /verify, /settle (X-API-Key)
    F->>C: transferWithAuthorization (facilitator pays gas)
    S-->>E: 200 + PAYMENT-RESPONSE (tx hash)
    E->>C: eth_getTransactionReceipt: AuthorizationUsed + Transfer from USDC
    E-->>G: EXECUTED (receipt = tx)
    E->>P: signed outcome report: budget settled
```

### 3.1 What binds the signature to the authorization (`src/adapters/x402-evm/x402-evm.ts`)

Each check runs on the **live** 402, immediately before signing. A failure throws `PaymentRefusedError`, which
means nothing was signed. All of this happens after the auth service committed the single claim for this
authorization.

| Field signed | Constraint |
| --- | --- |
| chain | `request.network` is a configured **testnet** (mainnet refused), and the RPC's `eth_chainId` equals it. If the RPC is unreachable, the payment is refused |
| `verifyingContract`, EIP-712 name/version | the 402 asset equals the authorized asset, is a configured EIP-3009 token, and `extra.name` / `extra.version` equal its known domain |
| scheme / method | `exact`, `assetTransferMethod` absent or `eip3009` |
| `to` | the 402 `payTo` equals the authorized recipient **and** is on the executor's approved-recipient list |
| `value` | the live 402 amount, `0 < amount <= max_amount` |
| resource | the 402 `resource.url` (origin + path) equals the authorized URL |
| `validBefore` | `min(now + maxTimeoutSeconds, authorization.expiry)`, with at least 10 s left. The signed payment never outlives the OxDeAI authorization |
| `nonce` | `sha256("oxdeai-celo-poc/x402-eip3009-nonce/v1\0" ‖ intent_hash)`. One authorized intent can settle at most **one** transfer, and the token contract enforces it |
| key | read from the executor-private file only after every check above. A nonce already consumed on chain refuses a new signature |

The executor never accepts a caller's claim that authorization succeeded: the request envelope is exactly
`{action, authorization}`, and the authorization is verified cryptographically (X2).

### 3.2 Outcomes

| Situation | Answer | Journal | Budget |
| --- | --- | --- | --- |
| Receipt mined, status 1, with `AuthorizationUsed(payer, nonce)` and `Transfer(payer → recipient, value)` from the token | ALLOW / EXECUTED | SETTLED | confirmed at the settled amount |
| Any refusal before signing | DENY (`final` as in 0008) | REFUSED_BEFORE_SIGNING or REJECTED | released |
| Lost response, transport error, malformed PAYMENT-RESPONSE | INDETERMINATE | UNKNOWN (detail: payer, nonce, validBefore) | held fully |
| `settlement_pending`, or no receipt before the timeout | INDETERMINATE (`X402_TX_PENDING`) | UNKNOWN (+ tx) | held fully |
| Seller or facilitator says "not settled" | INDETERMINATE (`X402_NOT_SETTLED_UNCONFIRMED`). Not proof: the signed authorization stays valid until `validBefore` | UNKNOWN | held fully |
| Reverted transaction | INDETERMINATE (`X402_TX_REVERTED`), nonce not consumed | UNKNOWN | held fully |
| Success claimed with an unknown or unrelated transaction | INDETERMINATE (`X402_TX_PENDING` / `X402_TX_EVIDENCE_MISMATCH`) | UNKNOWN | held fully |

A restart, a timeout or a lost RPC answer is never read as "not submitted".

### 3.3 Reconciliation (on-chain evidence)

The only accepted evidence of settlement (`src/chain/eip3009-evidence.ts`) is a mined, successful receipt that
carries **from the authorized token** both:
* `AuthorizationUsed(payer, nonce = f(intent))`;
* `Transfer(payer → authorized recipient, value ≤ max)`.

In addition, the nonce must be consumed (`authorizationState == true`), and the chain id must be the testnet's.

Process deployment, executor stopped, run as the executor identity:

```
node src/isolation/journal-cli.ts <journalDir> resolve-x402 <intent_hash> <tx_hash> <rpcUrl> <walletKeyPath> <note>
```

The command:
* checks the evidence and refuses a pending, reverted or unrelated transaction (XP2);
* records an `EIP3009_ONCHAIN` resolution in the journal and in the append-only checkpoint;
* lets the reporter then confirm the reservation (`RESOLVED_SETTLED`).

**FUTURE:** the chain can also prove **non**-execution. If the nonce is still unused once the chain time is past
`validBefore`, the signed authorization can never settle. Releasing an UNCERTAIN reservation on that proof
needs a new auth-service transition and an independent review, so it is not implemented. Until then such a
reservation stays charged (fail-safe).

### 3.4 Configuration separation

* `src/chain/networks.ts` contains only Celo Sepolia.
* `authorizedTestnet()` refuses `eip155:42220` (Celo mainnet), `eip155:1` and `eip155:8453` with
  `NETWORK_NOT_AUTHORIZED:mainnet`, and every unlisted network.
* An x402 executor configured for mainnet refuses to start (XP5).
* A mainnet configuration would be a separate file under a separate mandate.

## 4. Trust assumptions and limits

* **The wallet key is confined to the executor identity**: a 0600 file, read only inside `pay` (XP1). OxDeAI
  constrains what the executor signs. It **cannot** constrain someone who holds the key: a stolen key spends
  directly on chain.
  * FUTURE: on-chain enforcement, for example a smart account or delegation (ERC-7710) with recipient, amount
    and expiry caveats, so that the key alone is not enough.
* **The RPC is trusted** for the chain id, nonce state and receipts. A lying RPC could fake a settlement
  receipt, which would be a false EXECUTED. It cannot cause an unauthorized payment: the signature binds `to`,
  `value` and `nonce`.
  * FUTURE: two independent RPCs, or a light client.
* **The seller and facilitator are untrusted** for correctness (X12-b) and trusted only for liveness. A payee
  can hold a signed authorization and settle it later. It can only ever move exactly the authorized amount, to
  the authorized recipient, once, before `validBefore`.
* **Finality:** one mined receipt is accepted (testnet). Mainnet would need a confirmation policy.
* **Live demonstration mode:** `npm run testnet:live` runs the OxDeAI components in one process. OS isolation
  with the x402 rail is exercised offline (XP1-XP5), not live.
* **Clock:** `validAfter = now − 30 s`. Executor clock skew larger than that would make the facilitator refuse.
  That failure is safe: it is reported INDETERMINATE and the reservation is held.

## 5. Testnet runbook (developer workstation)

1. `npm ci && npm run typecheck && npm test`. Expected: all tests pass and `LIVE-1` is skipped.
2. Create a **new, testnet-only** key and never reuse it elsewhere. For example:

   ```
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" > ~/.oxdeai/celo-sepolia-payer.key
   chmod 600 ~/.oxdeai/celo-sepolia-payer.key
   npm run testnet:address -- ~/.oxdeai/celo-sepolia-payer.key     # prints the address, never the key
   ```

3. Fund that address with Celo Sepolia USDC at https://faucet.circle.com (network "Celo Sepolia"). No CELO is
   needed.
4. Pick a recipient you control (a second testnet address), and create a facilitator API key on
   https://x402.celo.org.
5. Copy `docs/testnet.env.example` to a file outside the repository, fill it in, and `source` it.
6. `npm run testnet:live`. Expected: `L1` to `L5` PASS, then `evidence: evidence/testnet/<run>/live-evidence.json (PASS)`.
7. Open the `explorer` link of L1 (https://celo-sepolia.blockscout.com/tx/...). It shows a
   `transferWithAuthorization` from the facilitator's signer moving the price from your payer to your
   recipient.
8. For independent review, keep `live-evidence.json` together with the run's `journal/` and `checkpoint.log`.
   Since R-02 they contain the signed EIP-3009 authorization (a bearer capability until `validBefore`, at most the
   OxDeAI authorization expiry): share them only after `validBefore` has passed, never from a live run in progress
   (security review XR-04). Optionally run `OXDEAI_TESTNET_LIVE=1 node --test tests/testnet/live-celo-sepolia.test.ts`.

If L1 is not PASS with an INDETERMINATE answer, do **not** re-run blindly:
* look up the nonce printed in `adapter_events` on the explorer;
* the payment may still settle until `validBefore`.

## 6. Tests

| ID | Mandate §7 item | Where | Result here |
| --- | --- | --- | --- |
| X1, X1-b | valid authorized payment | tests/x402/x402-security.test.ts | PASS |
| X2 | missing or invalid authorization, caller-asserted authorization | same | PASS |
| X3 | expired authorization (and too close to expiry) | same | PASS |
| X4 | recipient mismatch (402, approved list, policy) | same | PASS |
| X5 | amount mismatch (above max, lower price, policy max) | same | PASS |
| X6 | wrong chain id, mainnet network, RPC unavailable before signing | same | PASS |
| X7 | token, contract, EIP-712 domain, transfer method mismatch | same | PASS |
| X8 | replay of a consumed authorization (with restarts) | same | PASS |
| X9 | duplicate transaction submission; re-sign after total state loss | same | PASS |
| X10-a/b | RPC or response timeout after broadcast; `settlement_pending` | same | PASS |
| X11, XP2 | process crash during execution (in process; real SIGKILL) | same; tests/isolation/x402-process.test.ts | PASS |
| X12, X12-b | reverted on chain; lying seller or facilitator | x402-security | PASS |
| X13, XP2 | gateway or executor restart | x402-security; x402-process | PASS |
| X14, XP4 | authorization service outage | both | PASS |
| X15, XP3 | journal and checkpoint rollback | both | PASS |
| X16 | concurrent payment attempts | x402-security | PASS |
| X17, X14, XP4 | final / non-final propagation | both | PASS |
| X18, XP1 | key hygiene (journal, checkpoint, logs, config, seller, agent access) | both | PASS |
| XP5 | mainnet refused at executor start | x402-process | PASS |
| EV1-EV6 | primitives, independent EIP-712 vector, strict codecs | tests/x402/evm-primitives.test.ts | PASS |
| LD1 | live script against the simulator | tests/x402/live-demo-dryrun.test.ts | PASS |
| LIVE-1 | real Celo Sepolia | tests/testnet/live-celo-sepolia.test.ts | **NOT_TESTED** (skipped) |

Commands, exit codes and logs: see the evidence package (`TEST-RESULTS.md`).

## 7. Changes to existing behaviour

* `AuthorizedPayment.authorization_expiry`: a new optional field, which the executor always passes. The mock
  ignores it.
* `SettlementEvidence` accepts the new `EIP3009_ONCHAIN` kind.
* `ExecutorConfig.payment` (optional, default mock) and `LaunchOptions.payment`.
* `initPolicyState({state})` takes an explicit profile.
* `policyStateFor()` is extracted from `initialPolicyState()`, which is unchanged in output.
* `TRUSTED_DEPENDENCIES` contains `@noble/hashes` and `@noble/curves` 2.2.0. The sealed artifact loads them from
  the operator's npm cache, verified against the lockfile.
* `journal-cli resolve-x402`; agent probe `authorize-request` (test-only).
* The mock path is unchanged, and so are all 259 baseline tests.

## 8. Dependencies

| Package | Version | Why | Integrity (lockfile = registry) | Notes |
| --- | --- | --- | --- | --- |
| `@noble/hashes` | 2.2.0 (git `81983c2`) | keccak-256, sha256 | `sha512-IYqDGiTX…sjtEg==` | audited, zero dependencies |
| `@noble/curves` | 2.2.0 (git `043905d`) | secp256k1 (low-s, recoverable) | `sha512-T/BoHgFX…SeIkQ==` | audited, depends only on `@noble/hashes` |

* The registry was unreachable here. Both packages were built from their git tags with TypeScript 6.0.2, as
  upstream does, and `npm pack` reproduced the registry tarballs **byte for byte**: same sha512 and sha1 as the
  registry metadata, whose gitHead matches.
* Chosen version: April 2026, about 6 months old, rather than the newest (August 2026), for supply-chain
  reasons.
* Security implications: these are the only new runtime code. Both are on the trusted-artifact allowlist. No
  network client library (viem, ethers) was added: JSON-RPC and x402 are about 400 lines of local code.

## 9. Proposed future work

1. Run `LIVE-1` on a workstation and archive the evidence for independent review.
2. F-SIBLING remediation R1: an on-chain nonce cancel for non-final rejections (`docs/F-SIBLING-ASSESSMENT.md`).
3. Positive non-execution evidence (`validBefore` passed, nonce unused) to release UNCERTAIN reservations,
   after review.
4. RPC redundancy, a confirmation policy, and on-chain spending caveats for the key.
5. Mainnet only under a new written mandate, with a key-management design, limits, monitoring and an
   emergency stop.

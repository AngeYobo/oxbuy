# OxBuy

**AI agents that buy. You set the rules.** OxBuy buys paid API services from an **approved catalogue** through x402
on Celo. Every purchase is authorized by [OxDeAI](https://github.com/oxdeai/oxdeai) before anything is signed.

* The agent chooses what to buy.
* The operator's catalogue fixes the provider, recipient, token, network and maximum price per call, plus a budget
  **per session** (one run of the CLI).
* An out-of-policy purchase is denied with nothing signed and nothing paid.

Status: Proof of Concept, **Celo Sepolia only**. Mainnet is refused in code until separately approved.

## 1. Wallets (do not mix them up)

| Role | Address | Used by |
| --- | --- | --- |
| Sepolia test wallet | `0xae1c830076fe626610a9c24c92180bcf97c9e924` | everything in this document |
| Hackathon mainnet wallet | `0xddc224cbf39471673f3948385aa65e967df7c50a` | **not used here**. Mainnet needs a separate approval |

## 2. Gate before any live payment (all three must PASS)

| Gate | Command | PASS | FAIL → stop |
| --- | --- | --- | --- |
| G1: patch 0010 applied and tested | `node --test tests/x402/patch-0010.test.ts` | `# pass 3` and `# fail 0` (P10-XR01-a, P10-XR01-b, P10-XR03) | any failure, or the file is missing |
| G2: the gateway probe | §3 | last line `PROBE PASS`, exit code 0 | `PROBE FAIL` (exit 3) or any error |
| G3: the Sepolia wallet is funded | open `https://celo-sepolia.blockscout.com/address/0xae1c830076fe626610a9c24c92180bcf97c9e924` | USDC balance ≥ the probe's `max_price` (for example 0.001 USDC = 1000 units). No CELO needed | balance too low: faucet.circle.com, network "Celo Sepolia" |

Also run the full `npm test` once: it must show `# fail 0`. On WSL the isolation tests are skipped: that is a
coverage limit, not a pass.

## 3. Probe the buy gateway (no key, no payment)

```bash
npm run x402:probe -- POST https://gateway.usebuy.ai/v1/social/x/posts/search '{"query":"celo"}'
echo "exit=$?"
```

### PASS: what you should see
* `"status": 402`, and `"x402": 1` (or 2).
* In `offers`, an entry with `"network": "eip155:11142220"` (wire name `celo-sepolia`), the USDC Sepolia asset
  `0x01C5…C44E`, `"extra": {"name":"USDC","version":"2"}` and `"payable_on_sepolia": "yes"`.
* A `catalog_entry` with `pay_to` and `max_price` copied from that offer.
* The last line `PROBE PASS: payable Celo Sepolia offer found …` and `exit=0`.

### FAIL: what it means
| Output | Meaning | Next step |
| --- | --- | --- |
| `PROBE FAIL … network celo is not Celo Sepolia` | only a mainnet offer | the Sepolia offer is not exposed for this route: try another `/v1/…` route, or report back |
| `PROBE FAIL … ASSET_NOT_AUTHORIZED` | the sandbox uses another test token | send me the output: the token must be verified, then added to `src/chain/networks.ts` |
| `PROBE FAIL … EIP-712 domain …` | the token domain differs | send me the output |
| `"status": 400/401/404/405`, `no 402 challenge` | wrong path or body, or the route needs something else | send me the output |
| network error | gateway unreachable from your machine | check connectivity and proxy |

## 4. Catalogue (non-secret; from the probe's `catalog_entry`)

`catalog.json`:

```json
{
  "network": "eip155:11142220",
  "budget": "5000",
  "per_call_max": "2000",
  "services": [
    {
      "service_id": "buy-x-search",
      "method": "POST",
      "url": "https://gateway.usebuy.ai/v1/social/x/posts/search",
      "network": "eip155:11142220",
      "asset": "0x01c5c0122039549ad1493b8220cabedd739bc44e",
      "pay_to": "<catalog_entry.pay_to>",
      "max_price": "<catalog_entry.max_price>",
      "purpose": "brand mentions on X"
    }
  ]
}
```

Rules: `max_price` ≤ `per_call_max` ≤ `budget`. `pay_to` and `asset` must be lower-case. Only
`eip155:11142220` is accepted.

## 5. Run the purchase (one authorized, one blocked)

```bash
export OXDEAI_TESTNET_PAYER_KEY_FILE=~/.oxdeai/celo-sepolia-payer.key   # Sepolia key file, mode 0600 (address 0xae1c…e924)
npm run testnet:address -- "$OXDEAI_TESTNET_PAYER_KEY_FILE"              # must print 0xae1c830076fe626610a9c24c92180bcf97c9e924
npm run oxbuy -- --catalog catalog.json --topic "celo" --deny-demo
echo "exit=$?"
```

Optional non-secret settings:
* `OXDEAI_TESTNET_RPC_URL` (default `https://forno.celo-sepolia.celo-testnet.org`);
* `OXDEAI_BUYER_STATE_DIR` (default `~/.oxdeai/oxbuy`, one private sub-directory per run);
* `OXDEAI_BUYER_EVIDENCE_DIR` (default `evidence/oxbuy`).

### PASS: expected output, in this order
1. `OxBuy · purchases authorized by OxDeAI · topic "celo" · service buy-x-search · budget 5000 · per call ≤ 2000`
2. `authorized purchase: ALLOW · tx 0x<64 hex> · https://celo-sepolia.blockscout.com/tx/0x…`
3. The brief: `# OxBuy brief: celo` … `## Spend (authorized by OxDeAI)` with the same tx.
4. `unapproved purchase: DENY at authorize · … · nothing signed or paid`
5. `budget spent: <max_price or less> of 5000`
6. `evidence: evidence/oxbuy/<run>/evidence.json`, then `exit=0`

Then on the explorer, the tx must show a USDC transfer from `0xae1c…e924` to the catalogue's `pay_to`, for the
amount in the brief. It is the only new transfer from that wallet (the blocked attempt never pays).

### FAIL: what it means (no blind retry)
| Output | Meaning | Action |
| --- | --- | --- |
| `authorized purchase: DENY …` with `RECIPIENT`, `AMOUNT`, `ASSET` or `NETWORK` | the live 402 no longer matches the catalogue | nothing was paid. Re-run the probe and update the catalogue |
| `authorized purchase: INDETERMINATE` (`X402_TX_PENDING`, `X402_NOT_SETTLED_UNCONFIRMED`, `X402_OUTCOME_UNKNOWN`) | the signed payment left; its outcome is unknown | **do not re-run**. Look up the wallet on the explorer. The signed authorization may still settle until its `validBefore` (≤ 2 min). Send me `evidence.json` |
| `BUYER_WRONG_CHAIN` | the RPC is not Celo Sepolia | fix `OXDEAI_TESTNET_RPC_URL` |
| `insufficient_funds` in the detail | wallet not funded | faucet, then re-run (a new run means a new authorization) |
| `unapproved purchase: ALLOW` | **a security failure** | stop and report immediately |

Send me `evidence.json`. It contains no key: addresses, tx hashes and results only. Keep the run's state
directory private (it holds the signed payment, XR-04).

## 6. Not established yet
* A real purchase: it depends on G1-G3 and §5 on your machine.
* Mainnet calls (the ones that count for judging): separate approval, the mainnet wallet `0xddc2…c50a`, and
  ERC-8004 on mainnet.
* The budget is per session, not per day.

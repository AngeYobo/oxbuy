# F-SIBLING and the remaining financial-integrity risks (x402 testnet integration)

Status: **OPEN. Not resolved by this work.** Classification: a release blocker for any mainnet authorization,
unless it is formally accepted by the owner.

## 1. The scenario

Four things happen in order:
1. An authentic authorization is rejected before execution while the authorization service is unreachable.
   The VOID is lost, so the answer is `final: false` (patch 0008).
2. Later, the executor's journal **and** its append-only checkpoint are restored together from an older backup,
   and the append-only attribute is re-armed. No executor-side store remembers the rejection any more.
3. The authorization service, which never learned of the rejection, still holds the reservation RESERVED.
4. The authorization is resubmitted before it expires.

Result: the authorization can pay once, within its binding and budget, and is charged once.

## 2. Reproduction (offline)

| Test | Rail | What it shows |
| --- | --- | --- |
| RB6-b (0008) | mock, OS identities | non-final rejection + joint restore → one payment |
| **X19-a** | **x402 / EIP-3009** | same on the real payment path: exactly one transfer, of the authorized amount, to the authorized recipient; a second attempt is refused, and the nonce makes a duplicate impossible |
| RB6-a, X15, XP3 | both | a **final** rejection, or a consumed authorization, survives the joint restore: the auth service refuses the claim |
| X9 | x402 | even with **every** OxDeAI store lost and an authority that grants any claim, a payment that **did** settle cannot be paid twice: the on-chain nonce stops the re-signature |
| X19-b | x402 (simulated cancel) | the mechanism of remediation R1 (§5): once the intent's nonce is canceled on chain, the F-SIBLING sequence can no longer pay |

Commands and logs: `TEST-RESULTS.md` in the evidence package.

## 3. Which guarantee rests on what

| Guarantee | Enforced by | Survives an executor journal + checkpoint restore? | Survives loss of every OxDeAI store? |
| --- | --- | --- | --- |
| No payment without an authorization (signature, audience, binding, expiry) | executor verification + adapter pre-signing checks | yes (stateless) | yes |
| At most one claim per authorization | auth service (policy state with its own anchor) | yes | no |
| A **final** rejection is never paid | auth service (VOID committed) | yes | no |
| A **non-final** rejection is never paid | executor journal + checkpoint only | **no (F-SIBLING)** | no |
| A settled intent is never paid twice | x402: token contract nonce `f(intent)`; mock: journal + auth | yes | **yes on x402** (X9) |
| A signed payment cannot outlive its authorization | `validBefore ≤ authorization.expiry` (token contract) | yes | yes |
| Budget never under-charged for a possible payment | auth service: UNCERTAIN is held fully | yes | no |

The x402 rail adds one witness that is independent of OxDeAI: the chain. It remembers every payment that
happened, so duplicates and double spends are closed even after total state loss. A rejection that was never
turned into a chain fact is not remembered by it. That is exactly F-SIBLING.

## 4. Exposure assessment (x402)

* **Duplication:** closed by the deterministic nonce. One intent gives one possible transfer, ever
  (X9, X16, X19-a).
* **Delayed confirmation:** a signed authorization can settle until `validBefore`, which is at most the OxDeAI
  expiry (60 s TTL here). In that window the outcome is INDETERMINATE and the reservation is held fully. The
  exposure is bounded by the authorized amount and recipient.
* **Replay:** four independent layers stop it: the gateway replay store, the executor journal, the single claim
  at the auth service, and the on-chain nonce (X8, X15).
* **Rollback:**
  * a journal-only rollback is detected and refused (X15, XP3);
  * a joint rollback is stopped by the auth service for consumed or finally rejected authorizations, and by the
    chain for settled ones;
  * it is **not** stopped for non-final rejections (X19-a).
* **Maximum loss in the F-SIBLING case:** one payment of at most `max_amount`, to the authorized recipient,
  within the budget, before the authorization expires. The policy authorized exactly this purchase; it is a
  broken promise (a rejection), not an unauthorized payment.

## 5. Remediation options

| | Mechanism | Trust assumptions | Failure modes | Assessment |
| --- | --- | --- | --- | --- |
| **R1: on-chain nonce cancel (recommended for x402)** | When a rejection's VOID is not confirmed, the executor signs EIP-3009 `cancelAuthorization(payer, nonce = f(intent))`. A relayer, or the executor with a little CELO for gas, submits it. Once mined, the rejection is a chain fact: any later attempt for that intent is refused before signing (`X402_NONCE_ALREADY_CONSUMED`, X19-b). The answer can become `final: true` | the chain (already trusted for settlement); an RPC to observe the cancel | chain also unreachable: still non-final; gas wallet empty: still non-final; a cancel not yet mined: non-final until mined | Closes F-SIBLING on x402 whenever the chain is reachable, with no new trusted party. Needs a gas or relayer design, live verification, and an outcome rule for "nonce canceled" (today X19-b ends INDETERMINATE and the reservation is held, which is safe but not tidy) |
| R2: external durable rejection record (state provider) | Before answering a rejection, write it to a replicated, append-only store outside the executor's backup domain (another host, WORM object storage, a transparency log). The executor checks it before every claim | the provider's integrity and availability, and that it is outside every restore | provider down: same as an auth outage (non-final); a provider restored with the executor: same as today | General, works for any rail. It adds a trusted component and operational weight |
| R3: VOID retry outbox | The reporter retries unconfirmed VOIDs until the service confirms them | none new | restore before the retry succeeds: open | Shrinks the window only; changes about 8 existing test expectations (release by VOID instead of expiry) |
| R4: refuse to reject without the authority | The executor does not consume locally while the auth service is unreachable ("try later") | none | the same payment can happen later | Honest but only renames the risk: nothing was ever "rejected" |
| R5: accept | Document the bounded exposure (§4) | — | — | Acceptable for a testnet PoC; a formal owner decision before mainnet |

Recommendation: implement **R1 + R3** for the x402 rail and verify them live on Celo Sepolia. Keep R2 for rails
without a programmable witness. Until R1 is implemented and reviewed, F-SIBLING stays a **mainnet release
blocker**, or needs an explicit, documented R5 acceptance by the owner.

## 6. Other remaining financial-integrity risks (x402)

| Risk | Status |
| --- | --- |
| UNCERTAIN reservations are never released, even when the chain proves non-execution (nonce unused after `validBefore`) | fail-safe (over-charged budget). FUTURE: a reviewed release transition |
| A single trusted RPC: a lying RPC can fake a settlement receipt (false EXECUTED). It cannot cause an unauthorized transfer | FUTURE: RPC redundancy, or a light client |
| A stolen executor key spends without OxDeAI | trust assumption; FUTURE: on-chain spending caveats (smart account or delegation) |
| One-receipt finality | acceptable on testnet; mainnet needs a confirmation policy |
| Live behaviour of the real facilitator and token (error codes, pending semantics) | NOT_TESTED here; run LIVE-1 |

// SPDX-License-Identifier: MIT
/**
 * x402 v2 `exact` / EIP-3009 payment adapter for EVM testnets (Celo Sepolia).
 *
 * The executor calls `pay` only with an execution claim committed by the OxDeAI authorization
 * service (src/executor/executor.ts). This adapter is the last gate before a signature leaves the
 * process. Holding the wallet key is not enough to pay: it signs exactly one EIP-3009 authorization,
 * and only one that is bound to the OxDeAI authorization:
 *
 *   network    = authorized network (CAIP-2), a configured TESTNET (mainnet refused), and the RPC's
 *                chain id equals it
 *   asset      = authorized asset = a configured EIP-3009 token, with its exact EIP-712 domain
 *   to         = authorized recipient, also on the executor's approved-recipient list
 *   value      = the live 402 amount, required to be <= authorized max_amount (and > 0)
 *   resource   = authorized URL (origin + path)
 *   validBefore= min(now + maxTimeoutSeconds, OxDeAI authorization expiry)
 *   nonce      = f(intent_hash): one authorized intent settles at most one transfer, enforced by the
 *                token contract itself, even if every executor-side store is lost
 *
 * Every check runs against the LIVE 402 requirements immediately before signing. Any failure before
 * the signature is handed out throws PaymentRefusedError (nothing signed). After that point every
 * failure is an unknown outcome (plain Error whose message carries what reconciliation needs, e.g.
 * the transaction hash): a timeout, a lost response, a "failed" or "pending" answer, or a reverted
 * transaction never proves that the signed authorization will not settle until validBefore.
 *
 * Success requires on-chain proof (src/chain/eip3009-evidence.ts), not the server's word.
 */
import { authorizationConsumed, settlementInReceipt } from "../../chain/eip3009-evidence.ts";
import { addressOfPrivateKey, eip3009NonceForIntent, HEX32, signTransferAuthorization } from "../../chain/evm.ts";
import { authorizedAsset, authorizedTestnet, type EvmNetwork } from "../../chain/networks.ts";
import type { EvmRpc } from "../../chain/rpc.ts";
import {
  PaymentRefusedError,
  type AuthorizedPayment,
  type PaymentAdapter,
  type PaymentQuote,
  type PaymentReceipt,
  type QuoteRequest,
} from "../../executor/payment-adapter.ts";
import {
  encodeHeader,
  HEADER_PAYMENT_REQUIRED,
  HEADER_PAYMENT_RESPONSE,
  HEADER_PAYMENT_SIGNATURE,
  parsePaymentRequired,
  parseSettleResponse,
  decodeHeader,
  HEADER_X_PAYMENT,
  HEADER_X_PAYMENT_RESPONSE,
  parsePaymentRequiredV1,
  v1NetworkToCaip2,
  type PaymentPayloadV1,
  type PaymentPayload,
  type PaymentRequirements,
} from "../../x402/wire.ts";

export type X402EvmConfig = {
  /** CAIP-2 id of the configured testnet (e.g. eip155:11142220). */
  readonly network: string;
  readonly rpc: EvmRpc;
  /** Reads the executor-private wallet key. Called only inside `pay`, after every pre-signing check. */
  readonly loadWalletKey: () => Uint8Array;
  /** Recipients this executor may ever pay (lower-case). Defense in depth on top of the policy allowlist. */
  readonly approvedRecipients: readonly string[];
  /** HTTP transport (default: global fetch). */
  readonly fetch?: typeof fetch;
  /**
   * Executor-owned routing of an authorized https origin to the endpoint actually dialed (like curl
   * --connect-to), e.g. a local seller during tests. The authorized URL itself is unchanged and is
   * what the 402 resource must name.
   */
  readonly endpoints?: Readonly<Record<string, string>>;
  /** Unix seconds. */
  readonly now?: () => number;
  /** Receipt wait after a broadcast (default 30 s; poll every 1 s). */
  readonly receiptTimeoutMs?: number;
  readonly receiptPollMs?: number;
  /** HTTP timeout per request (default 30 s). */
  readonly httpTimeoutMs?: number;
  /** Seconds that must remain before validBefore when signing (default 10). */
  readonly minValiditySeconds?: number;
  readonly log?: (event: Record<string, unknown>) => void;
};

const MAX_BODY = 64 * 1024;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const lc = (s: string) => s.toLowerCase();

export function createX402EvmAdapter(cfg: X402EvmConfig): PaymentAdapter {
  const network: EvmNetwork = authorizedTestnet(cfg.network);
  const approved = new Set(cfg.approvedRecipients.map(lc));
  const now = cfg.now ?? (() => Math.floor(Date.now() / 1000));
  const f = cfg.fetch ?? fetch;
  const minValidity = cfg.minValiditySeconds ?? 10;

  function dialUrl(url: string): string {
    const u = new URL(url);
    const target = cfg.endpoints?.[u.origin];
    return target === undefined ? url : `${target.replace(/\/$/, "")}${u.pathname}${u.search}`;
  }

  async function send(req: QuoteRequest, headers: Record<string, string> = {}): Promise<Response> {
    return f(dialUrl(req.url), {
      method: req.method,
      headers: { ...(req.body !== null ? { "content-type": "application/json" } : {}), ...headers },
      ...(req.body !== null ? { body: req.body } : {}),
      redirect: "manual",
      signal: AbortSignal.timeout(cfg.httpTimeoutMs ?? 30_000),
    });
  }

  /**
   * The live 402 offers for `req` (read-only), normalized: x402 v2 (PAYMENT-REQUIRED header) or v1 (JSON body,
   * network names mapped to CAIP-2). `resource` is origin + path of the resource the offer is for.
   */
  type Offer = { readonly req: PaymentRequirements; readonly resource: string; readonly version: 1 | 2; readonly wireNetwork: string };
  async function challenge(req: QuoteRequest): Promise<{ offers: readonly Offer[] }> {
    const res = await send(req);
    if (res.status !== 402) throw new Error(`X402_NO_CHALLENGE:http ${res.status}`);
    const originPath = (url: string) => {
      const u = new URL(url);
      return `${u.origin}${u.pathname}`;
    };
    const header = res.headers.get(HEADER_PAYMENT_REQUIRED);
    if (header) {
      const pr = parsePaymentRequired(header);
      return { offers: pr.accepts.map((a) => ({ req: a, resource: originPath(pr.resource.url), version: 2 as const, wireNetwork: a.network })) };
    }
    let body: unknown;
    try {
      body = JSON.parse((await res.text()).slice(0, MAX_BODY));
    } catch {
      throw new Error("X402_MALFORMED:402 without PAYMENT-REQUIRED header or JSON body");
    }
    return { offers: parsePaymentRequiredV1(body).map((o) => ({ req: o.requirements, resource: originPath(o.resource), version: 1 as const, wireNetwork: o.wireNetwork })) };
  }

  /** Requirements this executor can pay at all (scheme, testnet, configured EIP-3009 asset). */
  function payable(a: PaymentRequirements): boolean {
    if (a.scheme !== "exact" || a.network !== network.caip2) return false;
    const m = a.extra?.assetTransferMethod;
    if (m !== undefined && m !== "eip3009") return false;
    try {
      authorizedAsset(network, a.asset);
      return true;
    } catch {
      return false;
    }
  }

  /** Why `a` cannot be paid under `payment`, or null. Pure; runs on the live 402 just before signing. */
  function mismatch(a: PaymentRequirements, resource: string, p: AuthorizedPayment): string | null {
    const r = p.request;
    if (a.scheme !== "exact") return "X402_SCHEME_NOT_EXACT";
    if (a.network !== r.network) return "X402_NETWORK_MISMATCH";
    const m = a.extra?.assetTransferMethod;
    if (m !== undefined && m !== "eip3009") return "X402_TRANSFER_METHOD_NOT_EIP3009";
    if (lc(a.asset) !== lc(r.asset)) return "X402_ASSET_MISMATCH";
    let asset;
    try {
      asset = authorizedAsset(network, a.asset);
    } catch {
      return "X402_ASSET_NOT_AUTHORIZED";
    }
    if (a.extra?.name !== asset.eip712Name || a.extra?.version !== asset.eip712Version) return "X402_EIP712_DOMAIN_MISMATCH";
    if (!/^0x[0-9a-fA-F]{40}$/.test(a.payTo) || lc(a.payTo) !== r.recipient) return "X402_RECIPIENT_MISMATCH";
    if (!approved.has(r.recipient)) return "X402_RECIPIENT_NOT_APPROVED";
    const amount = BigInt(a.amount);
    if (amount <= 0n) return "X402_AMOUNT_INVALID";
    if (amount > BigInt(r.max_amount)) return "X402_AMOUNT_EXCEEDS_AUTHORIZED_MAX";
    const u = new URL(r.url);
    if (resource !== `${u.origin}${u.pathname}`) return "X402_RESOURCE_MISMATCH";
    return null;
  }

  return {
    async quote(request) {
      const c = await challenge(request);
      const o = c.offers.find((x) => payable(x.req));
      if (!o) throw new Error("X402_NO_PAYABLE_REQUIREMENT");
      const a = o.req;
      const q: PaymentQuote = { network: a.network, asset: lc(a.asset), pay_to: lc(a.payTo), amount: a.amount, resource: o.resource };
      return q;
    },

    async pay(payment) {
      const r = payment.request;
      // ── Before signing: any failure means nothing was signed (PaymentRefusedError). ──
      let net: EvmNetwork;
      try {
        net = authorizedTestnet(r.network);
      } catch (err) {
        throw new PaymentRefusedError((err as Error).message);
      }
      if (net.caip2 !== network.caip2) throw new PaymentRefusedError("X402_NETWORK_NOT_CONFIGURED");
      if (typeof payment.authorization_expiry !== "number") throw new PaymentRefusedError("X402_AUTHORIZATION_EXPIRY_REQUIRED");
      // XR-03: no durable binding store, no signature (checked before any key read or signing).
      const persistBinding = payment.persistPaymentBinding;
      if (typeof persistBinding !== "function") throw new PaymentRefusedError("X402_PAYMENT_BINDING_REQUIRED");
      let chainId: bigint;
      try {
        chainId = await cfg.rpc.chainId();
      } catch (err) {
        throw new PaymentRefusedError(`X402_RPC_UNAVAILABLE_BEFORE_SIGNING:${(err as Error).message}`);
      }
      if (chainId !== network.chainId) throw new PaymentRefusedError(`X402_CHAIN_ID_MISMATCH:${chainId}`);

      let c;
      try {
        c = await challenge(r);
      } catch (err) {
        throw new PaymentRefusedError(`X402_CHALLENGE_UNAVAILABLE:${(err as Error).message}`);
      }
      // The first requirement this executor could pay decides; it must match the authorization exactly.
      const candidates = c.offers.filter((o) => o.req.scheme === "exact" && o.req.network === r.network);
      const offer = candidates.find((o) => mismatch(o.req, o.resource, payment) === null);
      if (!offer) throw new PaymentRefusedError(candidates.length ? mismatch(candidates[0]!.req, candidates[0]!.resource, payment)! : "X402_NO_REQUIREMENT_FOR_AUTHORIZED_NETWORK");
      const req = offer.req;

      const t = now();
      const validBefore = Math.min(t + req.maxTimeoutSeconds, payment.authorization_expiry);
      if (validBefore - t < minValidity) throw new PaymentRefusedError("X402_AUTHORIZATION_TOO_CLOSE_TO_EXPIRY");
      const asset = authorizedAsset(network, req.asset);
      const nonce = eip3009NonceForIntent(payment.intent_hash);

      let key: Uint8Array;
      try {
        key = cfg.loadWalletKey();
      } catch (err) {
        throw new PaymentRefusedError(`X402_WALLET_UNAVAILABLE:${(err as Error).message}`);
      }
      const from = addressOfPrivateKey(key);
      // A consumed nonce means this intent already settled (or was canceled) on chain: never sign again.
      // Not a refusal: a payment for this intent may exist, so the outcome must be reconciled.
      let consumed: boolean;
      try {
        consumed = await authorizationConsumed(cfg.rpc, { asset: asset.address, payer: from, nonce });
      } catch (err) {
        key.fill(0);
        throw new PaymentRefusedError(`X402_RPC_UNAVAILABLE_BEFORE_SIGNING:${(err as Error).message}`);
      }
      if (consumed) {
        key.fill(0);
        throw new Error(`X402_NONCE_ALREADY_CONSUMED:payer ${from} nonce ${nonce} (reconcile on chain)`);
      }

      const authorization = {
        from,
        to: r.recipient,
        value: BigInt(req.amount),
        validAfter: BigInt(t - 30),
        validBefore: BigInt(validBefore),
        nonce,
      };
      const domain = { name: asset.eip712Name, version: asset.eip712Version, chainId: network.chainId, verifyingContract: asset.address };
      const signature = signTransferAuthorization(key, domain, authorization);
      key.fill(0);
      const signed = {
        signature,
        authorization: {
          from,
          to: r.recipient,
          value: req.amount,
          validAfter: authorization.validAfter.toString(),
          validBefore: authorization.validBefore.toString(),
          nonce,
        },
      };
      const payload: PaymentPayload | PaymentPayloadV1 =
        offer.version === 2
          ? { x402Version: 2, resource: { url: r.url }, accepted: req, payload: signed }
          : { x402Version: 1, scheme: "exact", network: offer.wireNetwork, payload: signed };
      const [sigHeader, responseHeader] = offer.version === 2 ? [HEADER_PAYMENT_SIGNATURE, HEADER_PAYMENT_RESPONSE] : [HEADER_X_PAYMENT, HEADER_X_PAYMENT_RESPONSE];
      // No payload may leave until both durable stores acknowledge the immutable binding.
      persistBinding({ intent_hash: payment.intent_hash, claim_id: payment.claim_id,
        chain_id: network.chainId.toString(), asset: asset.address, payer: from, recipient: r.recipient,
        amount: authorization.value.toString(), nonce, valid_after: authorization.validAfter.toString(),
        valid_before: authorization.validBefore.toString(), signature });
      const ref = `payer ${from} nonce ${nonce} validBefore ${validBefore}`;
      cfg.log?.({ event: "x402_signed", intent_hash: payment.intent_hash, claim_id: payment.claim_id, from, to: r.recipient, value: req.amount, nonce, valid_before: validBefore });

      // ── After this point the signed authorization is out: every failure is an unknown outcome. ──
      let res: Response;
      let body: string;
      try {
        res = await send(r, { [sigHeader]: encodeHeader(payload) });
        body = (await res.text()).slice(0, MAX_BODY);
      } catch (err) {
        throw new Error(`X402_OUTCOME_UNKNOWN:transport ${(err as Error).name} (${ref})`);
      }
      let settle;
      try {
        settle = parseSettleResponse(decodeHeader(res.headers.get(responseHeader), responseHeader.toUpperCase()));
      } catch (err) {
        throw new Error(`X402_OUTCOME_UNKNOWN:http ${res.status} ${(err as Error).message} (${ref})`);
      }
      const tx = lc(settle.transaction);
      if (!settle.success && settle.errorReason !== "settlement_pending") {
        // The server says it did not settle. Not proof: the signed authorization stays valid until validBefore.
        throw new Error(`X402_NOT_SETTLED_UNCONFIRMED:${settle.errorReason ?? "unknown"} http ${res.status}${tx ? ` tx ${tx}` : ""} (${ref})`);
      }
      if (!HEX32.test(tx)) throw new Error(`X402_OUTCOME_UNKNOWN:no transaction hash (${ref})`);
      const settledOn = offer.version === 1 ? v1NetworkToCaip2(settle.network) : settle.network;
      if (settledOn !== network.caip2) throw new Error(`X402_OUTCOME_UNKNOWN:settlement on ${settle.network} tx ${tx} (${ref})`);
      if (settle.payer !== undefined && lc(settle.payer) !== from) throw new Error(`X402_OUTCOME_UNKNOWN:payer mismatch tx ${tx} (${ref})`);

      // On-chain proof: the receipt must carry exactly this authorization's AuthorizationUsed + Transfer.
      const deadline = Date.now() + (cfg.receiptTimeoutMs ?? 30_000);
      for (;;) {
        let receipt;
        try {
          receipt = await cfg.rpc.receipt(tx);
        } catch (err) {
          receipt = undefined;
          cfg.log?.({ event: "x402_receipt_rpc_error", tx, error: (err as Error).message });
        }
        if (receipt) {
          if (!HEX32.test(receipt.transactionHash.toLowerCase()) || receipt.transactionHash.toLowerCase() !== tx) throw new Error("X402_TX_HASH_MISMATCH");
          if (receipt.status !== 1) throw new Error(`X402_TX_REVERTED:tx ${tx} (the authorization may still settle until validBefore; ${ref})`);
          const value = settlementInReceipt(receipt, { asset: asset.address, payer: from, payTo: r.recipient, nonce });
          if (value === null) throw new Error(`X402_TX_EVIDENCE_MISMATCH:tx ${tx} does not carry this authorization (${ref})`);
          if (value !== BigInt(req.amount)) throw new Error(`X402_TX_AMOUNT_MISMATCH:tx ${tx} value ${value} (${ref})`);
          const receiptOut: PaymentReceipt = {
            settled: true,
            reference: tx,
            network: network.caip2,
            asset: asset.address,
            amount: value.toString(),
            pay_to: r.recipient,
            response_status: res.status,
            response_body: body,
          };
          cfg.log?.({ event: "x402_settled", intent_hash: payment.intent_hash, tx, block: receipt.blockNumber.toString(), explorer: network.explorerTxUrl(tx) });
          return receiptOut;
        }
        if (Date.now() >= deadline) throw new Error(`X402_TX_PENDING:tx ${tx} not mined before the receipt timeout (${ref})`);
        await sleep(cfg.receiptPollMs ?? 1_000);
      }
    },
  };
}

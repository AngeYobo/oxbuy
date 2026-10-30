// SPDX-License-Identifier: MIT
/**
 * Offline stand-in for Celo Sepolia + its x402 facilitator (test-only).
 *
 * SimChain implements the EIP-3009 semantics of FiatToken v2 (Circle USDC) that the executor relies
 * on: signature recovery over the exact EIP-712 domain (name, version, chainId, verifyingContract),
 * validAfter < now < validBefore, one use per (authorizer, nonce), balance, and the Transfer +
 * AuthorizationUsed events. A failing call is mined as a reverted transaction that consumes nothing.
 * It is served over a real HTTP JSON-RPC endpoint so the production RPC client is exercised.
 *
 * SimFacilitator implements x402 v2 `exact` / eip3009 verify + settle against SimChain.
 *
 * What this does NOT prove: anything about the real network, the real facilitator, or the real
 * token contract (see docs/TESTNET-X402.md, NOT_TESTED items).
 */
import { createServer, type Server } from "node:http";
import { addressTopic, decodeWord, hex, keccak, keccakText, recoverTransferAuthorizationSigner, SEL_AUTHORIZATION_STATE, SEL_BALANCE_OF, TOPIC_AUTHORIZATION_USED, TOPIC_TRANSFER, word } from "../../src/chain/evm.ts";
import type { Eip3009Asset, EvmNetwork } from "../../src/chain/networks.ts";
import type { FacilitatorClient } from "../../src/x402/facilitator-client.ts";
import type { PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse } from "../../src/x402/wire.ts";

type Log = { address: string; topics: string[]; data: string };
type Receipt = { transactionHash: string; status: "0x0" | "0x1"; blockNumber: string; to: string; logs: Log[] };

export type SimAuthorization = { from: string; to: string; value: bigint; validAfter: bigint; validBefore: bigint; nonce: string };

export function createSimChain(o: { network: EvmNetwork; asset: Eip3009Asset; now: () => number }) {
  const balances = new Map<string, bigint>();
  const consumed = new Map<string, "used" | "canceled">();
  const receipts = new Map<string, Receipt>();
  const submissions: { hash: string; status: 0 | 1; reason?: string }[] = [];
  let block = 1000n;
  let txCounter = 0;
  const faults = {
    rpcDown: false,
    chainIdOverride: undefined as bigint | undefined,
    /** Receipts are hidden (pending) while true. */
    holdReceipts: false,
    /** The next transferWithAuthorization reverts (consumes nothing). */
    revertNext: false,
  };
  const key = (a: string, n: string) => `${a.toLowerCase()}:${n.toLowerCase()}`;
  const domain = { name: o.asset.eip712Name, version: o.asset.eip712Version, chainId: o.network.chainId, verifyingContract: o.asset.address };

  /** Why this call would revert, or null. */
  function check(a: SimAuthorization, signature: string): string | null {
    const t = BigInt(o.now());
    if (!(t > a.validAfter)) return "FiatTokenV2: authorization is not yet valid";
    if (!(t < a.validBefore)) return "FiatTokenV2: authorization is expired";
    if (consumed.has(key(a.from, a.nonce))) return "FiatTokenV2: authorization is used or canceled";
    let signer: string;
    try {
      signer = recoverTransferAuthorizationSigner(domain, a, signature);
    } catch {
      return "FiatTokenV2: invalid signature";
    }
    if (signer !== a.from.toLowerCase()) return "FiatTokenV2: invalid signature";
    if ((balances.get(a.from.toLowerCase()) ?? 0n) < a.value) return "ERC20: transfer amount exceeds balance";
    return null;
  }

  /** Submit transferWithAuthorization (as any relayer would). Mined immediately. */
  function transferWithAuthorization(a: SimAuthorization, signature: string): { hash: string; status: 0 | 1; reason?: string } {
    const hash = hex(keccakText(`sim-tx-${++txCounter}-${a.nonce}-${signature}`));
    block += 1n;
    let reason = check(a, signature);
    if (reason === null && faults.revertNext) reason = "injected revert";
    faults.revertNext = false;
    if (reason !== null) {
      receipts.set(hash, { transactionHash: hash, status: "0x0", blockNumber: `0x${block.toString(16)}`, to: o.asset.address, logs: [] });
      submissions.push({ hash, status: 0, reason });
      return { hash, status: 0, reason };
    }
    const from = a.from.toLowerCase();
    const to = a.to.toLowerCase();
    balances.set(from, balances.get(from)! - a.value);
    balances.set(to, (balances.get(to) ?? 0n) + a.value);
    consumed.set(key(from, a.nonce), "used");
    const logs: Log[] = [
      { address: o.asset.address, topics: [TOPIC_AUTHORIZATION_USED, addressTopic(from), a.nonce.toLowerCase()], data: "0x" },
      { address: o.asset.address, topics: [TOPIC_TRANSFER, addressTopic(from), addressTopic(to)], data: hex(word(a.value)) },
    ];
    receipts.set(hash, { transactionHash: hash, status: "0x1", blockNumber: `0x${block.toString(16)}`, to: o.asset.address, logs });
    submissions.push({ hash, status: 1 });
    return { hash, status: 1 };
  }

  function rpc(method: string, params: unknown[]): unknown {
    switch (method) {
      case "eth_chainId":
        return `0x${(faults.chainIdOverride ?? o.network.chainId).toString(16)}`;
      case "eth_blockNumber":
        return `0x${block.toString(16)}`;
      case "eth_getTransactionReceipt": {
        const h = String(params[0]).toLowerCase();
        return faults.holdReceipts ? null : (receipts.get(h) ?? null);
      }
      case "eth_call": {
        const c = params[0] as { to: string; data: string };
        if (c.to.toLowerCase() !== o.asset.address) return "0x";
        const data = c.data.toLowerCase();
        if (data.startsWith(SEL_AUTHORIZATION_STATE) && data.length === 2 + 8 + 128) {
          const who = `0x${data.slice(10 + 24, 10 + 64)}`;
          const nonce = `0x${data.slice(10 + 64)}`;
          return hex(word(consumed.has(key(who, nonce)) ? 1n : 0n));
        }
        if (data.startsWith(SEL_BALANCE_OF) && data.length === 2 + 8 + 64) return hex(word(balances.get(`0x${data.slice(10 + 24)}`) ?? 0n));
        throw new Error("unsupported call");
      }
      default:
        throw new Error(`unsupported method ${method}`);
    }
  }

  let server: Server | undefined;
  return {
    asset: o.asset,
    faults,
    balances,
    submissions,
    mint(addr: string, amount: bigint) {
      balances.set(addr.toLowerCase(), (balances.get(addr.toLowerCase()) ?? 0n) + amount);
    },
    balanceOf: (addr: string) => balances.get(addr.toLowerCase()) ?? 0n,
    isConsumed: (addr: string, nonce: string) => consumed.has(key(addr, nonce)),
    /** Payer cancels a nonce (EIP-3009 cancelAuthorization; signature checking elided in the sim). */
    cancel(addr: string, nonce: string) {
      consumed.set(key(addr, nonce), "canceled");
    },
    check,
    transferWithAuthorization,
    /** Successful transfers (Transfer events) — the ground truth of payments. */
    transfers(): { hash: string; from: string; to: string; value: bigint; nonce: string }[] {
      const out = [];
      for (const r of receipts.values()) {
        if (r.status !== "0x1") continue;
        const t = r.logs.find((l) => l.topics[0] === TOPIC_TRANSFER)!;
        const u = r.logs.find((l) => l.topics[0] === TOPIC_AUTHORIZATION_USED)!;
        out.push({ hash: r.transactionHash, from: `0x${t.topics[1]!.slice(26)}`, to: `0x${t.topics[2]!.slice(26)}`, value: decodeWord(t.data), nonce: u.topics[2]! });
      }
      return out;
    },
    async listen(): Promise<string> {
      server = createServer(async (req, res) => {
        if (faults.rpcDown) {
          res.writeHead(503).end();
          return;
        }
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        const m = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: number; method: string; params: unknown[] };
        try {
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: rpc(m.method, m.params) }));
        } catch (err) {
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32000, message: (err as Error).message } }));
        }
      });
      await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
      return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    },
    close: () => new Promise<void>((r) => (server ? server.close(() => r()) : r())),
  };
}

export type SimChain = ReturnType<typeof createSimChain>;

const toAuth = (p: PaymentPayload): SimAuthorization => ({
  from: p.payload.authorization.from,
  to: p.payload.authorization.to,
  value: BigInt(p.payload.authorization.value),
  validAfter: BigInt(p.payload.authorization.validAfter),
  validBefore: BigInt(p.payload.authorization.validBefore),
  nonce: p.payload.authorization.nonce,
});

/** x402 v2 exact/eip3009 facilitator over SimChain, with fault injection. */
export function createSimFacilitator(chain: SimChain, network: EvmNetwork) {
  const faults = {
    /** Broadcast, then answer settlement_pending (receipt not established). */
    pendingAfterBroadcast: false,
    /** Answer success with a transaction hash that is not on chain. */
    lieSuccessUnknownTx: false,
    /** Broadcast, then answer success:false with no transaction (a lying or confused facilitator). */
    broadcastThenDenyBroadcast: false,
    /** Refuse settlement without broadcasting. */
    refuseSettle: undefined as string | undefined,
  };
  const calls = { verify: 0, settle: 0 };
  function verify(p: PaymentPayload, req: PaymentRequirements): VerifyResponse {
    const a = p.payload.authorization;
    if (p.accepted.scheme !== "exact" || req.scheme !== "exact") return { isValid: false, invalidReason: "unsupported_scheme" };
    if (p.accepted.network !== network.caip2 || req.network !== network.caip2) return { isValid: false, invalidReason: "invalid_network" };
    if (a.to.toLowerCase() !== req.payTo.toLowerCase()) return { isValid: false, invalidReason: "invalid_exact_evm_payload_recipient_mismatch" };
    if (a.value !== req.amount) return { isValid: false, invalidReason: "invalid_exact_evm_payload_authorization_value_mismatch" };
    if (req.asset.toLowerCase() !== chain.asset.address || p.accepted.asset.toLowerCase() !== chain.asset.address) return { isValid: false, invalidReason: "invalid_payment_requirements" };
    const why = chain.check(toAuth(p), p.payload.signature);
    if (why !== null) return { isValid: false, invalidReason: /balance/.test(why) ? "insufficient_funds" : /signature/.test(why) ? "invalid_exact_evm_payload_signature" : "invalid_transaction_state", payer: a.from };
    return { isValid: true, payer: a.from };
  }
  const client: FacilitatorClient = {
    async verify(p, req) {
      calls.verify += 1;
      return verify(p, req);
    },
    async settle(p, req): Promise<SettleResponse> {
      calls.settle += 1;
      if (faults.refuseSettle) return { success: false, errorReason: faults.refuseSettle, transaction: "", network: network.caip2 };
      if (faults.lieSuccessUnknownTx) return { success: true, transaction: hex(keccakText(`lie-${calls.settle}`)), network: network.caip2, payer: p.payload.authorization.from };
      const v = verify(p, req);
      if (!v.isValid) return { success: false, errorReason: v.invalidReason, transaction: "", network: network.caip2, payer: p.payload.authorization.from };
      const tx = chain.transferWithAuthorization(toAuth(p), p.payload.signature);
      if (faults.broadcastThenDenyBroadcast) return { success: false, errorReason: "unexpected_settle_error", transaction: "", network: network.caip2 };
      if (faults.pendingAfterBroadcast) return { success: false, errorReason: "settlement_pending", transaction: tx.hash, network: network.caip2, payer: p.payload.authorization.from };
      if (tx.status !== 1) return { success: false, errorReason: "invalid_transaction_state", transaction: tx.hash, network: network.caip2, payer: p.payload.authorization.from };
      return { success: true, transaction: tx.hash, network: network.caip2, payer: p.payload.authorization.from, amount: p.payload.authorization.value };
    },
    async supported() {
      return { kinds: [{ x402Version: 2, scheme: "exact", network: network.caip2 }] };
    },
  };
  return { client, faults, calls };
}

/** keccak re-export for tests that need deterministic fake hashes. */
export { keccak };

/** Serve a FacilitatorClient as an x402 v2 facilitator over HTTP (POST /verify, POST /settle, GET /supported). */
export async function serveFacilitator(client: FacilitatorClient, o: { apiKey?: string } = {}): Promise<{ url: string; close(): Promise<void>; seenKeys: string[] }> {
  const seenKeys: string[] = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const send = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
    if (req.method === "GET" && req.url === "/supported") return send(200, await client.supported());
    const b = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as { x402Version?: number; paymentPayload: PaymentPayload; paymentRequirements: PaymentRequirements };
    if (b.x402Version !== 2) return send(400, { error: "invalid_x402_version" });
    if (req.url === "/verify") return send(200, await client.verify(b.paymentPayload, b.paymentRequirements));
    if (req.url === "/settle") {
      const k = req.headers["x-api-key"];
      seenKeys.push(String(k ?? ""));
      if (o.apiKey !== undefined && k !== o.apiKey) return send(401, { error: "unauthorized" });
      return send(200, await client.settle(b.paymentPayload, b.paymentRequirements));
    }
    send(404, {});
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, close: () => new Promise<void>((r) => server.close(() => r())), seenKeys };
}

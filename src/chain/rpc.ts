// SPDX-License-Identifier: MIT
/**
 * Minimal EVM JSON-RPC client (read-only) used for chain-id checks, receipts and EIP-3009
 * authorization state. It never sends transactions: in x402 `exact` the facilitator broadcasts.
 *
 * Every failure (transport, timeout, malformed answer, JSON-RPC error) throws RpcError. Callers
 * must treat an RpcError after a payment was handed out as "outcome unknown", never as "not paid".
 */
import { ADDRESS, HEX32 } from "./evm.ts";

export class RpcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RpcError";
  }
}

export type RpcLog = { readonly address: string; readonly topics: readonly string[]; readonly data: string };
export type RpcReceipt = {
  readonly transactionHash: string;
  /** 1 success, 0 reverted. */
  readonly status: 0 | 1;
  readonly blockNumber: bigint;
  readonly to: string | null;
  readonly logs: readonly RpcLog[];
};

export interface EvmRpc {
  chainId(): Promise<bigint>;
  blockNumber(): Promise<bigint>;
  /** Null when the node does not know the transaction as mined (pending, dropped, or unknown). */
  receipt(txHash: string): Promise<RpcReceipt | null>;
  call(to: string, data: string): Promise<string>;
}

const QUANTITY = /^0x(0|[1-9a-f][0-9a-f]*)$/;
const DATA = /^0x([0-9a-f]{2})*$/;

function quantity(v: unknown, what: string): bigint {
  if (typeof v !== "string" || !QUANTITY.test(v.toLowerCase())) throw new RpcError(`RPC_MALFORMED:${what}`);
  return BigInt(v);
}

export function parseReceipt(v: unknown): RpcReceipt | null {
  if (v === null) return null;
  if (typeof v !== "object" || Array.isArray(v)) throw new RpcError("RPC_MALFORMED:receipt");
  const r = v as Record<string, unknown>;
  const hash = String(r.transactionHash ?? "").toLowerCase();
  if (!HEX32.test(hash)) throw new RpcError("RPC_MALFORMED:receipt.transactionHash");
  const status = quantity(r.status, "receipt.status");
  if (status !== 0n && status !== 1n) throw new RpcError("RPC_MALFORMED:receipt.status");
  if (!Array.isArray(r.logs)) throw new RpcError("RPC_MALFORMED:receipt.logs");
  const logs = r.logs.map((l: unknown) => {
    const x = (l ?? {}) as Record<string, unknown>;
    const address = String(x.address ?? "").toLowerCase();
    const data = String(x.data ?? "").toLowerCase();
    if (!ADDRESS.test(address) || !DATA.test(data) || !Array.isArray(x.topics)) throw new RpcError("RPC_MALFORMED:receipt.log");
    const topics = x.topics.map((t: unknown) => {
      const s = String(t).toLowerCase();
      if (!HEX32.test(s)) throw new RpcError("RPC_MALFORMED:receipt.log.topic");
      return s;
    });
    return { address, topics, data };
  });
  const to = r.to === null || r.to === undefined ? null : String(r.to).toLowerCase();
  return { transactionHash: hash, status: Number(status) as 0 | 1, blockNumber: quantity(r.blockNumber, "receipt.blockNumber"), to, logs };
}

/** HTTP JSON-RPC over the global fetch, with a per-call timeout. */
export function createHttpRpc(url: string, opts: { timeoutMs?: number; fetch?: typeof fetch } = {}): EvmRpc {
  const f = opts.fetch ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  let id = 0;
  async function rpc(method: string, params: unknown[]): Promise<unknown> {
    const requestId = ++id;
    let res: Response;
    try {
      res = await f(url, {
        method: "POST",
        redirect: "error",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw new RpcError(`RPC_UNAVAILABLE:${method}:${(err as Error).name}`);
    }
    if (!res.ok) throw new RpcError(`RPC_HTTP:${method}:${res.status}`);
    let body: unknown;
    try {
      body = (await res.json()) as typeof body;
    } catch {
      throw new RpcError(`RPC_MALFORMED:${method}:http ${res.status}`);
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new RpcError(`RPC_MALFORMED:${method}:envelope`);
    const b = body as Record<string, unknown>;
    const has = (k: string) => Object.hasOwn(b, k);
    if (b.jsonrpc !== "2.0" || b.id !== requestId || has("result") === has("error")) throw new RpcError(`RPC_MALFORMED:${method}:envelope`);
    if (has("error")) {
      const e = b.error as Record<string, unknown> | null;
      if (!e || typeof e !== "object" || Array.isArray(e) || !Number.isInteger(e.code) || typeof e.message !== "string") throw new RpcError(`RPC_MALFORMED:${method}:error`);
      throw new RpcError(`RPC_ERROR:${method}`);
    }
    return b.result;
  }
  return {
    chainId: async () => quantity(await rpc("eth_chainId", []), "eth_chainId"),
    blockNumber: async () => quantity(await rpc("eth_blockNumber", []), "eth_blockNumber"),
    receipt: async (h) => parseReceipt(await rpc("eth_getTransactionReceipt", [h])),
    async call(to, data) {
      const r = await rpc("eth_call", [{ to, data }, "latest"]);
      if (typeof r !== "string" || !DATA.test(r.toLowerCase())) throw new RpcError("RPC_MALFORMED:eth_call");
      return r.toLowerCase();
    },
  };
}

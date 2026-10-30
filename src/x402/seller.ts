// SPDX-License-Identifier: MIT
/**
 * Minimal x402 v2 resource server ("seller") for the testnet demonstration and the offline tests.
 *
 *   request without PAYMENT-SIGNATURE  -> 402 + PAYMENT-REQUIRED (accepts: the route's requirements)
 *   request with PAYMENT-SIGNATURE     -> `accepted` must equal one of the route's requirements,
 *                                         facilitator /verify, then /settle, then
 *                                         200 + PAYMENT-RESPONSE + resource body   (settled)
 *                                         402 + PAYMENT-RESPONSE (success:false)   (not settled / pending)
 *
 * It is the payee side and holds no payer key. It is NOT part of the OxDeAI trust boundary: the
 * executor checks everything it says against the authorization and against the chain.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { FacilitatorClient } from "./facilitator-client.ts";
import {
  encodeHeader,
  HEADER_PAYMENT_REQUIRED,
  HEADER_PAYMENT_RESPONSE,
  HEADER_PAYMENT_SIGNATURE,
  parsePaymentPayload,
  decodeHeader,
  HEADER_X_PAYMENT,
  HEADER_X_PAYMENT_RESPONSE,
  V1_NETWORKS,
  type PaymentPayload,
  type PaymentRequired,
  type PaymentRequirements,
  type SettleResponse,
} from "./wire.ts";

export type SellerRoute = {
  readonly method: "GET" | "POST";
  /** Path, no query. */
  readonly path: string;
  readonly description?: string;
  readonly requirements: PaymentRequirements;
  /** Resource body returned after settlement. */
  readonly body: (req: { url: string; body: string }) => string;
};

/** Test hooks. Never enabled by the demonstration entry point. */
export type SellerHooks = {
  /** After a successful settlement: "drop" destroys the connection before any answer (lost response). */
  readonly afterSettle?: (s: SettleResponse) => "drop" | void;
  /** Keep the signed payload (a payee can always settle it later, until validBefore). */
  readonly onPayment?: (p: ReturnType<typeof parsePaymentPayload>) => void;
};

export type Seller = {
  readonly server: Server;
  readonly url: string;
  readonly routes: SellerRoute[];
  close(): Promise<void>;
};

const sameRequirements = (a: PaymentRequirements, b: PaymentRequirements) =>
  a.scheme === b.scheme &&
  a.network === b.network &&
  a.amount === b.amount &&
  a.asset.toLowerCase() === b.asset.toLowerCase() &&
  a.payTo.toLowerCase() === b.payTo.toLowerCase() &&
  a.maxTimeoutSeconds === b.maxTimeoutSeconds &&
  JSON.stringify(a.extra ?? {}) === JSON.stringify(b.extra ?? {});

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > 64 * 1024) throw new Error("body too large");
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * `publicOrigin` is the https origin the resource is authorized under (resource.url); the server
 * itself may listen on loopback (the executor maps the origin to it, see X402EvmConfig.endpoints).
 */
export async function startSeller(o: {
  publicOrigin: string;
  routes: SellerRoute[];
  facilitator: FacilitatorClient;
  host?: string;
  port?: number;
  hooks?: SellerHooks;
  log?: (e: Record<string, unknown>) => void;
  /** Wire version (default 2). 1 = JSON 402 body, X-PAYMENT / X-PAYMENT-RESPONSE, short network names (buy gateway). */
  x402Version?: 1 | 2;
}): Promise<Seller> {
  const v1 = o.x402Version === 1;
  const v1Name = (caip2: string) => Object.entries(V1_NETWORKS).find(([, c]) => c === caip2)?.[0] ?? caip2;
  const routes = o.routes;
  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const u = new URL(req.url ?? "/", "http://seller.invalid");
    const route = routes.find((r) => r.method === req.method && r.path === u.pathname);
    if (!route) {
      res.writeHead(404).end();
      return;
    }
    const body = await readBody(req);
    const resourceUrl = `${o.publicOrigin}${u.pathname}${u.search}`;
    const header = req.headers[v1 ? HEADER_X_PAYMENT : HEADER_PAYMENT_SIGNATURE];
    const challenge = (error: string): void => {
      if (v1) {
        const q = route.requirements;
        const accepts = [{ scheme: q.scheme, network: v1Name(q.network), maxAmountRequired: q.amount, asset: q.asset, payTo: q.payTo, resource: resourceUrl, description: route.description ?? "", mimeType: "application/json", maxTimeoutSeconds: q.maxTimeoutSeconds, ...(q.extra ? { extra: q.extra } : {}) }];
        res.writeHead(402, { "content-type": "application/json" }).end(JSON.stringify({ x402Version: 1, error, accepts }));
        return;
      }
      const pr: PaymentRequired = {
        x402Version: 2,
        error,
        resource: { url: resourceUrl, ...(route.description ? { description: route.description } : {}), mimeType: "application/json" },
        accepts: [route.requirements],
      };
      res.writeHead(402, { "content-type": "application/json", [HEADER_PAYMENT_REQUIRED]: encodeHeader(pr) }).end("{}");
    };
    if (typeof header !== "string") return challenge("PAYMENT-SIGNATURE header is required");
    let payload: PaymentPayload;
    try {
      if (v1) {
        const p = decodeHeader(header, "X-PAYMENT") as { x402Version?: unknown; scheme?: unknown; network?: unknown; payload?: PaymentPayload["payload"] };
        if (p.x402Version !== 1 || p.scheme !== route.requirements.scheme || p.network !== v1Name(route.requirements.network) || !p.payload) throw new Error("X402_MALFORMED:v1 payment");
        payload = { x402Version: 2, resource: { url: resourceUrl }, accepted: route.requirements, payload: p.payload };
      } else payload = parsePaymentPayload(header);
    } catch (err) {
      res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: (err as Error).message }));
      return;
    }
    o.hooks?.onPayment?.(payload);
    if (!sameRequirements(payload.accepted, route.requirements)) return challenge("accepted requirements do not match");
    const respHeader = v1 ? HEADER_X_PAYMENT_RESPONSE : HEADER_PAYMENT_RESPONSE;
    const wire = (s: SettleResponse): SettleResponse => (v1 ? { ...s, network: v1Name(s.network) } : s);
    const fail = (s: SettleResponse): void => {
      res.writeHead(402, { "content-type": "application/json", [respHeader]: encodeHeader(wire(s)) }).end("{}");
    };
    const v = await o.facilitator.verify(payload, route.requirements);
    o.log?.({ event: "seller_verify", isValid: v.isValid, invalidReason: v.invalidReason });
    if (!v.isValid) return fail({ success: false, errorReason: v.invalidReason ?? "invalid_payload", transaction: "", network: route.requirements.network, ...(v.payer ? { payer: v.payer } : {}) });
    const s = await o.facilitator.settle(payload, route.requirements);
    o.log?.({ event: "seller_settle", success: s.success, transaction: s.transaction, errorReason: s.errorReason });
    if (s.success && o.hooks?.afterSettle?.(s) === "drop") {
      res.destroy();
      return;
    }
    if (!s.success) return fail(s);
    res.writeHead(200, { "content-type": "application/json", [respHeader]: encodeHeader(wire(s)) }).end(route.body({ url: resourceUrl, body }));
  }
  const server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      o.log?.({ event: "seller_error", error: (err as Error).message });
      if (!res.headersSent) res.writeHead(500).end();
      else res.destroy();
    });
  });
  await new Promise<void>((r) => server.listen(o.port ?? 0, o.host ?? "127.0.0.1", r));
  const addr = server.address() as { port: number };
  return {
    server,
    url: `http://${o.host ?? "127.0.0.1"}:${addr.port}`,
    routes,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

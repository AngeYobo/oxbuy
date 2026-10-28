// SPDX-License-Identifier: MIT
/**
 * Deterministic mock of the `@celo/buy` quote / pay flow.
 *
 * No wallet, no keys, no network, no chain. "Signing" is a counter and the
 * settlement reference is a hash prefixed with "mock-". The ledger and
 * counters exist so tests can prove that a DENY never reached `pay`.
 */
import { createHash } from "node:crypto";
import type { PurchaseRequest } from "../../agent/purchase-request.ts";
import {
  PaymentRefusedError,
  type PaymentAdapter,
  type PaymentQuote,
  type PaymentReceipt,
  type QuoteRequest,
} from "../../executor/payment-adapter.ts";

export type MockService = {
  readonly service_id: string;
  /** Origin + path, no query. */
  readonly resource: string;
  network: string;
  asset: string;
  pay_to: string;
  /** Atomic units. */
  price: bigint;
};

export function createMockBuyAdapter(services: readonly MockService[]) {
  const catalog = new Map(services.map((s) => [s.service_id, { ...s }]));
  const ledger: PaymentReceipt[] = [];
  const counters = { quotes: 0, signatures: 0, payments: 0 };

  function lookup(request: QuoteRequest): MockService {
    const service = catalog.get(request.service_id);
    const u = new URL(request.url);
    if (!service || `${u.origin}${u.pathname}` !== service.resource) throw new Error("MOCK_BUY_UNKNOWN_SERVICE");
    return service;
  }

  function toQuote(service: MockService): PaymentQuote {
    return {
      network: service.network,
      asset: service.asset,
      pay_to: service.pay_to,
      amount: service.price.toString(),
      resource: service.resource,
    };
  }

  const adapter: PaymentAdapter = {
    async quote(request) {
      counters.quotes += 1;
      return toQuote(lookup(request));
    },
    async pay({ request }) {
      let service: MockService;
      try {
        service = lookup(request);
      } catch (err) {
        throw new PaymentRefusedError((err as Error).message);
      }
      // Re-check the live requirements against the authorized binding at the
      // point of payment, not only at the preceding quote.
      if (service.network !== request.network) throw new PaymentRefusedError("MOCK_BUY_NETWORK_MISMATCH");
      if (service.asset !== request.asset) throw new PaymentRefusedError("MOCK_BUY_ASSET_MISMATCH");
      if (service.pay_to.toLowerCase() !== request.recipient) throw new PaymentRefusedError("MOCK_BUY_RECIPIENT_MISMATCH");
      if (service.price > BigInt(request.max_amount)) throw new PaymentRefusedError("MOCK_BUY_PRICE_EXCEEDS_MAX_AMOUNT");
      counters.signatures += 1;
      const digest = createHash("sha256")
        .update(JSON.stringify([request, service.price.toString(), counters.signatures]))
        .digest("hex");
      const receipt: PaymentReceipt = {
        settled: true,
        reference: `mock-${digest.slice(0, 32)}`,
        network: service.network,
        asset: service.asset,
        amount: service.price.toString(),
        pay_to: service.pay_to,
        response_status: 200,
        response_body: JSON.stringify({ mock: true, service_id: service.service_id }),
      };
      counters.payments += 1;
      ledger.push(receipt);
      return receipt;
    },
  };

  return {
    adapter,
    /** Test/operator inspection. Never handed to the agent. */
    inspect: {
      ledger: ledger as readonly PaymentReceipt[],
      counters: counters as Readonly<typeof counters>,
      /** Simulate the upstream changing its price after authorization. */
      setPrice(serviceId: string, price: bigint) {
        const s = catalog.get(serviceId);
        if (!s) throw new Error("unknown service");
        s.price = price;
      },
      /** Simulate the upstream 402 challenge naming a different payee. */
      setPayTo(serviceId: string, payTo: string) {
        const s = catalog.get(serviceId);
        if (!s) throw new Error("unknown service");
        s.pay_to = payTo;
      },
      /** Simulate the upstream 402 challenge naming a different network. */
      setNetwork(serviceId: string, network: string) {
        const s = catalog.get(serviceId);
        if (!s) throw new Error("unknown service");
        s.network = network;
      },
      /** Simulate the upstream 402 challenge naming a different asset. */
      setAsset(serviceId: string, asset: string) {
        const s = catalog.get(serviceId);
        if (!s) throw new Error("unknown service");
        s.asset = asset;
      },
    },
  };
}

export type MockBuy = ReturnType<typeof createMockBuyAdapter>;

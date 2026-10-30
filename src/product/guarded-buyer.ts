// SPDX-License-Identifier: MIT
/**
 * OxDeAI Guarded Buyer: a brand / topic monitoring agent for a small business.
 *
 * The agent decides what to buy; OxDeAI decides whether it may. Every purchase is an exact request (method, URL,
 * body, network, token, recipient, maximum price) that the PDP must authorize against the operator catalog and
 * budget before the executor will sign anything. An out-of-policy purchase (unapproved provider, price above the
 * per-call ceiling, budget exhausted) is denied before any payment.
 */
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { type Catalog, type CatalogService, findService } from "./catalog.ts";
import { buildBrief, extractPosts, type Brief } from "./brief.ts";
import type { GuardedStack } from "./stack.ts";

export type PurchaseAttempt = {
  readonly service_id: string;
  readonly stage: "authorize" | "purchase";
  readonly decision: string;
  readonly reasons?: readonly string[];
  readonly detail?: string;
  readonly final?: boolean;
  readonly tx?: string;
  readonly amount?: string;
  readonly auth_id?: string;
  readonly data?: unknown;
};

/** The exact request for a catalog service; `body` and `query` are agent choices, the rest is fixed by the catalog. */
export function requestFor(s: CatalogService, o: { body?: unknown; query?: Record<string, string> } = {}): PurchaseRequest {
  const u = new URL(s.url);
  for (const [k, v] of Object.entries(o.query ?? {})) u.searchParams.set(k, v);
  return {
    service_id: s.service_id,
    method: s.method,
    url: u.href,
    body: s.method === "POST" ? JSON.stringify(o.body ?? {}) : null,
    network: s.network,
    asset: s.asset,
    recipient: s.pay_to,
    max_amount: s.max_price,
  };
}

export function createGuardedBuyer(stack: GuardedStack, catalog: Catalog, o: { explorer?: (tx: string) => string; now?: () => Date } = {}) {
  /** Authorize, then purchase. Never pays when the PDP denies. */
  async function attempt(request: PurchaseRequest): Promise<PurchaseAttempt> {
    const d = await stack.authorize(request);
    if (d.decision !== "ALLOW") return { service_id: request.service_id, stage: "authorize", decision: "DENY", reasons: d.reasons };
    const r = (await stack.purchase({ request, intent_ref: d.intent_ref, authorization: d.authorization })) as Record<string, any>;
    let data: unknown;
    const rec = r.receipt as { reference?: string; amount?: string; response_body?: string } | undefined;
    if (r.decision === "ALLOW" && typeof rec?.response_body === "string") {
      try {
        data = JSON.parse(rec.response_body);
      } catch {
        data = rec.response_body;
      }
    }
    return {
      service_id: request.service_id,
      stage: "purchase",
      decision: r.decision,
      ...(r.detail !== undefined ? { detail: String(r.detail) } : {}),
      ...(typeof r.final === "boolean" ? { final: r.final } : {}),
      ...(rec?.reference ? { tx: rec.reference } : {}),
      ...(rec?.amount ? { amount: rec.amount } : {}),
      auth_id: d.authorization.auth_id,
      ...(data !== undefined ? { data } : {}),
    };
  }

  return {
    attempt,
    /** Buy one social search for `topic` from catalog service `serviceId`, then build the brief. */
    async brief(topic: string, serviceId: string): Promise<{ brief?: Brief; purchase: PurchaseAttempt }> {
      const s = findService(catalog, serviceId);
      if (!s) throw new Error(`GUARDED_BUYER_UNKNOWN_SERVICE:${serviceId}`);
      const purchase = await attempt(requestFor(s, { body: { query: topic } }));
      if (purchase.decision !== "ALLOW") return { purchase };
      await stack.report();
      const brief = buildBrief({
        topic,
        posts: extractPosts(purchase.data),
        cost: `${purchase.amount} atomic units (${s.asset} on ${s.network}) to ${s.pay_to}`,
        tx: purchase.tx,
        explorer: purchase.tx && o.explorer ? o.explorer(purchase.tx) : undefined,
        at: o.now ? o.now() : new Date(),
      });
      return { brief, purchase: { ...purchase, data: undefined } };
    },
  };
}

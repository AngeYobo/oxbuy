// SPDX-License-Identifier: MIT
/**
 * OxDeAI Guarded Buyer: operator catalog of approved paid services (the only purchases the agent may make).
 *
 * The catalog is operator configuration, never agent input. Each entry fixes, per service: method, exact URL
 * origin + path, network, token, recipient and a maximum price per call. It becomes the OxDeAI policy
 * (allowlisted targets, per-action maximum, budget). Values for a real provider come from its live 402
 * (`npm run x402:probe`) and must be reviewed by a human before use.
 */
import { authorizedAsset, authorizedTestnet } from "../chain/networks.ts";

export type CatalogService = {
  readonly service_id: string;
  readonly method: "GET" | "POST";
  /** https URL; origin + path is the policy target (query and body are bound per purchase). */
  readonly url: string;
  readonly network: string;
  /** Lower-case token address. */
  readonly asset: string;
  /** Lower-case recipient from the provider's 402. */
  readonly pay_to: string;
  /** Atomic token units, the most the agent may pay per call. */
  readonly max_price: string;
  readonly purpose?: string;
};

export type Catalog = {
  readonly network: string;
  /** Atomic units for the budget period of this deployment. */
  readonly budget: string;
  /** Atomic units, ceiling for any single purchase. */
  readonly per_call_max: string;
  readonly services: readonly CatalogService[];
};

const ATOMIC = /^[1-9][0-9]{0,30}$/;
const ADDR = /^0x[0-9a-f]{40}$/;

/** Validate and freeze an operator catalog. Throws CATALOG_INVALID:* (testnet-only: mainnet is refused). */
export function validateCatalog(c: unknown): Catalog {
  const fail = (m: string): never => {
    throw new Error(`CATALOG_INVALID:${m}`);
  };
  if (typeof c !== "object" || c === null) return fail("not an object");
  const k = c as Record<string, unknown>;
  if (typeof k.network !== "string") return fail("network");
  const net = authorizedTestnet(k.network);
  for (const f of ["budget", "per_call_max"] as const) if (typeof k[f] !== "string" || !ATOMIC.test(k[f] as string)) fail(f);
  if (BigInt(k.per_call_max as string) > BigInt(k.budget as string)) fail("per_call_max exceeds budget");
  if (!Array.isArray(k.services) || k.services.length === 0 || k.services.length > 32) return fail("services");
  const ids = new Set<string>();
  const services = (k.services as unknown[]).map((s, i) => {
    if (typeof s !== "object" || s === null) return fail(`services[${i}]`);
    const v = s as Record<string, unknown>;
    if (typeof v.service_id !== "string" || !/^[A-Za-z0-9._:\-]{1,128}$/.test(v.service_id) || ids.has(v.service_id)) fail(`services[${i}].service_id`);
    ids.add(v.service_id as string);
    if (v.method !== "GET" && v.method !== "POST") fail(`services[${i}].method`);
    let u: URL;
    try {
      u = new URL(String(v.url));
    } catch {
      return fail(`services[${i}].url`);
    }
    if (u.protocol !== "https:" || u.username || u.password || u.hash) fail(`services[${i}].url must be plain https`);
    if (v.network !== net.caip2) fail(`services[${i}].network must be ${net.caip2}`);
    if (typeof v.asset !== "string" || !ADDR.test(v.asset)) fail(`services[${i}].asset`);
    authorizedAsset(net, v.asset as string);
    if (typeof v.pay_to !== "string" || !ADDR.test(v.pay_to)) fail(`services[${i}].pay_to`);
    if (typeof v.max_price !== "string" || !ATOMIC.test(v.max_price) || BigInt(v.max_price) > BigInt(k.per_call_max as string)) fail(`services[${i}].max_price`);
    return Object.freeze({
      service_id: v.service_id as string,
      method: v.method as "GET" | "POST",
      url: u.href,
      network: v.network as string,
      asset: v.asset as string,
      pay_to: v.pay_to as string,
      max_price: v.max_price as string,
      ...(typeof v.purpose === "string" ? { purpose: v.purpose } : {}),
    });
  });
  return Object.freeze({ network: net.caip2, budget: k.budget as string, per_call_max: k.per_call_max as string, services: Object.freeze(services) });
}

/** The catalog entry whose URL (origin + path) is `url`, if any. */
export function findService(c: Catalog, id: string): CatalogService | undefined {
  return c.services.find((s) => s.service_id === id);
}

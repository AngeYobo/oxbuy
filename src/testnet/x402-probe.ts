// SPDX-License-Identifier: MIT
/**
 * x402 probe: one UNPAID request, then print the live 402 challenge, normalized (v1 or v2), and whether this
 * executor could pay it on the configured testnet. Never reads a key, never signs, never pays.
 *
 *   npm run x402:probe -- POST https://gateway.usebuy.ai/v1/social/x/posts/search '{"query":"celo"}'
 *
 * Output: the raw challenge, each offer normalized, a ready-to-review OxBuy catalog entry for the offer that
 * matches Celo Sepolia + a configured EIP-3009 token (docs/OXBUY.md §3), and a final verdict:
 *   PROBE PASS  (exit 0): a Sepolia offer this executor can pay exists
 *   PROBE FAIL  (exit 3): no payable Sepolia offer (reason printed); nothing to buy yet
 */
import { authorizedAsset, CELO_SEPOLIA } from "../chain/networks.ts";
import { HEADER_PAYMENT_REQUIRED, decodeHeader, parsePaymentRequired, parsePaymentRequiredV1 } from "../x402/wire.ts";

export async function probe(method: string, url: string, body: string | null, f: typeof fetch = fetch) {
  const res = await f(url, {
    method,
    headers: body !== null ? { "content-type": "application/json" } : {},
    ...(body !== null ? { body } : {}),
    redirect: "manual",
    signal: AbortSignal.timeout(20_000),
  });
  const text = (await res.text()).slice(0, 64 * 1024);
  const header = res.headers.get(HEADER_PAYMENT_REQUIRED);
  const out: Record<string, unknown> = { status: res.status, x402: header ? 2 : undefined };
  if (res.status !== 402) return { ...out, note: "no 402 challenge (free endpoint, wrong method/path, or an error)", body: text.slice(0, 2000) };
  let offers: { network: string; wireNetwork: string; scheme: string; amount: string; asset: string; payTo: string; resource: string; maxTimeoutSeconds: number; extra?: unknown }[];
  if (header) {
    const pr = parsePaymentRequired(header);
    out.raw = decodeHeader(header, "PAYMENT-REQUIRED");
    offers = pr.accepts.map((a) => ({ ...a, wireNetwork: a.network, resource: pr.resource.url }));
  } else {
    const json = JSON.parse(text);
    out.x402 = 1;
    out.raw = json;
    offers = parsePaymentRequiredV1(json).map((o) => ({ ...o.requirements, wireNetwork: o.wireNetwork, resource: o.resource }));
  }
  out.offers = offers.map((o) => {
    let payable = "no";
    let why = "";
    try {
      if (o.network !== CELO_SEPOLIA.caip2) throw new Error(`network ${o.wireNetwork} is not Celo Sepolia (mainnet stays refused until separately approved)`);
      if (o.scheme !== "exact") throw new Error(`scheme ${o.scheme}`);
      const asset = authorizedAsset(CELO_SEPOLIA, o.asset);
      const ex = (o.extra ?? {}) as { name?: unknown; version?: unknown };
      if (ex.name !== asset.eip712Name || ex.version !== asset.eip712Version) throw new Error(`EIP-712 domain ${String(ex.name)}/${String(ex.version)} differs from ${asset.eip712Name}/${asset.eip712Version}`);
      payable = "yes";
    } catch (err) {
      why = (err as Error).message;
    }
    return { ...o, payable_on_sepolia: payable, ...(why ? { why } : {}) };
  });
  const ok = (out.offers as { payable_on_sepolia: string }[]).find((o) => o.payable_on_sepolia === "yes") as (typeof offers)[number] | undefined;
  if (ok) {
    const u = new URL(url);
    out.catalog_entry = {
      service_id: `${u.hostname}${u.pathname}`.replace(/[^a-z0-9._:-]/gi, "-").slice(0, 100),
      method,
      url,
      network: ok.network,
      asset: ok.asset.toLowerCase(),
      pay_to: ok.payTo.toLowerCase(),
      max_price: ok.amount,
      note: "review before use: recipient and price come from the provider's live 402",
    };
  }
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [method, url, body] = process.argv.slice(2);
  if (!method || !url) {
    process.stderr.write("usage: x402:probe -- <GET|POST> <url> [json-body]\n");
    process.exit(2);
  }
  probe(method.toUpperCase(), url, body ?? null)
    .then((r) => {
      process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
      const offers = (r as { offers?: { payable_on_sepolia: string; why?: string; wireNetwork: string }[] }).offers ?? [];
      if ((r as { catalog_entry?: unknown }).catalog_entry) {
        process.stdout.write("PROBE PASS: payable Celo Sepolia offer found (review catalog_entry before use)\n");
      } else {
        const reasons = offers.map((o) => `${o.wireNetwork}: ${o.why ?? "not payable"}`).join("; ") || (r as { note?: string }).note || "no offers";
        process.stdout.write(`PROBE FAIL: no payable Celo Sepolia offer (${reasons})\n`);
        process.exitCode = 3;
      }
    })
    .catch((err) => {
      process.stderr.write(`${(err as Error).message}\n`);
      process.exit(1);
    });
}

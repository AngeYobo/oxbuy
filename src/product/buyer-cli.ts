// SPDX-License-Identifier: MIT
/**
 * OxBuy demo: an AI purchasing agent whose purchases are authorized by OxDeAI (Celo Sepolia only; mainnet is
 * refused until separately approved).
 *
 *   npm run oxbuy -- --catalog <catalog.json> --topic "<brand or topic>" [--service <id>] [--deny-demo]
 *   (`npm run buyer` is kept as an alias)
 *
 * Environment: OXDEAI_TESTNET_PAYER_KEY_FILE (0600 testnet key), optional OXDEAI_TESTNET_RPC_URL,
 * OXDEAI_BUYER_STATE_DIR (default ~/.oxdeai/oxbuy; one sub-directory per run, keep it private: it holds
 * the signed payments, XR-04), OXDEAI_BUYER_EVIDENCE_DIR (default evidence/oxbuy).
 *
 * --deny-demo adds a purchase the policy does not allow (a provider endpoint absent from the catalog) and shows
 * that it is denied before any signature or payment.
 */
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { authorizedNetwork, CELO_MAINNET, CELO_SEPOLIA, MAINNET_APPROVAL } from "../chain/networks.ts";
import { parsePrivateKey } from "../chain/evm.ts";
import { createHttpRpc } from "../chain/rpc.ts";
import { validateCatalog } from "./catalog.ts";
import { createGuardedBuyer, requestFor } from "./guarded-buyer.ts";
import { createGuardedStack } from "./stack.ts";

export async function runBuyer(argv: string[], env: NodeJS.ProcessEnv = process.env, out: (l: string) => void = (l) => process.stdout.write(`${l}\n`), extra: { fetch?: typeof fetch; endpoints?: Record<string, string> } = {}) {
  const arg = (name: string) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const catalogPath = arg("catalog");
  const topic = arg("topic");
  if (!catalogPath || !topic) throw new Error("usage: oxbuy -- --catalog <file> --topic <topic> [--service <id>] [--deny-demo]");
  const rawCatalog = JSON.parse(readFileSync(catalogPath, "utf8"));
  const mainnet = rawCatalog.network === CELO_MAINNET.caip2;
  if (mainnet && (!argv.includes("--mainnet") || env.OXDEAI_ENABLE_CELO_MAINNET !== MAINNET_APPROVAL))
    throw new Error("BUYER_MAINNET_NOT_APPROVED:requires --mainnet and OXDEAI_ENABLE_CELO_MAINNET=I_ACCEPT_REAL_MONEY_RISK");
  const catalog = validateCatalog(rawCatalog);
  const network = authorizedNetwork(catalog.network);
  if (mainnet && (catalog.budget !== "5000" || catalog.per_call_max !== "5000" ||
      catalog.services.length !== 1 || catalog.services[0]?.asset !== CELO_MAINNET.assets[0]?.address ||
      catalog.services[0]?.pay_to !== "0x20faaca5f980e29639a0fcc6dca6988e18ed333b" ||
      catalog.services[0]?.url !== "https://gateway.usebuy.ai/v1/social/x/posts/search" ||
      catalog.services[0]?.method !== "POST" || catalog.services[0]?.max_price !== "5000"))
    throw new Error("BUYER_MAINNET_PROFILE_MISMATCH");
  const serviceId = arg("service") ?? catalog.services[0]!.service_id;
  const keyFile = mainnet ? env.OXDEAI_MAINNET_PAYER_KEY_FILE : env.OXDEAI_TESTNET_PAYER_KEY_FILE;
  if (!keyFile) throw new Error(`set ${mainnet ? "OXDEAI_MAINNET_PAYER_KEY_FILE" : "OXDEAI_TESTNET_PAYER_KEY_FILE"} (0600)`);
  if ((statSync(keyFile).mode & 0o077) !== 0) throw new Error(`${keyFile} must be mode 0600`);
  const rpc = createHttpRpc((mainnet ? env.OXDEAI_MAINNET_RPC_URL : env.OXDEAI_TESTNET_RPC_URL) ?? network.defaultRpcUrl, { timeoutMs: 15_000 });
  const chainId = await rpc.chainId();
  if (chainId !== network.chainId) throw new Error(`BUYER_WRONG_CHAIN:${chainId}; expected ${network.chainId}`);

  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const events: Record<string, unknown>[] = [];
  const stack = createGuardedStack({
    catalog,
    rpc,
    loadWalletKey: () => parsePrivateKey(readFileSync(keyFile, "utf8")),
    // One journal per run, matching the per-run (in-memory) policy state and budget.
    stateDir: resolve(env.OXDEAI_BUYER_STATE_DIR ?? join(homedir(), ".oxdeai", "oxbuy"), runId),
    fetch: extra.fetch,
    endpoints: extra.endpoints,
    log: (e) => events.push(e),
  });
  const buyer = createGuardedBuyer(stack, catalog, { explorer: network.explorerTxUrl });
  const results: Record<string, unknown> = {};
  try {
    out(`OxBuy · purchases authorized by OxDeAI · topic "${topic}" · service ${serviceId} · budget ${catalog.budget} · per call ≤ ${catalog.per_call_max}`);
    const r = await buyer.brief(topic, serviceId);
    results.authorized = r.purchase;
    out(`authorized purchase: ${r.purchase.decision}${r.purchase.tx ? ` · tx ${r.purchase.tx} · ${network.explorerTxUrl(r.purchase.tx)}` : ""}${r.purchase.detail ? ` · ${r.purchase.detail}` : ""}`);
    if (r.brief) {
      out("");
      out(r.brief.markdown);
      results.brief = r.brief.markdown;
    }
    if (argv.includes("--deny-demo")) {
      const s = catalog.services.find((x) => x.service_id === serviceId)!;
      // The agent tries a provider endpoint the operator never approved (same gateway, same recipient, same price).
      const u = new URL(s.url);
      u.pathname = "/v1/social/linkedin/profile";
      const denied = await buyer.attempt({ ...requestFor(s, { body: { query: topic } }), service_id: "unapproved-linkedin", url: u.href });
      results.denied = denied;
      out(`unapproved purchase: ${denied.decision} at ${denied.stage}${denied.reasons ? ` · ${denied.reasons.join(",")}` : ""} · nothing signed or paid`);
    }
    results.spent = (await stack.spent()).toString();
    out(`budget spent: ${results.spent} of ${catalog.budget}`);
  } finally {
    stack.close();
  }
  const dir = resolve(env.OXDEAI_BUYER_EVIDENCE_DIR ?? "evidence/oxbuy", runId);
  mkdirSync(dir, { recursive: true });
  const evidence = { schema: "oxbuy/evidence/v1", topic, service: serviceId, network: catalog.network, results, adapter_events: events };
  writeFileSync(join(dir, "evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`);
  out(`evidence: ${join(dir, "evidence.json")}`);
  return evidence;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runBuyer(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  });
}

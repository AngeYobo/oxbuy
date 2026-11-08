// SPDX-License-Identifier: MIT
/**
 * OxBuy web app: the playground (simulated chain, real OxDeAI + x402 code) and, when enabled, a capped live
 * purchase through the same code path as `npm run oxbuy`.
 *
 *   node src/web/server.ts                      # PORT (default 3000)
 *
 * Live purchases are OFF unless OXBUY_LIVE=1. OXBUY_LIVE_NETWORK selects the network (default testnet).
 *
 * Testnet (Celo Sepolia):
 *   OXBUY_PAYER_KEY            testnet payer key (hex), written to a private 0600 file at start;
 *                              or OXDEAI_TESTNET_PAYER_KEY_FILE (an existing 0600 file)
 *   OXBUY_CATALOG_FILE         operator catalog (default config/usebuy-celo-sepolia.json)
 *   OXBUY_CATALOG_JSON         or the catalog itself, inline (takes precedence)
 *   OXBUY_LIVE_MAX_PURCHASES   purchases per server process (default 10)
 *   OXBUY_LIVE_PER_CLIENT      purchases per client per server process (default 2)
 *   OXDEAI_TESTNET_RPC_URL     optional RPC override
 *
 * Mainnet (Celo, real money). The server refuses to start unless ALL of these hold:
 *   OXBUY_LIVE_NETWORK=mainnet
 *   OXDEAI_ENABLE_CELO_MAINNET=I_ACCEPT_REAL_MONEY_RISK   (in the process environment)
 *   OXBUY_MAINNET_PAYER_KEY    key (hex) of a DEDICATED hot wallet, or OXDEAI_MAINNET_PAYER_KEY_FILE (0600);
 *                              OXBUY_PAYER_KEY must not be set (no testnet/mainnet key confusion)
 *   OXBUY_LIVE_MAX_PURCHASES   set explicitly, 1 to 50
 *   no OXBUY_CATALOG_FILE / OXBUY_CATALOG_JSON: the catalog is pinned to config/usebuy-celo-mainnet.json, and
 *   runBuyer pins its profile (one service, recipient, token, price 0.005 USDC, budget one call per run)
 * At run time, mainnet adds: one purchase per OXBUY_LIVE_COOLDOWN_SECONDS (default 60, at least 30) across all
 * visitors, OXBUY_LIVE_PER_CLIENT at most 2 (default 1), an explicit confirmation from the visitor, and an
 * on-chain balance check before each purchase (fails closed if the RPC does not answer).
 *
 * The in-memory counters reset when the server restarts. The durable cap is the wallet balance: fund the
 * dedicated wallet with only what you accept to spend.
 *
 * Security limits (same as the CLI): the live path runs the agent, PDP, gateway, executor and wallet key in this
 * one process (createGuardedStack). It is not the process-isolated deployment (src/isolation/).
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { addressOfPrivateKey, decodeWord, encodeBalanceOf, parsePrivateKey } from "../chain/evm.ts";
import { CELO_MAINNET, CELO_SEPOLIA, MAINNET_APPROVAL, type EvmNetwork } from "../chain/networks.ts";
import { createHttpRpc, type EvmRpc } from "../chain/rpc.ts";
import { runBuyer } from "../product/buyer-cli.ts";
import { validateCatalog, type Catalog } from "../product/catalog.ts";
import { runScenario, SCENARIOS } from "./scenarios.ts";

const ROOT = resolve(import.meta.dirname, "../..");
const STATIC: Record<string, { file: string; type: string }> = {
  "/": { file: "web/index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "web/app.js", type: "text/javascript; charset=utf-8" },
  "/style.css": { file: "web/style.css", type: "text/css; charset=utf-8" },
  "/logo.png": { file: "web/logo.png", type: "image/png" },
  "/agent-registration.json": { file: "web/agent-registration.json", type: "application/json; charset=utf-8" },
  "/favicon.png": { file: "web/favicon.png", type: "image/png" },
  "/apple-touch-icon.png": { file: "web/apple-touch-icon.png", type: "image/png" },
};
const CSP = [
  "default-src 'self'",
  "style-src 'self' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");
const TOPIC = /^[\p{L}\p{N} .,'#@&+-]{2,60}$/u;
const MAINNET_CATALOG = "config/usebuy-celo-mainnet.json";
const MAINNET_MAX_PURCHASES = 50;

export type LiveConfig =
  | { enabled: false; why: string }
  | {
      enabled: true;
      mainnet: boolean;
      network: EvmNetwork;
      catalog: Catalog;
      catalogFile: string;
      service: string;
      wallet: string;
      asset: string;
      price: bigint;
      maxPurchases: number;
      perClient: number;
      cooldownSeconds: number;
      /** For the pre-purchase balance check (mainnet). */
      rpc?: EvmRpc;
      argv: string[];
      env: NodeJS.ProcessEnv;
    };

function int(v: string | undefined, d: number, min = 0, max = Number.MAX_SAFE_INTEGER, name = "value"): number {
  const n = Number(v ?? d);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new Error(`WEB_CONFIG_INVALID:${name}=${v} (${min}..${max})`);
  return n;
}

function privateKeyFile(hex: string): string {
  const dir = mkdtempSync(join(tmpdir(), "oxbuy-key-"));
  chmodSync(dir, 0o700);
  const f = join(dir, "payer.key");
  writeFileSync(f, hex.trim(), { mode: 0o600 });
  return f;
}

export function liveConfig(env: NodeJS.ProcessEnv): LiveConfig {
  if (env.OXBUY_LIVE !== "1") return { enabled: false, why: "Live purchases are turned off on this server." };
  const net = env.OXBUY_LIVE_NETWORK ?? "testnet";
  if (net !== "testnet" && net !== "mainnet") throw new Error(`WEB_CONFIG_INVALID:OXBUY_LIVE_NETWORK=${net}`);
  const mainnet = net === "mainnet";
  const state = {
    OXDEAI_BUYER_STATE_DIR: env.OXDEAI_BUYER_STATE_DIR ?? join(tmpdir(), "oxbuy-state"),
    OXDEAI_BUYER_EVIDENCE_DIR: env.OXDEAI_BUYER_EVIDENCE_DIR ?? join(tmpdir(), "oxbuy-evidence"),
  };

  let catalogFile: string;
  let keyFile: string | undefined;
  let runEnv: NodeJS.ProcessEnv;
  if (mainnet) {
    // Both the given environment and the process environment: the network code reads the process one.
    if (env.OXDEAI_ENABLE_CELO_MAINNET !== MAINNET_APPROVAL || process.env.OXDEAI_ENABLE_CELO_MAINNET !== MAINNET_APPROVAL)
      throw new Error(`WEB_MAINNET_NOT_APPROVED:set OXDEAI_ENABLE_CELO_MAINNET=${MAINNET_APPROVAL}`);
    if (env.OXBUY_CATALOG_FILE || env.OXBUY_CATALOG_JSON) throw new Error(`WEB_MAINNET_CATALOG_PINNED:remove OXBUY_CATALOG_FILE/OXBUY_CATALOG_JSON (${MAINNET_CATALOG} is used)`);
    if (env.OXBUY_PAYER_KEY) throw new Error("WEB_MAINNET_KEY_AMBIGUOUS:OXBUY_PAYER_KEY is the testnet key; use OXBUY_MAINNET_PAYER_KEY");
    if (env.OXBUY_LIVE_MAX_PURCHASES === undefined) throw new Error(`WEB_MAINNET_CAP_REQUIRED:set OXBUY_LIVE_MAX_PURCHASES (1..${MAINNET_MAX_PURCHASES})`);
    catalogFile = resolve(ROOT, MAINNET_CATALOG);
    keyFile = env.OXBUY_MAINNET_PAYER_KEY ? privateKeyFile(env.OXBUY_MAINNET_PAYER_KEY) : env.OXDEAI_MAINNET_PAYER_KEY_FILE;
    if (!keyFile) throw new Error("WEB_CONFIG_INVALID:set OXBUY_MAINNET_PAYER_KEY or OXDEAI_MAINNET_PAYER_KEY_FILE");
    runEnv = {
      ...state,
      OXDEAI_MAINNET_PAYER_KEY_FILE: keyFile,
      OXDEAI_ENABLE_CELO_MAINNET: MAINNET_APPROVAL,
      ...(env.OXDEAI_MAINNET_RPC_URL ? { OXDEAI_MAINNET_RPC_URL: env.OXDEAI_MAINNET_RPC_URL } : {}),
    };
  } else {
    if (env.OXBUY_MAINNET_PAYER_KEY) throw new Error("WEB_CONFIG_INVALID:OXBUY_MAINNET_PAYER_KEY is set but OXBUY_LIVE_NETWORK is not mainnet");
    catalogFile = resolve(ROOT, env.OXBUY_CATALOG_FILE ?? "config/usebuy-celo-sepolia.json");
    if (env.OXBUY_CATALOG_JSON) {
      // Catalog passed inline (hosting without the file in the repository): validated, then written privately.
      validateCatalog(JSON.parse(env.OXBUY_CATALOG_JSON));
      catalogFile = join(mkdtempSync(join(tmpdir(), "oxbuy-catalog-")), "catalog.json");
      writeFileSync(catalogFile, env.OXBUY_CATALOG_JSON, { mode: 0o600 });
    }
    keyFile = env.OXBUY_PAYER_KEY ? privateKeyFile(env.OXBUY_PAYER_KEY) : env.OXDEAI_TESTNET_PAYER_KEY_FILE;
    if (!keyFile) throw new Error("WEB_CONFIG_INVALID:set OXBUY_PAYER_KEY or OXDEAI_TESTNET_PAYER_KEY_FILE");
    runEnv = {
      ...state,
      OXDEAI_TESTNET_PAYER_KEY_FILE: keyFile,
      ...(env.OXDEAI_TESTNET_RPC_URL ? { OXDEAI_TESTNET_RPC_URL: env.OXDEAI_TESTNET_RPC_URL } : {}),
    };
  }

  const catalog = validateCatalog(JSON.parse(readFileSync(catalogFile, "utf8")));
  const network = mainnet ? CELO_MAINNET : CELO_SEPOLIA;
  if (catalog.network !== network.caip2) throw new Error(`WEB_CONFIG_INVALID:catalog network ${catalog.network} is not ${network.caip2}`);
  const service = env.OXBUY_LIVE_SERVICE ?? catalog.services[0]!.service_id;
  const s = catalog.services.find((x) => x.service_id === service);
  if (!s) throw new Error(`WEB_CONFIG_INVALID:OXBUY_LIVE_SERVICE ${service}`);
  const wallet = addressOfPrivateKey(parsePrivateKey(readFileSync(keyFile, "utf8")));
  const rpcUrl = mainnet ? env.OXDEAI_MAINNET_RPC_URL : env.OXDEAI_TESTNET_RPC_URL;
  return {
    enabled: true,
    mainnet,
    network,
    catalog,
    catalogFile,
    service,
    wallet,
    asset: s.asset,
    price: BigInt(s.max_price),
    maxPurchases: mainnet
      ? int(env.OXBUY_LIVE_MAX_PURCHASES, 0, 1, MAINNET_MAX_PURCHASES, "OXBUY_LIVE_MAX_PURCHASES")
      : int(env.OXBUY_LIVE_MAX_PURCHASES, 10, 0, 10_000, "OXBUY_LIVE_MAX_PURCHASES"),
    perClient: mainnet ? int(env.OXBUY_LIVE_PER_CLIENT, 1, 1, 2, "OXBUY_LIVE_PER_CLIENT") : int(env.OXBUY_LIVE_PER_CLIENT, 2, 0, 1_000, "OXBUY_LIVE_PER_CLIENT"),
    cooldownSeconds: mainnet ? int(env.OXBUY_LIVE_COOLDOWN_SECONDS, 60, 30, 86_400, "OXBUY_LIVE_COOLDOWN_SECONDS") : int(env.OXBUY_LIVE_COOLDOWN_SECONDS, 0, 0, 86_400, "OXBUY_LIVE_COOLDOWN_SECONDS"),
    ...(mainnet ? { rpc: createHttpRpc(rpcUrl ?? network.defaultRpcUrl, { timeoutMs: 10_000 }) } : {}),
    argv: ["--catalog", catalogFile, "--service", service, ...(mainnet ? ["--mainnet"] : [])],
    env: runEnv,
  };
}

type Extra = Parameters<typeof runBuyer>[3];

export function createApp(o: { live: LiveConfig; extra?: Extra; commit?: string }) {
  const live = o.live;
  let purchases = 0;
  let liveBusy = false;
  let scenariosRunning = 0;
  let lastLiveAt = 0;
  const perClient = new Map<string, number>();
  const recent: { tx: string; txUrl: string; topic: string; at: string }[] = [];
  const hits = new Map<string, { n: number; t: number }>();

  /**
   * Client identity for the per-client caps: the right-most X-Forwarded-For entry, the one appended by the
   * hosting proxy (the left-most is whatever the client sent). The global caps do not depend on it.
   */
  const client = (req: IncomingMessage) => String(req.headers["x-forwarded-for"] ?? req.socket.remoteAddress ?? "?").split(",").pop()!.trim();
  const cooldownLeft = () => (live.enabled ? Math.max(0, Math.ceil(lastLiveAt / 1000 + live.cooldownSeconds - Date.now() / 1000)) : 0);
  /** 40 API calls per client per minute. */
  function limited(ip: string): boolean {
    const now = Date.now();
    const h = hits.get(ip);
    if (!h || now - h.t > 60_000) {
      hits.set(ip, { n: 1, t: now });
      return false;
    }
    h.n += 1;
    return h.n > 40;
  }

  function send(res: ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  }

  async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
    let size = 0;
    const chunks: Buffer[] = [];
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > 2048) throw new Error("BODY_TOO_LARGE");
      chunks.push(c as Buffer);
    }
    const v = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("BODY_NOT_OBJECT");
    return v as Record<string, unknown>;
  }

  function status() {
    const base = { commit: o.commit ?? null, scenarios: SCENARIOS, recent };
    if (!live.enabled) return { ...base, live: { enabled: false, why: live.why } };
    const s = live.catalog.services.find((x) => x.service_id === live.service)!;
    const explorer = live.mainnet ? "https://celo.blockscout.com" : "https://celo-sepolia.blockscout.com";
    return {
      ...base,
      live: {
        enabled: true,
        mainnet: live.mainnet,
        network: live.network.name,
        wallet: live.wallet,
        walletUrl: `${explorer}/address/${live.wallet}`,
        service: s.service_id,
        purpose: s.purpose ?? null,
        price: s.max_price,
        remaining: Math.max(0, live.maxPurchases - purchases),
        perClient: live.perClient,
        cooldownSeconds: live.cooldownSeconds,
        cooldownLeft: cooldownLeft(),
        requiresConfirmation: live.mainnet,
        busy: liveBusy,
      },
    };
  }

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? "/", "http://local");
    const st = STATIC[url.pathname];
    if (req.method === "GET" && st) {
      res.writeHead(200, { "content-type": st.type, "content-security-policy": CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cache-control": "no-cache" });
      res.end(readFileSync(join(ROOT, st.file)));
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/health") return send(res, 200, { ok: true });
    if (!url.pathname.startsWith("/api/")) return send(res, 404, { error: "Not found." });
    const ip = client(req);
    if (limited(ip)) return send(res, 429, { error: "Too many requests. Wait a minute and try again." });
    if (req.method === "GET" && url.pathname === "/api/status") return send(res, 200, status());

    if (req.method === "POST" && url.pathname === "/api/scenario") {
      const body = await readJson(req);
      const id = String(body.id ?? "");
      if (!SCENARIOS.some((s) => s.id === id)) return send(res, 400, { error: `Unknown scenario "${id}".` });
      if (scenariosRunning >= 4) return send(res, 429, { error: "The server is busy running other scenarios. Try again in a few seconds." });
      scenariosRunning += 1;
      try {
        return send(res, 200, await runScenario(id));
      } finally {
        scenariosRunning -= 1;
      }
    }

    if (req.method === "POST" && url.pathname === "/api/live") {
      if (!live.enabled) return send(res, 403, { error: live.why });
      const body = await readJson(req);
      const topic = String(body.topic ?? "").trim();
      if (!TOPIC.test(topic)) return send(res, 400, { error: "Use 2 to 60 letters, digits, spaces or . , ' # @ & + -" });
      if (live.mainnet && body.confirm !== true) return send(res, 400, { error: "Confirm that this purchase spends real USDC on Celo mainnet." });
      if (purchases >= live.maxPurchases) return send(res, 409, { error: "The live purchase allowance for this server is used up. The playground still works." });
      if ((perClient.get(ip) ?? 0) >= live.perClient) return send(res, 409, { error: `You have made ${live.perClient} live purchase${live.perClient === 1 ? "" : "s"} already. The playground still works.` });
      if (liveBusy) return send(res, 409, { error: "Another live purchase is running. Try again in a few seconds." });
      const wait = cooldownLeft();
      if (wait > 0) return send(res, 429, { error: `One live purchase per ${live.cooldownSeconds} seconds across all visitors. Try again in ${wait} s.` });
      liveBusy = true;
      try {
        if (live.rpc) {
          // On-chain balance check before anything is authorized; fails closed when the RPC does not answer.
          let balance: bigint;
          try {
            balance = decodeWord(await live.rpc.call(live.asset, encodeBalanceOf(live.wallet)));
          } catch {
            return send(res, 503, { error: "The wallet balance could not be checked, so nothing was bought. Try again in a minute." });
          }
          if (balance < live.price) return send(res, 409, { error: "The demo wallet has no funds left for another purchase. The playground still works." });
        }
        purchases += 1;
        perClient.set(ip, (perClient.get(ip) ?? 0) + 1);
        lastLiveAt = Date.now();
        const ev = (await runBuyer([...live.argv, "--topic", topic], live.env, () => {}, o.extra ?? {})) as {
          results: { authorized?: { decision?: string; tx?: string; detail?: string; amount?: string }; brief?: string; spent?: string };
        };
        const a = ev.results.authorized ?? {};
        if (a.decision === "ALLOW" && a.tx) recent.unshift({ tx: a.tx, txUrl: live.network.explorerTxUrl(a.tx), topic, at: new Date().toISOString() });
        recent.splice(5);
        if (a.decision === "DENY") {
          // Refused before any signature: nothing was paid, so the allowance is given back. Any other outcome
          // (ALLOW, INDETERMINATE, an error) keeps it used: money may have moved.
          purchases -= 1;
          perClient.set(ip, (perClient.get(ip) ?? 1) - 1);
          lastLiveAt = 0;
        }
        return send(res, 200, {
          decision: a.decision ?? "DENY",
          network: live.network.name,
          ...(a.tx ? { tx: a.tx, txUrl: live.network.explorerTxUrl(a.tx) } : {}),
          ...(a.detail ? { reason: a.detail } : {}),
          amount: a.amount ?? null,
          brief: ev.results.brief ?? null,
          remaining: Math.max(0, live.maxPurchases - purchases),
        });
      } catch (err) {
        return send(res, 502, { error: `The live purchase did not complete: ${String((err as Error).message).slice(0, 240)}` });
      } finally {
        liveBusy = false;
      }
    }
    return send(res, 404, { error: "Not found." });
  }

  return createServer((req, res) => {
    handle(req, res).catch((err) => {
      if (!res.headersSent) send(res, 400, { error: String((err as Error).message).slice(0, 200) });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const live = liveConfig(process.env);
  const port = Number(process.env.PORT ?? 3000);
  createApp({ live, commit: process.env.RENDER_GIT_COMMIT?.slice(0, 7) }).listen(port, () => {
    process.stdout.write(`OxBuy web on :${port}, live purchases ${live.enabled ? `ON on ${live.network.name} (${live.wallet}, ${live.maxPurchases} max)` : "OFF"}\n`);
  });
}

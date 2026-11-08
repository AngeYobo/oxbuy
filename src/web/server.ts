// SPDX-License-Identifier: MIT
/**
 * OxBuy web app: the playground (simulated chain, real OxDeAI + x402 code) and, when enabled, a capped live
 * purchase on Celo Sepolia through the same code path as `npm run oxbuy`.
 *
 *   node src/web/server.ts                      # PORT (default 3000)
 *
 * Live purchases are OFF unless OXBUY_LIVE=1. Then:
 *   OXBUY_PAYER_KEY            testnet payer key (hex), written to a private 0600 file at start;
 *                              or OXDEAI_TESTNET_PAYER_KEY_FILE (an existing 0600 file)
 *   OXBUY_CATALOG_FILE         operator catalog (default config/usebuy-celo-sepolia.json)
 *   OXBUY_CATALOG_JSON         or the catalog itself, inline (takes precedence)
 *   OXBUY_LIVE_SERVICE         catalog service_id (default: the first service)
 *   OXBUY_LIVE_MAX_PURCHASES   purchases per server process (default 10)
 *   OXBUY_LIVE_PER_CLIENT      purchases per client IP per server process (default 2)
 *   OXDEAI_TESTNET_RPC_URL     optional RPC override
 * The durable cap is the wallet balance: fund a dedicated demo wallet with only what you accept to spend.
 *
 * Security limits (same as the CLI): the live path runs the agent, PDP, gateway, executor and wallet key in this
 * one process (createGuardedStack). It is not the process-isolated deployment (src/isolation/).
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { addressOfPrivateKey, parsePrivateKey } from "../chain/evm.ts";
import { CELO_SEPOLIA } from "../chain/networks.ts";
import { runBuyer } from "../product/buyer-cli.ts";
import { validateCatalog, type Catalog } from "../product/catalog.ts";
import { runScenario, SCENARIOS } from "./scenarios.ts";

const ROOT = resolve(import.meta.dirname, "../..");
const STATIC: Record<string, { file: string; type: string }> = {
  "/": { file: "web/index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "web/app.js", type: "text/javascript; charset=utf-8" },
  "/style.css": { file: "web/style.css", type: "text/css; charset=utf-8" },
  "/logo.png": { file: "web/logo.png", type: "image/png" },
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

export type LiveConfig =
  | { enabled: false; why: string }
  | {
      enabled: true;
      catalog: Catalog;
      catalogFile: string;
      service: string;
      keyFile: string;
      wallet: string;
      maxPurchases: number;
      perClient: number;
      env: NodeJS.ProcessEnv;
    };

function int(v: string | undefined, d: number): number {
  const n = Number(v ?? d);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`WEB_CONFIG_INVALID:${v}`);
  return n;
}

export function liveConfig(env: NodeJS.ProcessEnv): LiveConfig {
  if (env.OXBUY_LIVE !== "1") return { enabled: false, why: "Live purchases are turned off on this server." };
  let catalogFile = resolve(ROOT, env.OXBUY_CATALOG_FILE ?? "config/usebuy-celo-sepolia.json");
  if (env.OXBUY_CATALOG_JSON) {
    // Catalog passed inline (hosting without the file in the repository): validated, then written privately.
    validateCatalog(JSON.parse(env.OXBUY_CATALOG_JSON));
    catalogFile = join(mkdtempSync(join(tmpdir(), "oxbuy-catalog-")), "catalog.json");
    writeFileSync(catalogFile, env.OXBUY_CATALOG_JSON, { mode: 0o600 });
  }
  const catalog = validateCatalog(JSON.parse(readFileSync(catalogFile, "utf8")));
  const service = env.OXBUY_LIVE_SERVICE ?? catalog.services[0]!.service_id;
  if (!catalog.services.some((s) => s.service_id === service)) throw new Error(`WEB_CONFIG_INVALID:OXBUY_LIVE_SERVICE ${service}`);
  let keyFile = env.OXDEAI_TESTNET_PAYER_KEY_FILE;
  if (env.OXBUY_PAYER_KEY) {
    const dir = mkdtempSync(join(tmpdir(), "oxbuy-key-"));
    chmodSync(dir, 0o700);
    keyFile = join(dir, "payer.key");
    writeFileSync(keyFile, env.OXBUY_PAYER_KEY.trim(), { mode: 0o600 });
  }
  if (!keyFile) throw new Error("WEB_CONFIG_INVALID: set OXBUY_PAYER_KEY or OXDEAI_TESTNET_PAYER_KEY_FILE");
  const wallet = addressOfPrivateKey(parsePrivateKey(readFileSync(keyFile, "utf8")));
  return {
    enabled: true,
    catalog,
    catalogFile,
    service,
    keyFile,
    wallet,
    maxPurchases: int(env.OXBUY_LIVE_MAX_PURCHASES, 10),
    perClient: int(env.OXBUY_LIVE_PER_CLIENT, 2),
    env: {
      OXDEAI_TESTNET_PAYER_KEY_FILE: keyFile,
      OXDEAI_BUYER_STATE_DIR: env.OXDEAI_BUYER_STATE_DIR ?? join(tmpdir(), "oxbuy-state"),
      OXDEAI_BUYER_EVIDENCE_DIR: env.OXDEAI_BUYER_EVIDENCE_DIR ?? join(tmpdir(), "oxbuy-evidence"),
      ...(env.OXDEAI_TESTNET_RPC_URL ? { OXDEAI_TESTNET_RPC_URL: env.OXDEAI_TESTNET_RPC_URL } : {}),
    },
  };
}

type Extra = Parameters<typeof runBuyer>[3];

export function createApp(o: { live: LiveConfig; extra?: Extra; commit?: string }) {
  const live = o.live;
  let purchases = 0;
  let liveBusy = false;
  let scenariosRunning = 0;
  const perClient = new Map<string, number>();
  const recent: { tx: string; topic: string; at: string }[] = [];
  const hits = new Map<string, { n: number; t: number }>();

  const client = (req: IncomingMessage) => String(req.headers["x-forwarded-for"] ?? req.socket.remoteAddress ?? "?").split(",")[0]!.trim();
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
    const base = { network: "Celo Sepolia (testnet)", commit: o.commit ?? null, scenarios: SCENARIOS, recent };
    if (!live.enabled) return { ...base, live: { enabled: false, why: live.why } };
    const s = live.catalog.services.find((x) => x.service_id === live.service)!;
    return {
      ...base,
      live: {
        enabled: true,
        wallet: live.wallet,
        walletUrl: `https://celo-sepolia.blockscout.com/address/${live.wallet}`,
        service: s.service_id,
        purpose: s.purpose ?? null,
        price: s.max_price,
        remaining: Math.max(0, live.maxPurchases - purchases),
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
      if (purchases >= live.maxPurchases) return send(res, 409, { error: "The live purchase allowance for this server is used up. The playground still works." });
      if ((perClient.get(ip) ?? 0) >= live.perClient) return send(res, 409, { error: `You have made ${live.perClient} live purchases already. The playground still works.` });
      if (liveBusy) return send(res, 409, { error: "Another live purchase is running. Try again in a few seconds." });
      liveBusy = true;
      purchases += 1;
      perClient.set(ip, (perClient.get(ip) ?? 0) + 1);
      try {
        const lines: string[] = [];
        const ev = (await runBuyer(["--catalog", live.catalogFile, "--topic", topic, "--service", live.service], live.env, (l) => lines.push(l), o.extra ?? {})) as {
          results: { authorized?: { decision?: string; tx?: string; detail?: string; amount?: string }; brief?: string; spent?: string };
        };
        const a = ev.results.authorized ?? {};
        if (a.decision === "ALLOW" && a.tx) recent.unshift({ tx: a.tx, topic, at: new Date().toISOString() });
        recent.splice(5);
        if (a.decision !== "ALLOW") {
          // Nothing was paid: give the allowance back.
          purchases -= 1;
          perClient.set(ip, (perClient.get(ip) ?? 1) - 1);
        }
        return send(res, 200, {
          decision: a.decision ?? "DENY",
          ...(a.tx ? { tx: a.tx, txUrl: CELO_SEPOLIA.explorerTxUrl(a.tx) } : {}),
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
    process.stdout.write(`OxBuy web on :${port} · live purchases ${live.enabled ? `ON (${live.wallet}, ${live.maxPurchases} max)` : "OFF"}\n`);
  });
}

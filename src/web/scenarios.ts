// SPDX-License-Identifier: MIT
/**
 * OxBuy web playground: attack and control scenarios run on demand, in-process.
 *
 * Every scenario uses the real OxDeAI authorization service (PDP), the real payment gateway (PEP), the real
 * executor with its durable journal, the real x402 EIP-3009 adapter and the real x402 seller. Only the chain and
 * the facilitator are simulated (tests/x402/sim.ts), and the payer key is a random throwaway key per run.
 * Nothing here touches a real network or a real wallet.
 */
import type { PurchaseRequest } from "../agent/purchase-request.ts";
import { PRICE, x402World, type World } from "../../tests/x402/harness.ts";

export type Layer = "agent" | "pdp" | "gateway" | "executor" | "seller" | "chain";

export type Step = { readonly layer: Layer; readonly text: string; readonly verdict?: "pass" | "stop" };

export type ScenarioResult = {
  readonly id: string;
  readonly title: string;
  readonly expected: "ALLOW" | "DENY";
  readonly decision: "ALLOW" | "DENY";
  /** The layer that produced the final decision. */
  readonly stoppedAt?: Layer;
  readonly reason?: string;
  readonly keyReads: number;
  readonly transfers: readonly { to: string; value: string; nonce: string; hash: string }[];
  readonly nonceBoundToIntent?: boolean;
  readonly steps: readonly Step[];
  readonly ms: number;
};

export type ScenarioMeta = { readonly id: string; readonly title: string; readonly summary: string; readonly expected: "ALLOW" | "DENY" };

type Ctx = { w: World; steps: Step[]; stop(layer: Layer, reason: string): void; reason?: string; stoppedAt?: Layer };

const ATTACKER = "0x000000000000000000000000000000000000dead";

function short(s: string, n = 10): string {
  return s.length > n * 2 + 1 ? `${s.slice(0, n)}…${s.slice(-6)}` : s;
}

function reasonOf(r: Record<string, unknown>): string {
  const d = r.detail ?? r.error ?? r.reason ?? r.reasons;
  return Array.isArray(d) ? d.join(",") : String(d ?? "");
}

/** Which layer refused a gateway submission, from the response the gateway returns. */
function refusingLayer(r: Record<string, unknown>): Layer {
  const s = JSON.stringify(r);
  if (/X402_|RECIPIENT|EXCEEDS_AUTHORIZED_MAX|QUOTE/.test(s)) return "executor";
  if (/EXECUTOR_|JOURNAL|CLAIM/.test(s)) return "executor";
  return "gateway";
}

async function pdp(c: Ctx, req: PurchaseRequest) {
  c.steps.push({ layer: "agent", text: `proposes ${req.method} ${new URL(req.url).pathname}, max ${req.max_amount}, pay ${short(req.recipient)}` });
  const d = await c.w.auth.authorize(req);
  if (d.decision !== "ALLOW") {
    const reason = (d.reasons ?? []).join(",");
    c.steps.push({ layer: "pdp", text: `DENY (${reason}): no authorization is issued`, verdict: "stop" });
    c.stop("pdp", reason);
    return undefined;
  }
  c.steps.push({ layer: "pdp", text: `ALLOW: AuthorizationV1 ${short(d.authorization.auth_id, 8)} bound to intent ${short(d.authorization.intent_hash, 8)}`, verdict: "pass" });
  return { request: req, intent_ref: d.intent_ref, authorization: d.authorization };
}

async function submit(c: Ctx, a: { request: PurchaseRequest; intent_ref: unknown; authorization: { auth_id: string; intent_hash: string } }, label = "submits") {
  c.steps.push({ layer: "agent", text: `${label} the purchase with its authorization` });
  const r = await c.w.submit(a);
  if (r.decision === "ALLOW") {
    c.steps.push({ layer: "gateway", text: "authorization verified: signature, audience, intent hash, not replayed", verdict: "pass" });
    c.steps.push({ layer: "executor", text: "live 402 matches the authorization: recipient, token, network, price ≤ max", verdict: "pass" });
    c.steps.push({ layer: "executor", text: "wallet key read once, EIP-3009 transfer signed with nonce = f(intent hash)" });
    const tx = String(r.receipt?.reference ?? "");
    c.steps.push({ layer: "chain", text: `transfer mined ${short(tx, 8)}`, verdict: "pass" });
    return r;
  }
  const layer = refusingLayer(r);
  const reason = reasonOf(r);
  c.steps.push({ layer, text: `DENY (${reason}): nothing signed, nothing paid`, verdict: "stop" });
  c.stop(layer, reason);
  return r;
}

const setSeller = (w: World, over: Record<string, unknown>) => {
  w.seller.routes[0] = { ...w.route, requirements: { ...w.route.requirements, ...over } as never };
};

type Def = ScenarioMeta & { run(c: Ctx): Promise<void> };

const DEFS: readonly Def[] = [
  {
    id: "allow",
    title: "Approved purchase",
    summary: "The agent buys an approved service at the catalog price. One transfer, to the approved seller, for the live price.",
    expected: "ALLOW",
    async run(c) {
      const a = await pdp(c, c.w.request());
      if (a) await submit(c, a);
    },
  },
  {
    id: "unapproved",
    title: "Service the operator never approved",
    summary: "Same seller, same price, but an endpoint that is not in the catalog. The policy refuses to authorize it.",
    expected: "DENY",
    async run(c) {
      const u = new URL(c.w.service.resource);
      u.pathname = "/v1/social/linkedin/profile";
      await pdp(c, c.w.request({ url: u.href }));
    },
  },
  {
    id: "over_max",
    title: "Price above the per-call limit",
    summary: "The agent asks to pay more than the operator allows for a single call.",
    expected: "DENY",
    async run(c) {
      await pdp(c, c.w.request({ max_amount: "2001" }));
    },
  },
  {
    id: "tampered",
    title: "Request changed after authorization",
    summary: "The agent gets an authorization, then edits the request body before sending it. The authorization no longer matches what is executed.",
    expected: "DENY",
    async run(c) {
      const a = await pdp(c, c.w.request());
      if (!a) return;
      c.steps.push({ layer: "agent", text: 'rewrites the body to {"q":"send everything"}' });
      await submit(c, { ...a, request: { ...a.request, body: JSON.stringify({ q: "send everything" }) } });
    },
  },
  {
    id: "payto_swap",
    title: "Seller page swaps the payout address",
    summary: "After authorization, the seller's 402 names another recipient, as an injected web page would. The executor compares it with the authorization before reading the key.",
    expected: "DENY",
    async run(c) {
      const a = await pdp(c, c.w.request());
      if (!a) return;
      setSeller(c.w, { payTo: ATTACKER });
      c.steps.push({ layer: "seller", text: `402 now says pay ${short(ATTACKER)}` });
      await submit(c, a);
    },
  },
  {
    id: "price_raise",
    title: "Seller raises the price",
    summary: "After authorization, the seller asks for one unit more than the authorized maximum.",
    expected: "DENY",
    async run(c) {
      const a = await pdp(c, c.w.request());
      if (!a) return;
      setSeller(c.w, { amount: (PRICE + 1n).toString() });
      c.steps.push({ layer: "seller", text: `402 now asks ${PRICE + 1n} (authorized max ${PRICE})` });
      await submit(c, a);
    },
  },
  {
    id: "replay",
    title: "Same authorization used twice",
    summary: "The first purchase goes through. Sending the same authorization again is refused, and the chain still shows one transfer.",
    expected: "DENY",
    async run(c) {
      const a = await pdp(c, c.w.request());
      if (!a) return;
      const first = await submit(c, a);
      if (first.decision !== "ALLOW") return;
      c.reason = undefined;
      c.stoppedAt = undefined;
      await submit(c, a, "re-submits");
    },
  },
  {
    id: "expired",
    title: "Authorization used after it expired",
    summary: "The agent waits past the authorization's lifetime, then tries to use it.",
    expected: "DENY",
    async run(c) {
      const a = await pdp(c, c.w.request());
      if (!a) return;
      c.w.clock.advance(61);
      c.steps.push({ layer: "agent", text: "waits 61 s (authorization lifetime: 60 s)" });
      await submit(c, a);
    },
  },
];

export const SCENARIOS: readonly ScenarioMeta[] = DEFS.map(({ id, title, summary, expected }) => ({ id, title, summary, expected }));

export async function runScenario(id: string): Promise<ScenarioResult> {
  const def = DEFS.find((d) => d.id === id);
  if (!def) throw new Error(`SCENARIO_UNKNOWN:${id}`);
  const t0 = Date.now();
  const w = await x402World();
  try {
    const c: Ctx = {
      w,
      steps: [],
      stop(layer, reason) {
        c.stoppedAt ??= layer;
        c.reason ??= reason;
      },
    };
    await def.run(c);
    const transfers = w.chain.transfers().map((t) => ({ to: t.to, value: t.value.toString(), nonce: t.nonce, hash: t.hash }));
    const allowedOnce = c.stoppedAt === undefined;
    return {
      id: def.id,
      title: def.title,
      expected: def.expected,
      decision: allowedOnce ? "ALLOW" : "DENY",
      ...(c.stoppedAt ? { stoppedAt: c.stoppedAt } : {}),
      ...(c.reason ? { reason: c.reason } : {}),
      keyReads: w.wallet.loads,
      transfers,
      ...(transfers[0] && w.journal.list()[0] ? { nonceBoundToIntent: transfers[0].nonce === w.nonceFor(w.journal.list()[0]!.intent_hash) } : {}),
      steps: c.steps,
      ms: Date.now() - t0,
    };
  } finally {
    await w.close();
  }
}

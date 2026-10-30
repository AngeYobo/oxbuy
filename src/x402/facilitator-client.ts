// SPDX-License-Identifier: MIT
/**
 * HTTP client for an x402 v2 facilitator (POST /verify, POST /settle, GET /supported), used by the
 * seller (resource server) side. The Celo Sepolia facilitator is https://api.x402.sepolia.celo.org;
 * `/settle` needs an API key sent as `X-API-Key` (created on https://x402.celo.org, stored only in
 * the seller's environment, never in source, logs or evidence).
 *
 * The executor (payer) never talks to a facilitator: it signs, and proves settlement on chain.
 */
import { parseSettleResponse, parseVerifyResponse, type PaymentPayload, type PaymentRequirements, type SettleResponse, type VerifyResponse } from "./wire.ts";

export interface FacilitatorClient {
  verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse>;
  settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse>;
  supported(): Promise<unknown>;
}

export function createHttpFacilitatorClient(o: { baseUrl: string; apiKey?: string; timeoutMs?: number; fetch?: typeof fetch }): FacilitatorClient {
  const f = o.fetch ?? fetch;
  const headers = { "content-type": "application/json", ...(o.apiKey ? { "x-api-key": o.apiKey } : {}) };
  const url = (p: string) => `${o.baseUrl.replace(/\/$/, "")}${p}`;
  async function post(path: string, payload: PaymentPayload, requirements: PaymentRequirements): Promise<{ status: number; body: unknown }> {
    const res = await f(url(path), {
      method: "POST",
      headers,
      body: JSON.stringify({ x402Version: 2, paymentPayload: payload, paymentRequirements: requirements }),
      signal: AbortSignal.timeout(o.timeoutMs ?? 60_000),
    });
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = undefined;
    }
    return { status: res.status, body };
  }
  return {
    async verify(payload, requirements) {
      const r = await post("/verify", payload, requirements);
      if (r.status !== 200) return { isValid: false, invalidReason: `facilitator_http_${r.status}` };
      return parseVerifyResponse(r.body);
    },
    async settle(payload, requirements) {
      const r = await post("/settle", payload, requirements);
      // 401 / 402 / 429 from the facilitator: nothing was broadcast (documented by the Celo facilitator).
      if (r.status !== 200 && (r.body === undefined || typeof r.body !== "object")) {
        return { success: false, errorReason: `facilitator_http_${r.status}`, transaction: "", network: requirements.network };
      }
      return parseSettleResponse(r.body, "settle");
    },
    async supported() {
      const res = await f(url("/supported"), { headers, signal: AbortSignal.timeout(o.timeoutMs ?? 60_000) });
      return res.json();
    },
  };
}

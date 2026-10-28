// SPDX-License-Identifier: MIT
/**
 * Untrusted program for the isolation tests.
 *
 * Launched by the tests as the agent OS identity, or as a service identity
 * to act as a compromised gateway / auth service / executor. Each command performs one
 * honest or adversarial action and prints one JSON line with what the OS and
 * the gateway answered. It never receives operator secrets except where a
 * test hands it an already-signed authorization to submit.
 *
 *   node agent-probe.ts <command> [args...]
 */
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { appendFileSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { signAuthorizationEd25519, type AuthorizationV1 } from "@oxdeai/core";
import { createPurchaseAgent } from "../../src/agent/agent.ts";
import type { PurchaseRequest } from "../../src/agent/purchase-request.ts";
import { createRemoteGatewayClient } from "../../src/agent/remote-client.ts";
import { postJson } from "../../src/isolation/ipc.ts";
import { SERVICES } from "../../src/system.ts";

type Service = (typeof SERVICES)[keyof typeof SERVICES];

function requestFor(service: Service): PurchaseRequest {
  return {
    service_id: service.service_id,
    method: "POST",
    url: `${service.resource}?city=lagos`,
    body: JSON.stringify({ units: "metric", days: 3 }),
    network: service.network,
    asset: service.asset,
    recipient: service.pay_to,
    max_amount: service.price.toString(),
  };
}

function errCode(err: unknown): string {
  return (err as NodeJS.ErrnoException).code ?? (err as Error).message;
}

function attempt(fn: () => unknown): { ok: boolean; code?: string; value?: unknown } {
  try {
    return { ok: true, value: fn() };
  } catch (err) {
    return { ok: false, code: errCode(err) };
  }
}

async function attemptAsync(fn: () => Promise<unknown>): Promise<{ ok: boolean; code?: string; value?: unknown }> {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, code: errCode(err) };
  }
}

function connectUnix(path: string): Promise<{ ok: boolean; code?: string }> {
  return new Promise((resolve) => {
    const s = connect(path);
    s.once("connect", () => {
      s.destroy();
      resolve({ ok: true });
    });
    s.once("error", (err) => resolve({ ok: false, code: errCode(err) }));
  });
}

async function authorized(sock: string, service: Service = SERVICES.weather) {
  const client = createRemoteGatewayClient(sock);
  const request = requestFor(service);
  const auth = await client.authorize(request);
  if (auth.decision !== "ALLOW") throw new Error(`authorize denied: ${JSON.stringify(auth)}`);
  return { client, request, intent_ref: auth.intent_ref, authorization: auth.authorization };
}

const [command, ...args] = process.argv.slice(2);
let out: unknown;

switch (command) {
  case "whoami":
    out = { uid: process.getuid!(), gid: process.getgid!(), groups: process.getgroups!() };
    break;

  case "buy": {
    const [sock, service] = args;
    const agent = createPurchaseAgent(createRemoteGatewayClient(sock!));
    const s = SERVICES[service as keyof typeof SERVICES];
    out = await agent.buy({ service_id: s.service_id, method: "POST", url: `${s.resource}?city=lagos`, body: JSON.stringify({ units: "metric", days: 3 }) });
    break;
  }

  case "submit": {
    // Submit a purchase the test prepared (e.g. an operator-minted authorization).
    const [sock, json] = args;
    out = await createRemoteGatewayClient(sock!).purchase(JSON.parse(json!));
    break;
  }

  case "authorize-only": {
    const a = await authorized(args[0]!);
    out = { request: a.request, intent_ref: a.intent_ref, authorization: a.authorization };
    break;
  }

  case "forge": {
    // Self-signed authorizations: own key, and either a foreign issuer or the PDP's issuer name.
    const [sock] = args;
    const a = await authorized(sock!);
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const results: Record<string, unknown> = {};
    for (const [name, patch] of [
      ["self_signed_pdp_issuer", {}],
      ["self_signed_foreign_issuer", { issuer: "attacker.example" }],
      ["audience_edited", { audience: "some-other-gateway" }],
    ] as const) {
      const base: AuthorizationV1 = { ...a.authorization, ...patch, auth_id: randomBytes(16).toString("hex") };
      const authorization = name === "audience_edited" ? { ...a.authorization, ...patch } : signAuthorizationEd25519(base as Parameters<typeof signAuthorizationEd25519>[0], pem);
      results[name] = await a.client.purchase({ request: a.request, intent_ref: a.intent_ref, authorization });
    }
    results.signature_garbled = await a.client.purchase({
      request: a.request,
      intent_ref: a.intent_ref,
      authorization: { ...a.authorization, signature: Buffer.from(randomBytes(64)).toString("base64") },
    });
    out = results;
    break;
  }

  case "tamper": {
    const [sock] = args;
    const results: Record<string, unknown> = {};
    for (const [field, value] of [
      ["recipient", SERVICES.unlisted.pay_to],
      ["max_amount", "19999"],
      ["url", `${SERVICES.weather.resource}?city=paris`],
      ["body", JSON.stringify({ units: "metric", days: 30 })],
    ] as const) {
      const a = await authorized(sock!);
      results[field] = await a.client.purchase({ request: { ...a.request, [field]: value }, intent_ref: a.intent_ref, authorization: a.authorization });
    }
    out = results;
    break;
  }

  case "replay": {
    const a = await authorized(args[0]!);
    const input = { request: a.request, intent_ref: a.intent_ref, authorization: a.authorization };
    out = { first: await a.client.purchase(input), second: await a.client.purchase(input) };
    break;
  }

  case "expire": {
    const [sock, waitMs] = args;
    const a = await authorized(sock!);
    await new Promise((r) => setTimeout(r, Number(waitMs)));
    out = await a.client.purchase({ request: a.request, intent_ref: a.intent_ref, authorization: a.authorization });
    break;
  }

  case "concurrent": {
    const [sock, n] = args;
    const a = await authorized(sock!);
    const input = { request: a.request, intent_ref: a.intent_ref, authorization: a.authorization };
    out = await Promise.all(Array.from({ length: Number(n) }, () => a.client.purchase(input)));
    break;
  }

  case "connect": {
    // Raw connection attempts to Unix sockets.
    out = Object.fromEntries(await Promise.all(args.map(async (p) => [p, await connectUnix(p)] as const)));
    break;
  }

  case "read": {
    out = Object.fromEntries(args.map((p) => [p, attempt(() => readFileSync(p, "utf8").length)]));
    break;
  }

  case "write": {
    out = Object.fromEntries(
      args.map((p) => [p, attempt(() => (p.endsWith(".ts") ? appendFileSync(p, "\n// agent was here\n") : writeFileSync(p, "agent", { flag: "a" })))]),
    );
    break;
  }

  case "signal": {
    out = Object.fromEntries(args.map((pid) => [pid, attempt(() => process.kill(Number(pid), "SIGKILL"))]));
    break;
  }

  case "proc": {
    out = Object.fromEntries(
      args.map((pid) => [
        pid,
        {
          environ: attempt(() => readFileSync(`/proc/${pid}/environ`, "utf8")),
          cmdline: attempt(() => readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean)),
          mem: attempt(() => readFileSync(`/proc/${pid}/mem`).length),
        },
      ]),
    );
    break;
  }

  case "post": {
    // Raw IPC request. A header value "@token-from:<config>" is replaced by the
    // internalToken in that config file, read with this process's own identity.
    const [sock, path, body, headers] = args;
    const h = Object.fromEntries(
      Object.entries(JSON.parse(headers ?? "{}") as Record<string, string>).map(([k, v]) => [
        k,
        v.startsWith("@token-from:") ? (JSON.parse(readFileSync(v.slice(12), "utf8")) as { internalToken: string }).internalToken : v,
      ]),
    );
    out = await attemptAsync(() => postJson(sock!, path!, JSON.parse(body!), h));
    break;
  }

  case "unlink": {
    out = Object.fromEntries(args.map((p) => [p, attempt(() => unlinkSync(p))]));
    break;
  }

  case "escalate": {
    const r = spawnSync("sudo", ["-n", "true"], { encoding: "utf8" });
    out = { sudo_status: r.status, sudo_stderr: r.stderr.trim() };
    break;
  }

  case "direct-pay": {
    // Import the payment runtime (any copy the agent can read) and try to
    // pay with the executor's wallet and ledger.
    const [appDir, walletKeyPath, ledgerPath, intentHash] = args;
    const { createMockBuyAdapter } = (await import(`${appDir}/src/adapters/mock-buy/mock-buy.ts`)) as typeof import("../../src/adapters/mock-buy/mock-buy.ts");
    const { withMockSettlement } = (await import(`${appDir}/src/adapters/mock-buy/mock-settlement.ts`)) as typeof import("../../src/adapters/mock-buy/mock-settlement.ts");
    const adapter = withMockSettlement(createMockBuyAdapter(Object.values(SERVICES)).adapter, { walletKeyPath: walletKeyPath!, ledgerPath: ledgerPath! });
    const pay = await attemptAsync(() => adapter.pay({ intent_hash: intentHash!, request: requestFor(SERVICES.weather) }));
    const forgeLedger = attempt(() => appendFileSync(ledgerPath!, `${JSON.stringify({ forged: true })}\n`));
    out = { pay, forgeLedger };
    break;
  }

  default:
    throw new Error(`unknown command ${command}`);
}

process.stdout.write(`${JSON.stringify(out)}\n`);

// SPDX-License-Identifier: MIT
/**
 * Process A: the untrusted agent, for the isolated demo.
 *
 * Runs as the agent OS identity. Its only input is the path of the gateway's
 * public socket; it also tries the executor socket and the executor's wallet
 * key to show what the OS answers.
 *
 *   node agent-main.ts <public gateway.sock> <executor.sock> <mock-wallet.key>
 */
import { readFileSync } from "node:fs";
import { connect } from "node:net";
import { createPurchaseAgent } from "../agent/agent.ts";
import { createRemoteGatewayClient } from "../agent/remote-client.ts";
import { SERVICES } from "../system.ts";

const [publicSocket, executorSocket, walletKeyPath] = process.argv.slice(2);
const agent = createPurchaseAgent(createRemoteGatewayClient(publicSocket!));

const draft = (s: (typeof SERVICES)[keyof typeof SERVICES]) => ({
  service_id: s.service_id,
  method: "POST" as const,
  url: `${s.resource}?city=lagos`,
  body: JSON.stringify({ units: "metric", days: 3 }),
});

const code = (err: unknown) => (err as NodeJS.ErrnoException).code ?? String(err);

const executorConnect = await new Promise<string>((resolve) => {
  const s = connect(executorSocket!);
  s.once("connect", () => {
    s.destroy();
    resolve("CONNECTED");
  });
  s.once("error", (err) => resolve(code(err)));
});

let walletKeyRead: string;
try {
  readFileSync(walletKeyPath!);
  walletKeyRead = "READ";
} catch (err) {
  walletKeyRead = code(err);
}

process.stdout.write(
  `${JSON.stringify({
    agent_uid: process.getuid!(),
    weather: await agent.buy(draft(SERVICES.weather)),
    unlisted: await agent.buy(draft(SERVICES.unlisted)),
    executor_socket_connect: executorConnect,
    wallet_key_read: walletKeyRead,
  })}\n`,
);

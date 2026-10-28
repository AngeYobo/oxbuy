// SPDX-License-Identifier: MIT
/**
 * `AgentGatewayClient` over the gateway's public Unix-domain socket.
 *
 * This is all the agent process gets: the path of the public socket. No
 * executor socket, token, signing key, or payment adapter.
 */
import { postJson } from "../isolation/ipc.ts";
import type { AgentGatewayClient, AuthorizeResult, PurchaseResult, QuoteView } from "./agent.ts";

export function createRemoteGatewayClient(publicSocketPath: string): AgentGatewayClient {
  return {
    async quote(request) {
      const res = await postJson(publicSocketPath, "/v1/quote", request);
      if (res.status !== 200) throw new Error(`QUOTE_FAILED:${res.status}`);
      return res.body as QuoteView;
    },
    async authorize(request) {
      const res = await postJson(publicSocketPath, "/v1/authorize", request);
      if (res.status !== 200) throw new Error(`AUTHORIZE_FAILED:${res.status}`);
      return res.body as AuthorizeResult;
    },
    async purchase(input) {
      const res = await postJson(publicSocketPath, "/v1/purchase", input);
      return res.body as PurchaseResult;
    },
  };
}

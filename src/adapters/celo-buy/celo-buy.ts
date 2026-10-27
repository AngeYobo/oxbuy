// SPDX-License-Identifier: MIT
/**
 * `@celo/buy` adapter: INTERFACE ONLY in Phase 1.
 *
 * Intended mapping, from the sponsor documentation cited in
 * docs/FEASIBILITY.md (not yet verified against a running buy process):
 *
 *   PaymentAdapter.quote(request) -> MCP `buy_pay_quote` (read-only, no signing)
 *   PaymentAdapter.pay(payment)   -> MCP `buy_curl` with maxAmount,
 *                                    or CLI `buy curl --max-amount <max>`
 *
 * The buy process holds the keychain wallet and signs in its own process.
 * In Phase 2 only the trusted executor may reach it, and the agent's process
 * / OS user must not be able to reach the buy MCP server, the `buy` CLI, or
 * the keychain entry.
 *
 * UNVERIFIED (must be confirmed before Phase 2 implementation):
 *   - exact MCP tool argument and result schemas of buy_pay_quote / buy_curl
 *   - whether buy_curl re-quotes and enforces maxAmount before signing
 *   - whether the payTo, network, and asset of the live 402 can be pinned to
 *     the authorized values before signing (buy_curl takes none of them);
 *     the PaymentAdapter.pay contract requires it
 *   - which buy errors guarantee nothing was signed (PaymentRefusedError);
 *     until known, every pay error must be treated as an unknown outcome
 *   - how the buy process authenticates its MCP client
 *   - ERC-8021 attribution support (no public evidence; see FEASIBILITY.md)
 */
import type { PaymentAdapter } from "../../executor/payment-adapter.ts";

export type CeloBuyAdapterConfig = {
  /** How the executor reaches the buy process (MCP stdio, MCP HTTP, or CLI). */
  readonly transport: "mcp-stdio" | "mcp-http" | "cli";
  /** Named buy account (`buy account ...`). Never a key. */
  readonly account: string;
};

export function createCeloBuyAdapter(_config: CeloBuyAdapterConfig): PaymentAdapter {
  throw new Error("NOT_IMPLEMENTED: live @celo/buy execution is out of scope for Phase 1");
}

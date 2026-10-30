// SPDX-License-Identifier: MIT
/**
 * x402 testnet profile: the one paid service of the Celo Sepolia demonstration, its policy, and the
 * executor-side x402 adapter configuration. Separate from the mock deployment (src/system.ts) and
 * from any future mainnet configuration (none exists; src/chain/networks.ts refuses mainnet).
 *
 * Environment (placeholders only in docs/TESTNET-X402.md; never commit real values):
 *   OXDEAI_TESTNET_PAYER_KEY_FILE   file holding the TESTNET payer private key (hex), mode 0600
 *   OXDEAI_TESTNET_PAY_TO           approved testnet recipient (the seller's address)
 *   OXDEAI_TESTNET_RPC_URL          optional, default https://forno.celo-sepolia.celo-testnet.org
 *   OXDEAI_X402_API_KEY             facilitator API key for /settle (seller side only)
 *   OXDEAI_TESTNET_PRICE            optional, atomic USDC units, default 1000 (0.001 USDC)
 */
import { CELO_SEPOLIA } from "../chain/networks.ts";
import type { MockService } from "../adapters/mock-buy/mock-buy.ts";
import { policyStateFor } from "../system.ts";

export const TESTNET_NETWORK = CELO_SEPOLIA;
export const TESTNET_USDC = CELO_SEPOLIA.assets[0]!;
/** The authorized origin of the demo seller. The executor dials it via its `endpoints` map. */
export const TESTNET_SELLER_ORIGIN = "https://seller.oxdeai.test";
export const TESTNET_SELLER_PATH = "/v1/report";

export const TESTNET_LIMITS = {
  /** 0.002 USDC per action, 0.005 USDC per budget period: testnet funds only. */
  perActionMax: 2_000n,
  budget: 5_000n,
};

/** The single paid service of the profile, for an approved recipient. */
export function testnetService(payTo: string, price: bigint): MockService {
  if (!/^0x[0-9a-f]{40}$/.test(payTo)) throw new Error("TESTNET_PAY_TO_INVALID:lower-case 20-byte hex address required");
  if (price <= 0n || price > TESTNET_LIMITS.perActionMax) throw new Error("TESTNET_PRICE_OUT_OF_RANGE");
  return {
    service_id: "x402-testnet-report",
    resource: `${TESTNET_SELLER_ORIGIN}${TESTNET_SELLER_PATH}`,
    network: TESTNET_NETWORK.caip2,
    asset: TESTNET_USDC.address,
    pay_to: payTo,
    price,
  };
}

export function testnetPolicyState(service: MockService, limits: { budget?: bigint; perActionMax?: bigint } = {}) {
  return policyStateFor({
    services: [service],
    assets: [TESTNET_USDC.address],
    budget: limits.budget ?? TESTNET_LIMITS.budget,
    perActionMax: limits.perActionMax ?? TESTNET_LIMITS.perActionMax,
  });
}

/** x402 v2 requirements the demo seller publishes for `service`. */
export function testnetRequirements(service: MockService, maxTimeoutSeconds = 60) {
  return {
    scheme: "exact",
    network: service.network,
    amount: service.price.toString(),
    asset: service.asset,
    payTo: service.pay_to,
    maxTimeoutSeconds,
    extra: { name: TESTNET_USDC.eip712Name, version: TESTNET_USDC.eip712Version },
  };
}

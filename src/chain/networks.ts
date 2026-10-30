// SPDX-License-Identifier: MIT
/**
 * EVM networks the x402 executor may settle on (testnet integration).
 *
 * Only Celo Sepolia is configured. Mainnet is not authorized by the current
 * mandate: Celo mainnet (eip155:42220) and every network not listed here are
 * refused before any key is read or anything is signed (NETWORK_NOT_AUTHORIZED).
 * A mainnet entry must come with a separate configuration file and a separate
 * written authorization; it is deliberately absent from this module.
 *
 * Values verified on 2026-10-29 (docs/TESTNET-X402.md §2):
 *   - chain id 11142220, RPC https://forno.celo-sepolia.celo-testnet.org (Celo docs)
 *   - USDC 0x01C5C0122039549AD1493B8220cABEdD739BC44E, 6 decimals, EIP-712 name "USDC" version "2",
 *     EIP-3009 (Circle contract list; Celo facilitator /supported; Blockscout token metadata)
 *   - facilitator https://api.x402.sepolia.celo.org, x402 v2 scheme "exact" on eip155:11142220
 */

export type Eip3009Asset = {
  /** Lower-case 20-byte hex. */
  readonly address: string;
  readonly symbol: string;
  readonly decimals: number;
  /** EIP-712 domain name and version of the token contract. */
  readonly eip712Name: string;
  readonly eip712Version: string;
};

export type EvmNetwork = {
  readonly name: string;
  /** CAIP-2 identifier, as used in x402 v2 `network`. */
  readonly caip2: string;
  readonly chainId: bigint;
  readonly testnet: true;
  readonly defaultRpcUrl: string;
  readonly explorerTxUrl: (hash: string) => string;
  readonly facilitatorUrl: string;
  readonly assets: readonly Eip3009Asset[];
};

export const CELO_SEPOLIA: EvmNetwork = Object.freeze({
  name: "Celo Sepolia",
  caip2: "eip155:11142220",
  chainId: 11142220n,
  testnet: true,
  defaultRpcUrl: "https://forno.celo-sepolia.celo-testnet.org",
  explorerTxUrl: (hash: string) => `https://celo-sepolia.blockscout.com/tx/${hash}`,
  facilitatorUrl: "https://api.x402.sepolia.celo.org",
  assets: Object.freeze([
    Object.freeze({
      address: "0x01c5c0122039549ad1493b8220cabedd739bc44e",
      symbol: "USDC",
      decimals: 6,
      eip712Name: "USDC",
      eip712Version: "2",
    }),
  ]),
});

/** Known mainnet chain ids: refused explicitly, with their own error code. */
const MAINNET_CHAIN_IDS: ReadonlySet<string> = new Set(["eip155:42220", "eip155:1", "eip155:8453"]);

const TESTNETS: ReadonlyMap<string, EvmNetwork> = new Map([[CELO_SEPOLIA.caip2, CELO_SEPOLIA]]);

/** The configured testnet for a CAIP-2 id. Throws NETWORK_NOT_AUTHORIZED:* for anything else. */
export function authorizedTestnet(caip2: string): EvmNetwork {
  if (MAINNET_CHAIN_IDS.has(caip2)) throw new Error(`NETWORK_NOT_AUTHORIZED:mainnet ${caip2} is not authorized by the current mandate`);
  const n = TESTNETS.get(caip2);
  if (!n) throw new Error(`NETWORK_NOT_AUTHORIZED:${caip2} is not a configured testnet`);
  return n;
}

/** The configured EIP-3009 asset on `network`. Throws ASSET_NOT_AUTHORIZED otherwise. */
export function authorizedAsset(network: EvmNetwork, address: string): Eip3009Asset {
  const a = network.assets.find((x) => x.address === address.toLowerCase());
  if (!a) throw new Error(`ASSET_NOT_AUTHORIZED:${address} on ${network.caip2}`);
  return a;
}

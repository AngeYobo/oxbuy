// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { authorizedNetwork, authorizedTestnet, CELO_MAINNET, CELO_SEPOLIA, MAINNET_APPROVAL } from "../../src/chain/networks.ts";
import { validateCatalog } from "../../src/product/catalog.ts";

const file = new URL("../../config/usebuy-celo-mainnet.json", import.meta.url);
const catalog = JSON.parse(readFileSync(file, "utf8"));

test("MN1: mainnet is refused without explicit approval", () => {
  const prior = process.env.OXDEAI_ENABLE_CELO_MAINNET;
  try {
    delete process.env.OXDEAI_ENABLE_CELO_MAINNET;
    assert.throws(() => authorizedNetwork(CELO_MAINNET.caip2), /NETWORK_NOT_AUTHORIZED/);
    assert.throws(() => validateCatalog(catalog), /NETWORK_NOT_AUTHORIZED/);
    assert.throws(() => authorizedTestnet(CELO_MAINNET.caip2), /NETWORK_NOT_AUTHORIZED/);
    assert.equal(authorizedNetwork(CELO_SEPOLIA.caip2).chainId, CELO_SEPOLIA.chainId);
  } finally {
    if (prior === undefined) delete process.env.OXDEAI_ENABLE_CELO_MAINNET;
    else process.env.OXDEAI_ENABLE_CELO_MAINNET = prior;
  }
});

test("MN2: explicit approval permits only configured Celo mainnet USDC", () => {
  const prior = process.env.OXDEAI_ENABLE_CELO_MAINNET;
  try {
    process.env.OXDEAI_ENABLE_CELO_MAINNET = MAINNET_APPROVAL;
    const c = validateCatalog(catalog);
    assert.equal(c.network, "eip155:42220");
    assert.equal(c.services[0]!.asset, CELO_MAINNET.assets[0]!.address);
    assert.throws(() => authorizedNetwork("eip155:1"), /NETWORK_NOT_AUTHORIZED/);
    assert.throws(() => validateCatalog({ ...catalog, services: [{ ...catalog.services[0], asset: "0x" + "1".repeat(40) }] }), /ASSET_NOT_AUTHORIZED/);
    assert.throws(() => validateCatalog({ ...catalog, services: [{ ...catalog.services[0], max_price: "5001" }] }), /CATALOG_INVALID/);
  } finally {
    if (prior === undefined) delete process.env.OXDEAI_ENABLE_CELO_MAINNET;
    else process.env.OXDEAI_ENABLE_CELO_MAINNET = prior;
  }
});

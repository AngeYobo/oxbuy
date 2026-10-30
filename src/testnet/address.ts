// SPDX-License-Identifier: MIT
/**
 * Print the address of a testnet key file (never the key):  npm run testnet:address -- <keyfile>
 */
import { readFileSync, statSync } from "node:fs";
import { addressOfPrivateKey, parsePrivateKey } from "../chain/evm.ts";

const file = process.argv[2] ?? process.env.OXDEAI_TESTNET_PAYER_KEY_FILE;
if (!file) throw new Error("usage: testnet:address -- <keyfile>");
if ((statSync(file).mode & 0o077) !== 0) throw new Error(`${file} must be mode 0600`);
const key = parsePrivateKey(readFileSync(file, "utf8"));
process.stdout.write(`${addressOfPrivateKey(key)}\n`);
key.fill(0);

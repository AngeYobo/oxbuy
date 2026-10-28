// SPDX-License-Identifier: MIT
/**
 * Operator tool for persistent policy state (src/isolation/policy-state-admin.ts).
 *
 *   node policy-cli.ts provision <stateRoot>
 *   node policy-cli.ts init <stateRoot> [budget] [ttlSeconds]
 *   node policy-cli.ts where <stateRoot> [ttlSeconds]
 *   node policy-cli.ts verify <stateRoot> [ttlSeconds]          state.json against the anchor (read-only)
 *   node policy-cli.ts migrate <stateRoot> [ttlSeconds]         format v1 -> v2 (Phase 2C)
 *   node policy-cli.ts restore <stateRoot> <backupFile> [ttlSeconds]
 *
 * `init` succeeds once per (state root, policy identity); afterwards it
 * fails with POLICY_STATE_EXISTS. Launch with
 * OXDEAI_POLICY_STATE_ROOT=<stateRoot> (or the `policyStateRoot` option).
 */
import { initPolicyState, migratePolicyState, policyBinding, policyStateDir, provisionStateRoot, restorePolicyState, verifyPolicyState } from "./policy-state-admin.ts";

const [command, stateRoot, a, b] = process.argv.slice(2);
const ttl = (v: string | undefined) => (v === undefined ? undefined : Number(v));
if (!command || !stateRoot) throw new Error("usage: policy-cli provision|init|where <stateRoot> ...");
let out: unknown;
switch (command) {
  case "provision":
    provisionStateRoot(stateRoot);
    out = { provisioned: stateRoot };
    break;
  case "init":
    out = initPolicyState({ stateRoot, budget: a, ttlSeconds: b === undefined ? undefined : Number(b) });
    break;
  case "where": {
    const binding = policyBinding({ ttlSeconds: a === undefined ? undefined : Number(a) });
    out = { binding, stateDir: policyStateDir(stateRoot, binding) };
    break;
  }
  case "verify":
    out = verifyPolicyState({ stateRoot, ttlSeconds: ttl(a) });
    break;
  case "migrate":
    out = await migratePolicyState({ stateRoot, ttlSeconds: ttl(a) });
    break;
  case "restore":
    if (!a) throw new Error("usage: policy-cli restore <stateRoot> <backupFile> [ttlSeconds]");
    out = await restorePolicyState({ stateRoot, backupPath: a, ttlSeconds: ttl(b) });
    break;
  default:
    throw new Error(`unknown command ${command}`);
}
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

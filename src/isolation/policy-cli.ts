// SPDX-License-Identifier: MIT
/**
 * Operator tool for persistent policy state (src/isolation/policy-state-admin.ts).
 *
 *   node policy-cli.ts provision <stateRoot>
 *   node policy-cli.ts init <stateRoot> [budget] [ttlSeconds]
 *   node policy-cli.ts where <stateRoot> [ttlSeconds]
 *
 * `init` succeeds once per (state root, policy identity); afterwards it
 * fails with POLICY_STATE_EXISTS. Launch with
 * OXDEAI_POLICY_STATE_ROOT=<stateRoot> (or the `policyStateRoot` option).
 */
import { initPolicyState, policyBinding, policyStateDir, provisionStateRoot } from "./policy-state-admin.ts";

const [command, stateRoot, a, b] = process.argv.slice(2);
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
  default:
    throw new Error(`unknown command ${command}`);
}
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

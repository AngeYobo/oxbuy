// SPDX-License-Identifier: MIT
/**
 * Operator tool for the executor's persistent state (src/isolation/executor-state-admin.ts).
 *
 *   node executor-cli.ts provision <executorStateRoot>
 *   node executor-cli.ts init <executorStateRoot>
 *
 * `init` creates the payment journal once; afterwards it fails with
 * JOURNAL_EXISTS. Launch with OXDEAI_EXECUTOR_STATE_ROOT=<executorStateRoot>
 * (or the `executorStateRoot` option).
 */
import { initExecutorState, provisionExecutorStateRoot } from "./executor-state-admin.ts";

const [command, root] = process.argv.slice(2);
if (!command || !root) throw new Error("usage: executor-cli provision|init <executorStateRoot>");
let out: unknown;
switch (command) {
  case "provision":
    provisionExecutorStateRoot(root);
    out = { provisioned: root };
    break;
  case "init":
    out = initExecutorState(root);
    break;
  default:
    throw new Error(`unknown command ${command}`);
}
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

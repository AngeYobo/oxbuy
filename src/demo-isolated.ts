// SPDX-License-Identifier: MIT
/**
 * Phase 2A demo: three processes, two OS identities, mock payments only.
 *
 *   npm run demo:isolated
 *
 * Launches only the operator-approved artifact from the trust store
 * ($OXDEAI_TRUST_STORE or ~/.oxdeai-celo-poc/trust); never the checkout.
 * Exits 2 (BLOCKED) if there is no approved artifact or the agent cannot be
 * run as a separate OS identity. Agent programs are taken from the current
 * directory (they are untrusted and must be readable by the agent).
 */
import { join } from "node:path";
import { approvedDigest, defaultTrustStore } from "./isolation/artifact.ts";
import { agentIdentityUnavailableReason } from "./isolation/identity.ts";
import { loadVerifiedLauncher } from "./isolation/trusted-entry.ts";

function blocked(reason: string): never {
  process.stdout.write(`${JSON.stringify({ status: "BLOCKED", reason })}\n`);
  process.exit(2);
}

const identity = agentIdentityUnavailableReason();
if (identity !== null) blocked(identity);
const store = defaultTrustStore();
if (approvedDigest(store) === null) blocked(`no approved artifact in ${store}; run trust-cli seal and approve (docs/ISOLATION.md §3)`);

// Verifies the approved artifact before importing any of it.
const { launchIsolatedSystem } = await loadVerifiedLauncher({ store });
const sys = await launchIsolatedSystem();
try {
  const run = await sys.runAgent(join(process.cwd(), "src", "isolation", "agent-main.ts"), [
    sys.paths.publicSocket,
    sys.paths.executorSocket,
    sys.paths.walletKeyPath,
  ]);
  if (run.code !== 0) throw new Error(`agent failed: ${run.stderr}`);
  const { executor, gateway } = sys.pids();
  process.stdout.write(
    `${JSON.stringify(
      {
        artifact: sys.artifact.digest,
        processes: { operator_uid: process.getuid!(), gateway_pid: gateway, executor_pid: executor },
        agent: run.result,
        ledger_payments: sys.ledger().length,
        journal: sys.journal().list().map((r) => ({ intent_hash: r.intent_hash, state: r.state })),
      },
      null,
      2,
    )}\n`,
  );
} finally {
  await sys.stop();
}

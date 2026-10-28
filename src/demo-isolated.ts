// SPDX-License-Identifier: MIT
/**
 * Phase 2B/2C demo: agent, gateway, auth service, and executor, each under its
 * own OS account (oxdeai-agent / -gateway / -auth / -executor), mock
 * payments only.
 *
 *   npm run demo:isolated
 *
 * Launches only the operator-approved artifact from the trust store
 * ($OXDEAI_TRUST_STORE or ~/.oxdeai-celo-poc/trust); never the checkout.
 * Exits 2 (BLOCKED) if there is no approved artifact, no initialized policy
 * state ($OXDEAI_POLICY_STATE_ROOT), no initialized executor state
 * ($OXDEAI_EXECUTOR_STATE_ROOT), or the agent cannot be run as a separate OS
 * identity. Both state roots persist across runs (Phase 2C): the budget, the
 * reservations, the payment journal, and the mock ledger. Agent programs are taken from the current
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
if (!process.env.OXDEAI_POLICY_STATE_ROOT) {
  blocked("no policy state: set OXDEAI_POLICY_STATE_ROOT to an initialized state root (policy-cli.ts provision + init; docs/ISOLATION.md §3b)");
}
if (!process.env.OXDEAI_EXECUTOR_STATE_ROOT) {
  blocked("no executor state: set OXDEAI_EXECUTOR_STATE_ROOT to an initialized executor state root (executor-cli.ts provision + init; docs/DEMO.md)");
}

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
  type Res = { state: string; amount: string; charged: string };
  type PolicyFile = {
    version: number;
    state: { budget: { budget_limit: Record<string, { $bigint: string }>; spent_in_period: Record<string, { $bigint: string }> } };
    reservations: Record<string, Res>;
  };
  const readPolicy = () => JSON.parse(sys.privileged.read(join(sys.paths.authStateDir, "state.json")).toString("utf8")) as PolicyFile;
  // Outcome reports reach the auth service asynchronously: wait (bounded) until no reservation is in flight.
  let policy = readPolicy();
  for (let i = 0; i < 40 && Object.values(policy.reservations).some((r) => r.state === "RESERVED" || r.state === "EXECUTING"); i++) {
    await new Promise((r) => setTimeout(r, 250));
    policy = readPolicy();
  }
  const journal = sys.journal();
  process.stdout.write(
    `${JSON.stringify(
      {
        artifact: sys.artifact.digest,
        processes: { operator_uid: process.getuid!(), gateway_pid: gateway, executor_pid: executor },
        agent: run.result,
        ledger_payments: sys.ledger().length,
        journal: journal.list().map((r) => ({ intent_hash: r.intent_hash, state: r.state })),
        journal_auths: journal.auths().map((a) => ({ auth_id: a.auth_id, disposition: a.disposition })),
        policy_state: {
          version: policy.version,
          budget_limit: Object.fromEntries(Object.entries(policy.state.budget.budget_limit).map(([k, v]) => [k, v.$bigint])),
          spent_in_period: Object.fromEntries(Object.entries(policy.state.budget.spent_in_period).map(([k, v]) => [k, v.$bigint])),
          reservations: Object.fromEntries(Object.entries(policy.reservations).map(([k, r]) => [k, { state: r.state, amount: r.amount, charged: r.charged }])),
        },
      },
      null,
      2,
    )}\n`,
  );
} finally {
  await sys.stop();
}

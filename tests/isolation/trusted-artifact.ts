// SPDX-License-Identifier: MIT
/**
 * Test helper: seal a source tree into a disposable operator-only trust
 * store, approve it, and load the launcher from the sealed artifact.
 *
 * The tests run as the operator from the checkout and therefore trust the
 * checkout at test time (the bootstrap seal, docs/ISOLATION.md §3). Attacks
 * on the working tree are run against disposable copies, never the repo.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { approveArtifact, removeTree, sealArtifact } from "../../src/isolation/artifact.ts";
import type { LaunchOptions } from "../../src/isolation/launcher.ts";
import { initPolicyState, provisionStateRoot } from "../../src/isolation/policy-state-admin.ts";
import { loadVerifiedLauncher } from "../../src/isolation/trusted-entry.ts";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

export function newStore(): string {
  const store = mkdtempSync(join(tmpdir(), "oxdeai-store-"));
  chmodSync(store, 0o700);
  return store;
}

/**
 * A fresh persistent policy state root, provisioned and initialized by the
 * operator (explicit first-time initialization: a new budget is a deliberate
 * fixture step, never a side effect of launching). Removed by `removeStateRoot`.
 */
export function freshPolicyState(opts: { budget?: string; ttlSeconds?: number } = {}): string {
  const parent = mkdtempSync(join(tmpdir(), "oxdeai-state-"));
  chmodSync(parent, 0o711);
  const root = join(parent, "policy");
  provisionStateRoot(root);
  initPolicyState({ stateRoot: root, ...opts });
  return root;
}

export function removeStateRoot(root: string): void {
  spawnSync("sudo", ["-n", "rm", "-rf", "--", dirname(root)]);
}

export type TestLaunchOptions = LaunchOptions & { budget?: string };

/** Verified before anything from the artifact is imported (src/isolation/trusted-entry.ts). */
export function loadLauncher(store: string, digest: string) {
  return loadVerifiedLauncher({ store, digest });
}

export async function trustedArtifact(sourceRoot: string = REPO_ROOT) {
  const store = newStore();
  const { digest } = sealArtifact({ sourceRoot, store });
  approveArtifact(digest, { store, note: "test bootstrap" });
  const launcher = await loadLauncher(store, digest);
  const stateRoots: string[] = [];
  return {
    store,
    digest,
    artifactRoot: join(store, "artifacts", digest),
    /** Launch; without `policyStateRoot`, a fresh state root is initialized with `budget` first. */
    launch: ({ budget, ...opts }: TestLaunchOptions = {}) => {
      let policyStateRoot = opts.policyStateRoot;
      if (policyStateRoot === undefined) {
        policyStateRoot = freshPolicyState({ budget, ttlSeconds: opts.ttlSeconds });
        stateRoots.push(policyStateRoot);
      }
      return launcher.launchIsolatedSystem({ agentCwd: REPO_ROOT, ...opts, policyStateRoot });
    },
    cleanup: () => {
      removeTree(store);
      for (const r of stateRoots.splice(0)) removeStateRoot(r);
    },
  };
}

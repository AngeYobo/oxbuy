// SPDX-License-Identifier: MIT
/**
 * Test helper: seal a source tree into a disposable operator-only trust
 * store, approve it, and load the launcher from the sealed artifact.
 *
 * The tests run as the operator from the checkout and therefore trust the
 * checkout at test time (the bootstrap seal, docs/ISOLATION.md §3). Attacks
 * on the working tree are run against disposable copies, never the repo.
 */
import { chmodSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { approveArtifact, removeTree, sealArtifact } from "../../src/isolation/artifact.ts";
import type { LaunchOptions } from "../../src/isolation/launcher.ts";
import { loadVerifiedLauncher } from "../../src/isolation/trusted-entry.ts";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

export function newStore(): string {
  const store = mkdtempSync(join(tmpdir(), "oxdeai-store-"));
  chmodSync(store, 0o700);
  return store;
}

/** Verified before anything from the artifact is imported (src/isolation/trusted-entry.ts). */
export function loadLauncher(store: string, digest: string) {
  return loadVerifiedLauncher({ store, digest });
}

export async function trustedArtifact(sourceRoot: string = REPO_ROOT) {
  const store = newStore();
  const { digest } = sealArtifact({ sourceRoot, store });
  approveArtifact(digest, { store, note: "test bootstrap" });
  const launcher = await loadLauncher(store, digest);
  return {
    store,
    digest,
    artifactRoot: join(store, "artifacts", digest),
    launch: (opts: LaunchOptions = {}) => launcher.launchIsolatedSystem({ agentCwd: REPO_ROOT, ...opts }),
    cleanup: () => removeTree(store),
  };
}

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
import { chmodSync, lstatSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { approveArtifact, removeTree, sealArtifact } from "../../src/isolation/artifact.ts";
import type { LaunchOptions } from "../../src/isolation/launcher.ts";
import { initExecutorState, provisionExecutorStateRoot } from "../../src/isolation/executor-state-admin.ts";
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
export function freshPolicyState(opts: { budget?: string; ttlSeconds?: number; state?: import("@oxdeai/core").State } = {}): string {
  const parent = mkdtempSync(join(tmpdir(), "oxdeai-state-"));
  chmodSync(parent, 0o711);
  const root = join(parent, "policy");
  provisionStateRoot(root);
  initPolicyState({ stateRoot: root, ...opts });
  return root;
}

/**
 * Fail-closed guard for every recursive test cleanup (Phase 2D, after the
 * 2026-10-28 /tmp incident: evidence/phase-2d/INCIDENT-TMP.md). Returns the
 * canonical path, or throws UNSAFE_CLEANUP_TARGET without touching anything,
 * unless `dir` is a test-owned temporary directory:
 *   - an absolute, normalized path (no `..`, `//`, or trailing `/`);
 *   - a DIRECT child of the canonical temp directory (realpath of
 *     os.tmpdir()), and its parent resolves there (no symlinked parent);
 *   - not itself a symlink (lstat); if it exists, a directory;
 *   - its name is an `oxdeai-` mkdtemp name (prefix + 6 random characters).
 * So `/`, `/tmp`, `/workspaces`, the repository, any ancestor of a test
 * directory, other users' or tools' temp entries, and symlink escapes are
 * all refused.
 */
export function assertDisposableTestDir(dir: string): string {
  const fail = (why: string): never => {
    throw new Error(`UNSAFE_CLEANUP_TARGET:${String(dir)}: ${why}`);
  };
  if (typeof dir !== "string" || !isAbsolute(dir)) return fail("not an absolute path");
  if (resolve(dir) !== dir) fail("not normalized (.., //, or trailing /)");
  const tmpRoot = realpathSync(tmpdir());
  if (dirname(dir) !== tmpRoot) fail(`not a direct child of ${tmpRoot}`);
  let parentReal: string;
  try {
    parentReal = realpathSync(dirname(dir));
  } catch {
    return fail("parent does not resolve");
  }
  if (parentReal !== tmpRoot) fail("parent resolves elsewhere (symlink)");
  if (!/^oxdeai-[A-Za-z0-9-]*[A-Za-z0-9]-[A-Za-z0-9]{6}$/.test(basename(dir))) fail("not an oxdeai- mkdtemp name");
  if (dir === "/" || dir === tmpRoot || dir === "/workspaces" || dir === REPO_ROOT || REPO_ROOT.startsWith(`${dir}/`)) fail("forbidden root");
  let st;
  try {
    st = lstatSync(dir);
  } catch {
    return dir; // does not exist: nothing to remove
  }
  if (st.isSymbolicLink()) fail("is a symlink");
  if (!st.isDirectory()) fail("not a directory");
  return dir;
}

/** Remove a fixture parent (state root, anchor root, or executor state root). Anchor files are append-only: clear the attribute first. */
export function removeStateRoot(root: string): void {
  // `root` is <mkdtemp parent>/<name>; only that mkdtemp parent is removed, and only if it is test-owned.
  const parent = assertDisposableTestDir(dirname(root));
  spawnSync("sudo", ["-n", "chattr", "-R", "-a", parent], { stdio: "ignore" });
  spawnSync("sudo", ["-n", "rm", "-rf", "--", parent]);
}

/** Recursive removal of a test-owned temporary directory (guarded; see assertDisposableTestDir). */
export function removeTestDir(dir: string): void {
  removeTree(assertDisposableTestDir(dir));
}

/** A fresh persistent executor state root with an initialized, empty journal (Phase 2C; N2). Removed by `removeStateRoot`. */
export function freshExecutorState(): string {
  const parent = mkdtempSync(join(tmpdir(), "oxdeai-exec-"));
  chmodSync(parent, 0o711);
  const root = join(parent, "executor");
  provisionExecutorStateRoot(root);
  initExecutorState(root);
  return root;
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
    /**
     * Launch; without `policyStateRoot`, a fresh state root is initialized with
     * `budget` first; without `executorStateRoot`, a fresh executor state root.
     */
    launch: ({ budget, ...opts }: TestLaunchOptions = {}) => {
      let policyStateRoot = opts.policyStateRoot;
      if (policyStateRoot === undefined) {
        policyStateRoot = freshPolicyState({ budget, ttlSeconds: opts.ttlSeconds });
        stateRoots.push(policyStateRoot);
      }
      let executorStateRoot = opts.executorStateRoot;
      if (executorStateRoot === undefined) {
        executorStateRoot = freshExecutorState();
        stateRoots.push(executorStateRoot);
      }
      return launcher.launchIsolatedSystem({ agentCwd: REPO_ROOT, ...opts, policyStateRoot, executorStateRoot });
    },
    cleanup: () => {
      removeTestDir(store);
      for (const r of stateRoots.splice(0)) removeStateRoot(r);
    },
  };
}

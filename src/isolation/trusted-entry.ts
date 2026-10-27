// SPDX-License-Identifier: MIT
/**
 * The only supported way for operator code to obtain the launcher.
 *
 * Importing a module evaluates its whole import graph, so a launcher that
 * verified itself would already have run whatever it imports. This entry
 * imports nothing but Node built-ins and artifact.ts / identity.ts (which
 * themselves import only built-ins), verifies the artifact completely, and
 * only then imports the launcher from it. Nothing from an unverified or
 * unapproved artifact is ever evaluated.
 *
 * Root of trust: this file must itself be loaded from a location the agent
 * cannot write (the approved artifact in an operator-only store, or the
 * checkout at bootstrap time while it is trusted). See docs/ISOLATION.md §3.
 */
import { join } from "node:path";
import { ArtifactError, approvedDigest, defaultTrustStore, verifyArtifact } from "./artifact.ts";

type Launcher = typeof import("./launcher.ts");

export async function loadVerifiedLauncher(opts: { store?: string; digest?: string } = {}): Promise<Launcher & { digest: string }> {
  const store = opts.store ?? defaultTrustStore();
  const approved = approvedDigest(store);
  if (approved === null) throw new ArtifactError("ARTIFACT_NO_APPROVAL", store);
  const digest = opts.digest ?? approved;
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new ArtifactError("ARTIFACT_INVALID_DIGEST");
  const root = join(store, "artifacts", digest);
  verifyArtifact(root); // throws on anything but the approved, intact, agent-unwritable artifact
  const launcher = (await import(join(root, "src", "isolation", "launcher.ts"))) as Launcher;
  return { ...launcher, digest };
}

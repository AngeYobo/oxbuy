// SPDX-License-Identifier: MIT
/**
 * Trusted deployment artifacts.
 *
 * The working tree is writable by the agent identity in this Codespace, so
 * no trusted process may run code from it. Trusted code runs only from a
 * sealed, operator-approved artifact in an operator-only trust store:
 *
 *   <store>/                       0700, operator
 *     approved                     0400  digest of the approved artifact
 *     approvals.log                0600  append-only approval history
 *     artifacts/<digest>/          0555 dirs / 0444 files
 *       MANIFEST.json              sha256 of every other file; <digest> = sha256(MANIFEST.json)
 *       package.json               fixed: { "type": "module" }
 *       src/**                     application source, copied at seal time
 *       node_modules/@oxdeai/..., node_modules/@noble/...   extracted from registry tarballs verified below
 *
 * Trust anchors:
 *   - Dependencies: the operator's npm cache (`~/.npm/_cacache`, not
 *     reachable by the agent). The cache index records the integrity of the
 *     tarball the registry served for the pinned URL; the tarball is
 *     re-hashed and extracted. `node_modules` in the working tree is never
 *     used. The lockfile is only cross-checked.
 *   - Application source: an explicit operator approval of the sealed
 *     digest (`approveArtifact`). There is no independent reference for
 *     uncommitted source; the approval is the operator's attestation, and the
 *     seal reports every file that differs from the currently approved
 *     artifact.
 *
 * `verifyArtifact` (run by the launcher before anything starts) requires: the
 * artifact is the approved one; every file matches the manifest and there
 * are no extra files or symlinks; everything is owned by the operator and
 * has no write bits; and, checked by the kernel as the agent identity, the
 * agent cannot write the artifact, the store, the approval, any ancestor
 * directory (a sticky ancestor is accepted when the next component is
 * operator- or root-owned), or the node binary and its directories.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { ROLES, writableBy } from "./identity.ts";

/** Dependencies the trusted runtime may load, pinned here, not in the lockfile. */
export const TRUSTED_DEPENDENCIES = [
  { name: "@oxdeai/core", version: "2.0.2" },
  { name: "@oxdeai/guard", version: "2.0.3" },
  // x402 testnet rail (src/chain/evm.ts): keccak-256 and secp256k1. Audited, zero-dependency; 2.2.0
  // rebuilt from the git tags reproduces the registry tarballs byte for byte (docs/TESTNET-X402.md §8).
  { name: "@noble/hashes", version: "2.2.0" },
  { name: "@noble/curves", version: "2.2.0" },
] as const;

const REGISTRY = "https://registry.npmjs.org";
const ARTIFACT_PACKAGE_JSON = `${JSON.stringify({ name: "oxdeai-celo-poc-runtime", private: true, type: "module" })}\n`;

export class ArtifactError extends Error {
  constructor(code: string, detail = "") {
    super(detail ? `${code}:${detail}` : code);
    this.name = "ArtifactError";
  }
}

export type ManifestDependency = { name: string; version: string; resolved: string; integrity: string };
export type ManifestFile = { path: string; sha256: string; size: number };
export type Manifest = {
  schema: "oxdeai-celo-poc/artifact/v1";
  dependencies: ManifestDependency[];
  files: ManifestFile[];
};

export function defaultTrustStore(): string {
  return process.env.OXDEAI_TRUST_STORE ?? join(homedir(), ".oxdeai-celo-poc", "trust");
}

const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");

/** Every regular file under `root`, relative paths, sorted. Symlinks and specials are rejected. */
function walk(root: string, code: string): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) throw new ArtifactError(code, `symlink ${relative(root, p)}`);
      if (st.isDirectory()) visit(p);
      else if (st.isFile()) out.push(relative(root, p).split(sep).join("/"));
      else throw new ArtifactError(code, `not a regular file ${relative(root, p)}`);
    }
  };
  visit(root);
  return out.sort();
}

function setReadOnly(root: string): void {
  const visit = (p: string) => {
    if (lstatSync(p).isDirectory()) {
      for (const name of readdirSync(p)) visit(join(p, name));
      chmodSync(p, 0o555);
    } else {
      chmodSync(p, 0o444);
    }
  };
  visit(root);
}

/** Make an artifact tree removable again (operator cleanup only). */
export function removeTree(path: string): void {
  if (!existsSync(path)) return;
  spawnSync("chmod", ["-R", "u+rwX", path]);
  rmSync(path, { recursive: true, force: true });
}

function secureStore(store: string): void {
  mkdirSync(join(store, "artifacts"), { recursive: true });
  chmodSync(store, 0o700);
  chmodSync(join(store, "artifacts"), 0o700);
}

/** Resolve a dependency tarball from the operator's npm cache and verify it. */
function cachedTarball(dep: { name: string; version: string }, cacheDir: string): { path: string; resolved: string; integrity: string } {
  const resolved = `${REGISTRY}/${dep.name}/-/${dep.name.split("/").pop()}-${dep.version}.tgz`;
  const key = `make-fetch-happen:request-cache:${resolved}`;
  const bucket = sha256(key);
  const indexPath = join(cacheDir, "index-v5", bucket.slice(0, 2), bucket.slice(2, 4), bucket.slice(4));
  let integrity: string | undefined;
  try {
    for (const line of readFileSync(indexPath, "utf8").split("\n")) {
      if (!line) continue;
      const entry = JSON.parse(line.slice(line.indexOf("\t") + 1)) as { key?: string; integrity?: string | null };
      if (entry.key === key) integrity = entry.integrity ?? undefined; // last entry wins
    }
  } catch (err) {
    throw new ArtifactError("SEAL_DEPENDENCY_NOT_IN_OPERATOR_CACHE", `${dep.name}@${dep.version} (${(err as NodeJS.ErrnoException).code})`);
  }
  if (!integrity?.startsWith("sha512-")) throw new ArtifactError("SEAL_DEPENDENCY_NOT_IN_OPERATOR_CACHE", `${dep.name}@${dep.version}`);
  const hex = Buffer.from(integrity.slice(7), "base64").toString("hex");
  const path = join(cacheDir, "content-v2", "sha512", hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
  const actual = `sha512-${createHash("sha512").update(readFileSync(path)).digest("base64")}`;
  if (actual !== integrity) throw new ArtifactError("SEAL_DEPENDENCY_INTEGRITY_MISMATCH", dep.name);
  return { path, resolved, integrity };
}

export type SealResult = {
  digest: string;
  artifactRoot: string;
  /** Differences from the currently approved artifact; null if none approved. */
  changesFromApproved: { added: string[]; removed: string[]; changed: string[] } | null;
};

/**
 * Seal `sourceRoot/src` plus the pinned dependencies into an immutable
 * artifact. Does not approve it.
 */
export function sealArtifact(opts: { sourceRoot: string; store?: string; npmCache?: string }): SealResult {
  const store = opts.store ?? defaultTrustStore();
  const cache = opts.npmCache ?? join(homedir(), ".npm", "_cacache");
  secureStore(store);
  const staging = mkdtempSync(join(store, "staging-"));
  try {
    // Application source: read once, hash what is written.
    const srcRoot = join(opts.sourceRoot, "src");
    for (const rel of walk(srcRoot, "SEAL_SOURCE_REJECTED")) {
      const data = readFileSync(join(srcRoot, rel));
      mkdirSync(dirname(join(staging, "src", rel)), { recursive: true });
      writeFileSync(join(staging, "src", rel), data);
    }
    writeFileSync(join(staging, "package.json"), ARTIFACT_PACKAGE_JSON);

    // Dependencies: from verified tarballs, never from the working tree.
    let lock: { packages?: Record<string, { version?: string; integrity?: string }> } = {};
    try {
      lock = JSON.parse(readFileSync(join(opts.sourceRoot, "package-lock.json"), "utf8"));
    } catch {
      throw new ArtifactError("SEAL_LOCKFILE_UNREADABLE");
    }
    const dependencies: ManifestDependency[] = [];
    for (const dep of TRUSTED_DEPENDENCIES) {
      const tarball = cachedTarball(dep, cache);
      const locked = lock.packages?.[`node_modules/${dep.name}`];
      if (locked?.version !== dep.version || locked?.integrity !== tarball.integrity) {
        throw new ArtifactError("SEAL_LOCKFILE_MISMATCH", dep.name);
      }
      const dest = join(staging, "node_modules", dep.name);
      mkdirSync(dest, { recursive: true });
      const tar = spawnSync(
        "/usr/bin/tar",
        ["-xzf", tarball.path, "-C", dest, "--strip-components=1", "--no-same-owner", "--no-same-permissions"],
        { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } },
      );
      if (tar.status !== 0) throw new ArtifactError("SEAL_DEPENDENCY_EXTRACT_FAILED", `${dep.name}: ${tar.stderr.trim()}`);
      walk(dest, "SEAL_DEPENDENCY_REJECTED");
      const pkg = JSON.parse(readFileSync(join(dest, "package.json"), "utf8")) as { name?: string; version?: string };
      if (pkg.name !== dep.name || pkg.version !== dep.version) throw new ArtifactError("SEAL_DEPENDENCY_IDENTITY_MISMATCH", dep.name);
      dependencies.push({ name: dep.name, version: dep.version, resolved: tarball.resolved, integrity: tarball.integrity });
    }

    const files = walk(staging, "SEAL_REJECTED").map((path) => {
      const data = readFileSync(join(staging, path));
      return { path, sha256: sha256(data), size: data.length };
    });
    const manifest: Manifest = { schema: "oxdeai-celo-poc/artifact/v1", dependencies, files };
    const manifestBytes = JSON.stringify(manifest);
    writeFileSync(join(staging, "MANIFEST.json"), manifestBytes);
    const digest = sha256(manifestBytes);

    // Renaming a directory needs write on it (its ".." changes), so the tree is
    // made read-only after the move. The store is operator-only throughout.
    const artifactRoot = join(store, "artifacts", digest);
    if (existsSync(artifactRoot)) {
      removeTree(staging);
    } else {
      renameSync(staging, artifactRoot);
      setReadOnly(artifactRoot);
    }

    const approved = approvedDigest(store);
    let changesFromApproved: SealResult["changesFromApproved"] = null;
    if (approved !== null) {
      const prev = new Map(readManifest(join(store, "artifacts", approved)).files.map((f) => [f.path, f.sha256]));
      const next = new Map(files.map((f) => [f.path, f.sha256]));
      changesFromApproved = {
        added: [...next.keys()].filter((p) => !prev.has(p)),
        removed: [...prev.keys()].filter((p) => !next.has(p)),
        changed: [...next.keys()].filter((p) => prev.has(p) && prev.get(p) !== next.get(p)),
      };
    }
    return { digest, artifactRoot, changesFromApproved };
  } catch (err) {
    removeTree(staging);
    throw err;
  }
}

function readManifest(artifactRoot: string): Manifest {
  return JSON.parse(readFileSync(join(artifactRoot, "MANIFEST.json"), "utf8")) as Manifest;
}

export function approvedDigest(store: string = defaultTrustStore()): string | null {
  try {
    const d = readFileSync(join(store, "approved"), "utf8").trim();
    return /^[0-9a-f]{64}$/.test(d) ? d : null;
  } catch {
    return null;
  }
}

/** Operator attestation: approve a sealed artifact after verifying it. */
export function approveArtifact(digest: string, opts: { store?: string; note?: string } = {}): void {
  const store = opts.store ?? defaultTrustStore();
  verifyArtifactContent(join(store, "artifacts", digest), digest);
  const tmp = join(store, `approved.tmp-${process.pid}`);
  writeFileSync(tmp, `${digest}\n`, { mode: 0o400, flag: "wx" });
  chmodSync(tmp, 0o400);
  renameSync(tmp, join(store, "approved"));
  appendFileSync(join(store, "approvals.log"), `${JSON.stringify({ at: new Date().toISOString(), digest, note: opts.note ?? "" })}\n`, { mode: 0o600 });
  chmodSync(join(store, "approvals.log"), 0o600);
}

/** Content checks: manifest digest, exact file set, hashes, modes, owner. */
function verifyArtifactContent(artifactRoot: string, digest: string): Manifest {
  const uid = process.getuid!();
  let manifestBytes: Buffer;
  try {
    manifestBytes = readFileSync(join(artifactRoot, "MANIFEST.json"));
  } catch {
    throw new ArtifactError("ARTIFACT_MISSING", artifactRoot);
  }
  if (sha256(manifestBytes) !== digest) throw new ArtifactError("ARTIFACT_MANIFEST_DIGEST_MISMATCH");
  const manifest = JSON.parse(manifestBytes.toString("utf8")) as Manifest;
  const onDisk = walk(artifactRoot, "ARTIFACT_REJECTED").filter((p) => p !== "MANIFEST.json");
  const listed = manifest.files.map((f) => f.path);
  if (onDisk.length !== listed.length || onDisk.some((p, i) => p !== listed[i])) {
    throw new ArtifactError("ARTIFACT_FILE_SET_MISMATCH");
  }
  for (const f of manifest.files) {
    if (sha256(readFileSync(join(artifactRoot, f.path))) !== f.sha256) throw new ArtifactError("ARTIFACT_HASH_MISMATCH", f.path);
  }
  const check = (p: string) => {
    const st = lstatSync(p);
    if (st.uid !== uid) throw new ArtifactError("ARTIFACT_OWNER_MISMATCH", relative(artifactRoot, p) || ".");
    if (st.mode & 0o222) throw new ArtifactError("ARTIFACT_WRITABLE_MODE", relative(artifactRoot, p) || ".");
    if (st.isDirectory()) for (const n of readdirSync(p)) check(join(p, n));
  };
  check(artifactRoot);
  return manifest;
}

function allPaths(root: string): string[] {
  const out = [root];
  if (lstatSync(root).isDirectory()) for (const n of readdirSync(root)) out.push(...allPaths(join(root, n)));
  return out;
}

function ancestors(path: string): string[] {
  const out: string[] = [];
  let p = path;
  while (dirname(p) !== p) {
    p = dirname(p);
    out.push(p);
  }
  return out;
}

/**
 * Full pre-launch verification of the artifact that contains `artifactRoot`.
 * Throws ArtifactError on any failure; never returns a partial result.
 */
export function verifyArtifact(artifactRoot: string): { digest: string; store: string; manifest: Manifest } {
  const root = realpathSync(artifactRoot);
  const artifactsDir = dirname(root);
  const store = dirname(artifactsDir);
  if (basename(artifactsDir) !== "artifacts") throw new ArtifactError("UNTRUSTED_LAUNCHER_LOCATION", root);
  const digest = basename(root);
  const approved = approvedDigest(store);
  if (approved === null) throw new ArtifactError("ARTIFACT_NO_APPROVAL", store);
  if (approved !== digest) throw new ArtifactError("ARTIFACT_NOT_APPROVED", digest);
  const manifest = verifyArtifactContent(root, digest);

  const uid = process.getuid!();
  for (const p of [store, artifactsDir, join(store, "approved")]) {
    const st = lstatSync(p);
    if (st.uid !== uid) throw new ArtifactError("TRUST_STORE_OWNER_MISMATCH", p);
    if (st.mode & 0o022) throw new ArtifactError("TRUST_STORE_WRITABLE_MODE", p);
  }

  // Kernel check as every non-operator identity (agent and the three services).
  const node = realpathSync(process.execPath);
  assertUntrustedCannotWrite(
    [...allPaths(root), artifactsDir, store, join(store, "approved"), node, ...ancestors(store), ...ancestors(node)],
    { anchors: [store, node], protectedRoots: [store, node] },
  );
  return { digest, store, manifest };
}

/**
 * Throws unless no non-operator identity (agent, gateway, auth, executor) can
 * write any of `candidates`, as answered by the kernel for each identity. A
 * writable ancestor of an anchor is accepted only if it is sticky (e.g. /tmp)
 * and the anchor's next path component is operator- or root-owned and itself
 * not writable: the identity can then add its own entries but not rename or
 * replace ours. Nothing at or under a protected root may be writable.
 */
export function assertUntrustedCannotWrite(
  candidates: readonly string[],
  opts: { anchors: readonly string[]; protectedRoots: readonly string[] },
): void {
  const uid = process.getuid!();
  for (const role of ROLES) {
    const writable = new Set(writableBy(role, candidates));
    for (const p of writable) {
      const isAncestor = (child: string) => child !== p && child.startsWith(p === "/" ? "/" : `${p}/`);
      const insideProtected = opts.protectedRoots.some((r) => p === r || p.startsWith(`${r}/`));
      const sticky = (statSync(p).mode & 0o1000) !== 0;
      const next = opts.anchors.filter(isAncestor).map((c) => join(p, relative(p, c).split("/")[0]!));
      const ownedByUs = next.length > 0 && next.every((c) => [uid, 0].includes(lstatSync(c).uid) && !writable.has(c));
      if (insideProtected || !(sticky && ownedByUs)) {
        throw role === "agent" ? new ArtifactError("ARTIFACT_AGENT_WRITABLE", p) : new ArtifactError("ARTIFACT_SERVICE_WRITABLE", `${role}:${p}`);
      }
    }
  }
}

/** Every path under `root`, and `root`. */
export function treePaths(root: string): string[] {
  return allPaths(root);
}

export { ancestors as ancestorDirs };

/**
 * Verify a copy of an artifact against its manifest (file set + hashes).
 * Used for the deployed runtime copy that the service identities read.
 */
export function verifyCopy(copyRoot: string, manifest: Manifest): void {
  const onDisk = walk(copyRoot, "DEPLOY_REJECTED").filter((p) => p !== "MANIFEST.json");
  const listed = manifest.files.map((f) => f.path);
  if (onDisk.length !== listed.length || onDisk.some((p, i) => p !== listed[i])) throw new ArtifactError("DEPLOY_FILE_SET_MISMATCH");
  for (const f of manifest.files) {
    if (sha256(readFileSync(join(copyRoot, f.path))) !== f.sha256) throw new ArtifactError("DEPLOY_HASH_MISMATCH", f.path);
  }
}

export { setReadOnly };

/** Root of the artifact this module was loaded from (or of the checkout). */
export function selfRoot(moduleUrlPath: string): string {
  return resolve(dirname(moduleUrlPath), "../..");
}

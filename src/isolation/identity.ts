// SPDX-License-Identifier: MIT
/**
 * OS identities of the four security domains, and kernel-checked access
 * tests run as them.
 *
 *   agent     oxdeai-agent     untrusted
 *   gateway   oxdeai-gateway   PEP, request routing; no signing key, no wallet
 *   auth      oxdeai-auth      PDP + authorization signer; no wallet
 *   executor  oxdeai-executor  payment capability, ledger, journal; no signing key
 *
 * Each is a dedicated system account (no login shell, locked password, no
 * sudo, only its own primary group). The operator assumes them through
 * `sudo -n setpriv --reuid --regid --clear-groups --no-new-privs --reset-env`.
 * If any account is missing, isolation is BLOCKED; there is no fallback.
 */
import { spawnSync } from "node:child_process";

export type Role = "agent" | "gateway" | "auth" | "executor";
export const ROLES: readonly Role[] = ["agent", "gateway", "auth", "executor"];

export const ACCOUNT_NAMES: Readonly<Record<Role, string>> = {
  agent: "oxdeai-agent",
  gateway: "oxdeai-gateway",
  auth: "oxdeai-auth",
  executor: "oxdeai-executor",
};

export type Identity = { readonly name: string; readonly uid: number; readonly gid: number };

function lookup(name: string): Identity | null {
  const r = spawnSync("getent", ["passwd", name], { encoding: "utf8" });
  if (r.status !== 0) return null;
  const [, , uid, gid] = r.stdout.trim().split(":");
  return { name, uid: Number(uid), gid: Number(gid) };
}

const cache = new Map<Role, Identity | null>();

/** The identity of `role`, or null if its account does not exist. */
export function identityOf(role: Role): Identity | null {
  if (!cache.has(role)) {
    // Hook for negative controls (e.g. pointing the agent at the operator uid).
    // It is also honored by the deployed launcher, and only uids are checked
    // for distinctness, not gids: an agent gid equal to the gateway's lets the
    // agent reach the auth and executor sockets (F5, docs/ISOLATION.md B7).
    const envUid = role === "agent" ? process.env.OXDEAI_AGENT_UID : undefined;
    const id = envUid !== undefined
      ? { name: `uid-${envUid}`, uid: Number(envUid), gid: Number(process.env.OXDEAI_AGENT_GID ?? envUid) }
      : lookup(ACCOUNT_NAMES[role]);
    cache.set(role, id);
  }
  return cache.get(role)!;
}

function required(role: Role): Identity {
  const id = identityOf(role);
  if (id === null) throw new Error(`IDENTITY_MISSING:${ACCOUNT_NAMES[role]}`);
  return id;
}

export const AGENT_UID = identityOf("agent")?.uid ?? -1;
export const AGENT_GID = identityOf("agent")?.gid ?? -1;

export function commandAs(role: Role, argv: readonly string[]): [string, string[]] {
  const id = required(role);
  return [
    "sudo",
    ["-n", "/usr/bin/setpriv", `--reuid=${id.uid}`, `--regid=${id.gid}`, "--clear-groups", "--no-new-privs", "--reset-env", "--", ...argv],
  ];
}

export function agentCommand(argv: readonly string[]): [string, string[]] {
  return commandAs("agent", argv);
}

/**
 * Null when every domain has its own identity, distinct from each other and
 * from the operator, and the operator can assume each one; otherwise why not.
 */
export function identitiesUnavailableReason(roles: readonly Role[] = ROLES): string | null {
  const seen = new Set<number>([process.getuid!(), 0]);
  for (const role of roles) {
    const id = identityOf(role);
    if (id === null) return `account ${ACCOUNT_NAMES[role]} does not exist`;
    if (seen.has(id.uid)) return `${role} uid ${id.uid} is not distinct from the operator, root, or another domain`;
    seen.add(id.uid);
    const [cmd, args] = commandAs(role, ["/usr/bin/id", "-u"]);
    const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 10_000 });
    if (r.status !== 0) return `cannot switch to ${role} (uid ${id.uid}): ${(r.stderr || r.error?.message || "").trim()}`;
    if (r.stdout.trim() !== String(id.uid)) return `identity switch for ${role} produced uid ${r.stdout.trim()}`;
  }
  return null;
}

/** Kept for existing callers: all four domains must be available. */
export function agentIdentityUnavailableReason(): string | null {
  return identitiesUnavailableReason();
}

const ACCESS_PROBE =
  'const fs=require("fs");const w=[];for(const p of JSON.parse(fs.readFileSync(0,"utf8"))){try{fs.accessSync(p,fs.constants.W_OK);w.push(p)}catch{}}process.stdout.write(JSON.stringify(w))';

/**
 * The subset of `paths` that `role` can write, as answered by the kernel
 * (access(2) as that identity: mode bits and ACLs both count). Throws if the
 * check cannot be run; callers must fail closed.
 */
export function writableBy(role: Role, paths: readonly string[]): string[] {
  const [cmd, args] = commandAs(role, [process.execPath, "-e", ACCESS_PROBE]);
  const r = spawnSync(cmd, args, { input: JSON.stringify(paths), encoding: "utf8", timeout: 30_000 });
  if (r.status !== 0) throw new Error(`ACCESS_CHECK_UNAVAILABLE:${role}:${(r.stderr || r.error?.message || "").trim()}`);
  return JSON.parse(r.stdout) as string[];
}

export function agentWritable(paths: readonly string[]): string[] {
  return writableBy("agent", paths);
}

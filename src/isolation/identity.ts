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
/** An identity plus what the group database says about its primary group. */
export type IdentityFacts = Identity & { readonly groupName: string | null; readonly groupMembers: readonly string[] };

function lookup(name: string): Identity | null {
  const r = spawnSync("getent", ["passwd", name], { encoding: "utf8" });
  if (r.status !== 0) return null;
  const [, , uid, gid] = r.stdout.trim().split(":");
  return { name, uid: Number(uid), gid: Number(gid) };
}

function groupOf(gid: number): { name: string; members: string[] } | null {
  const r = spawnSync("getent", ["group", String(gid)], { encoding: "utf8" });
  if (r.status !== 0) return null;
  const [name, , , members] = r.stdout.trim().split(":");
  return { name: name!, members: (members ?? "").split(",").filter(Boolean) };
}

const cache = new Map<Role, Identity | null>();

/**
 * The identity of `role`, looked up by its account name only, or null if the
 * account does not exist. There is no override (Phase 2C; F5): the former
 * OXDEAI_AGENT_UID / OXDEAI_AGENT_GID variables are ignored.
 */
export function identityOf(role: Role): Identity | null {
  if (!cache.has(role)) cache.set(role, lookup(ACCOUNT_NAMES[role]));
  return cache.get(role)!;
}

/**
 * Pure check of a full identity configuration (Phase 2C; F5). Null if safe,
 * otherwise the reason. Rejects, before anything starts:
 *   - a missing role, or an account whose name is not the expected one;
 *   - a uid or gid shared with root, the operator, or another role
 *     (e.g. an agent in the gateway's group would reach the auth and
 *     executor sockets, whose directories admit the gateway's group);
 *   - a primary group that is missing or has supplementary members (another
 *     account could join a domain's group);
 *   - a role's account listed as a member of another role's group.
 */
export function validateIdentities(ids: Partial<Record<Role, IdentityFacts>>, operator: { uid: number; gid: number }): string | null {
  const uids = new Map<number, string>([
    [0, "root"],
    [operator.uid, "the operator"],
  ]);
  const gids = new Map<number, string>([
    [0, "root"],
    [operator.gid, "the operator"],
  ]);
  for (const role of ROLES) {
    const id = ids[role];
    if (!id) return `account ${ACCOUNT_NAMES[role]} does not exist`;
    if (id.name !== ACCOUNT_NAMES[role]) return `${role} must be the account ${ACCOUNT_NAMES[role]}, not ${id.name}`;
    if (!Number.isSafeInteger(id.uid) || id.uid < 0 || !Number.isSafeInteger(id.gid) || id.gid < 0) return `${role} has an invalid uid/gid`;
    const u = uids.get(id.uid);
    if (u) return `${role} uid ${id.uid} is not distinct from ${u}`;
    uids.set(id.uid, role);
    const g = gids.get(id.gid);
    if (g) return `${role} gid ${id.gid} is not distinct from ${g}`;
    gids.set(id.gid, role);
    if (id.groupName === null) return `${role} primary group ${id.gid} does not exist`;
    if (id.groupMembers.length > 0) return `${role} primary group ${id.groupName} has members (${id.groupMembers.join(",")})`;
  }
  for (const role of ROLES) {
    for (const other of ROLES) {
      if (other !== role && ids[other]!.groupMembers.includes(ACCOUNT_NAMES[role])) return `${role} is a member of ${other}'s group`;
    }
  }
  return null;
}

/** The configured identities with their group facts, as the system reports them. */
export function identityFacts(): Partial<Record<Role, IdentityFacts>> {
  const out: Partial<Record<Role, IdentityFacts>> = {};
  for (const role of ROLES) {
    const id = identityOf(role);
    if (!id) continue;
    const g = groupOf(id.gid);
    out[role] = { ...id, groupName: g?.name ?? null, groupMembers: g?.members ?? [] };
  }
  return out;
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
 * Null when the four identities pass `validateIdentities` and the operator
 * can assume each one (kernel-reported uid and gid match); otherwise why not.
 */
export function identitiesUnavailableReason(roles: readonly Role[] = ROLES): string | null {
  const invalid = validateIdentities(identityFacts(), { uid: process.getuid!(), gid: process.getgid!() });
  if (invalid !== null) return invalid;
  for (const role of roles) {
    const id = identityOf(role)!;
    const [cmd, args] = commandAs(role, ["/bin/sh", "-c", "echo $(id -u) $(id -g) $(id -G)"]);
    const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 10_000 });
    if (r.status !== 0) return `cannot switch to ${role} (uid ${id.uid}): ${(r.stderr || r.error?.message || "").trim()}`;
    if (r.stdout.trim() !== `${id.uid} ${id.gid} ${id.gid}`) return `identity switch for ${role} produced ${r.stdout.trim()}`;
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

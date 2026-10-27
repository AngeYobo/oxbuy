// SPDX-License-Identifier: MIT
/**
 * The agent's OS identity and kernel-checked access tests run as it.
 *
 * The agent identity is assumed through
 * `sudo -n setpriv --reuid --regid --clear-groups --no-new-privs --reset-env`.
 * No account is created and no system configuration is changed.
 */
import { spawnSync } from "node:child_process";

/** The agent's OS identity. Default: the existing `nobody` account. */
export const AGENT_UID = Number(process.env.OXDEAI_AGENT_UID ?? 65534);
export const AGENT_GID = Number(process.env.OXDEAI_AGENT_GID ?? 65534);

export function agentCommand(argv: readonly string[]): [string, string[]] {
  return [
    "sudo",
    [
      "-n",
      "/usr/bin/setpriv",
      `--reuid=${AGENT_UID}`,
      `--regid=${AGENT_GID}`,
      "--clear-groups",
      "--no-new-privs",
      "--reset-env",
      "--",
      ...argv,
    ],
  ];
}

/**
 * Null when agent programs can be run as a distinct, unprivileged OS
 * identity here; otherwise why not.
 */
export function agentIdentityUnavailableReason(): string | null {
  if (process.getuid?.() === AGENT_UID) return `operator already runs as uid ${AGENT_UID}`;
  const [cmd, args] = agentCommand(["/usr/bin/id", "-u"]);
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 10_000 });
  if (r.status !== 0) return `cannot switch to uid ${AGENT_UID}: ${(r.stderr || r.error?.message || "").trim()}`;
  if (r.stdout.trim() !== String(AGENT_UID)) return `identity switch produced uid ${r.stdout.trim()}`;
  return null;
}

const ACCESS_PROBE =
  'const fs=require("fs");const w=[];for(const p of JSON.parse(fs.readFileSync(0,"utf8"))){try{fs.accessSync(p,fs.constants.W_OK);w.push(p)}catch{}}process.stdout.write(JSON.stringify(w))';

/**
 * The subset of `paths` the agent identity can write, as answered by the
 * kernel (access(2) as the agent, so mode bits and ACLs both count).
 * Throws if the check cannot be run: callers must fail closed.
 */
export function agentWritable(paths: readonly string[]): string[] {
  const [cmd, args] = agentCommand([process.execPath, "-e", ACCESS_PROBE]);
  const r = spawnSync(cmd, args, { input: JSON.stringify(paths), encoding: "utf8", timeout: 30_000 });
  if (r.status !== 0) throw new Error(`AGENT_ACCESS_CHECK_UNAVAILABLE:${(r.stderr || r.error?.message || "").trim()}`);
  return JSON.parse(r.stdout) as string[];
}

// SPDX-License-Identifier: MIT
/**
 * Operator administration of the persistent policy state (budget, velocity,
 * nonces) used by the authorization service.
 *
 * Policy state lives outside any deployment's runtime directory, under an
 * operator-provisioned state root:
 *
 *   <stateRoot>/                   oxdeai-auth:oxdeai-auth 0700   (provisionStateRoot)
 *     <binding id>/                oxdeai-auth:oxdeai-auth 0700   (initPolicyState, once)
 *       state.json                 0600  {"format","binding","version","state"}
 *       writer.lock                flock(1) target; held by the running auth service
 *       decisions.jsonl            0600  decision audit log
 *
 * The binding id is a hash of (issuer, policy_id, policy_version, agent_id),
 * so a deployment with a different policy identity looks in a different
 * directory and finds no state: it refuses to start rather than reusing or
 * resetting another policy's budget. The binding is also stored inside
 * state.json and checked on every open.
 *
 * Initialization is explicit and happens once: `mkdir` of the binding
 * directory (without -p) is the atomic "first time" test, and state.json is
 * moved into place with a rename. A second initialization fails with
 * POLICY_STATE_EXISTS and does not touch the existing state. A partially
 * initialized directory has no state.json, so the auth service refuses to
 * start and re-initialization is refused: the operator must inspect it.
 */
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../authorization/policy-state.ts";
import { initialStateFile, type PolicyBinding } from "../authorization/policy-state-file.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, initialPolicyState, PDP_ISSUER, POLICY, POLICY_VERSION } from "../system.ts";
import { identityOf } from "./identity.ts";

export type PolicySettings = { readonly ttlSeconds?: number };

/** The policy identity a deployment's authorization service will run with. */
export function policyBinding(settings: PolicySettings = {}): PolicyBinding {
  const authority = createAuthorizationService({
    policyVersion: POLICY_VERSION,
    issuer: PDP_ISSUER,
    audience: GATEWAY_AUDIENCE,
    agentId: AGENT_ID,
    ttlSeconds: settings.ttlSeconds ?? POLICY.ttlSeconds,
    stateStore: createInMemoryPolicyStateStore(undefined),
    now: () => Math.floor(Date.now() / 1000),
  }).trustMaterial.authority;
  return { issuer: authority.issuer, policyId: authority.policyId, policyVersion: POLICY_VERSION, agentId: AGENT_ID };
}

export function bindingId(b: PolicyBinding): string {
  return createHash("sha256").update(JSON.stringify([b.issuer, b.policyId, b.policyVersion, b.agentId])).digest("hex");
}

export function policyStateDir(stateRoot: string, b: PolicyBinding): string {
  return join(stateRoot, bindingId(b));
}

function sudo(args: readonly string[]): { status: number | null; stderr: string } {
  const r = spawnSync("sudo", ["-n", ...args], { encoding: "utf8" });
  return { status: r.status, stderr: (r.stderr ?? "").trim() };
}

function must(args: readonly string[], code: string): void {
  const r = sudo(args);
  if (r.status !== 0) throw new Error(`${code}:${r.stderr}`);
}

/** Create (or re-assert ownership of) the state root: oxdeai-auth 0700. Idempotent; never touches existing state. */
export function provisionStateRoot(stateRoot: string): void {
  const auth = identityOf("auth");
  if (!auth) throw new Error("IDENTITY_MISSING:oxdeai-auth");
  must(["install", "-d", "-o", String(auth.uid), "-g", String(auth.gid), "-m", "0700", stateRoot], "STATE_ROOT_PROVISION_FAILED");
}

/**
 * First-time initialization of the policy state for one policy identity.
 * Throws POLICY_STATE_EXISTS if this binding was ever initialized under the root.
 */
export function initPolicyState(opts: { stateRoot: string; budget?: string; ttlSeconds?: number }): { binding: PolicyBinding; stateDir: string } {
  const auth = identityOf("auth");
  if (!auth) throw new Error("IDENTITY_MISSING:oxdeai-auth");
  const binding = policyBinding({ ttlSeconds: opts.ttlSeconds });
  const stateDir = policyStateDir(opts.stateRoot, binding);

  // Atomic "first time" test: mkdir without -p fails if the directory exists.
  const mk = sudo(["mkdir", "-m", "0700", stateDir]);
  if (mk.status !== 0) {
    throw new Error(/exists/i.test(mk.stderr) ? `POLICY_STATE_EXISTS:${stateDir}` : `POLICY_STATE_INIT_FAILED:${mk.stderr}`);
  }
  const state = initialPolicyState();
  if (opts.budget !== undefined) state.budget.budget_limit[binding.agentId] = BigInt(opts.budget);

  const staging = mkdtempSync(join(tmpdir(), "oxdeai-init-"));
  chmodSync(staging, 0o700);
  const tmp = join(staging, "state.json");
  try {
    writeFileSync(tmp, initialStateFile(binding, state), { mode: 0o600, flag: "wx" });
    chmodSync(tmp, 0o600);
    const pending = join(stateDir, `state.json.init-${randomBytes(4).toString("hex")}`);
    must(["install", "-o", String(auth.uid), "-g", String(auth.gid), "-m", "0600", tmp, pending], "POLICY_STATE_INIT_FAILED");
    must(["mv", "-T", pending, join(stateDir, "state.json")], "POLICY_STATE_INIT_FAILED");
    must(["chown", `${auth.uid}:${auth.gid}`, stateDir], "POLICY_STATE_INIT_FAILED");
    must(["chmod", "0700", stateDir], "POLICY_STATE_INIT_FAILED");
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
  return { binding, stateDir };
}

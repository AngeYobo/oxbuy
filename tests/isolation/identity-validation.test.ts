// SPDX-License-Identifier: MIT
/**
 * Phase 2C (F5): unsafe identity configurations are rejected before anything
 * starts; the former OXDEAI_AGENT_UID / OXDEAI_AGENT_GID override has no effect.
 *
 * The override variables are set BEFORE any project module is imported, so a
 * module that still read them would be affected. The R4 configuration
 * (agent uid 4242 in the gateway's group 984) is used for the process-level check.
 */
process.env.OXDEAI_AGENT_UID = "4242";
process.env.OXDEAI_AGENT_GID = "984";

const assert: typeof import("node:assert/strict") = (await import("node:assert/strict")).default;
const { join } = await import("node:path");
const { spawnSync } = await import("node:child_process");
const { after, before, test } = await import("node:test");
const { ACCOUNT_NAMES, identitiesUnavailableReason, identityFacts, identityOf, validateIdentities } = await import("../../src/isolation/identity.ts");
const { REPO_ROOT, trustedArtifact } = await import("./trusted-artifact.ts");
type Facts = ReturnType<typeof identityFacts>;

const operator = { uid: 1000, gid: 1000 };
const ok: Facts = {
  agent: { name: ACCOUNT_NAMES.agent, uid: 999, gid: 985, groupName: "oxdeai-agent", groupMembers: [] },
  gateway: { name: ACCOUNT_NAMES.gateway, uid: 996, gid: 984, groupName: "oxdeai-gateway", groupMembers: [] },
  auth: { name: ACCOUNT_NAMES.auth, uid: 995, gid: 983, groupName: "oxdeai-auth", groupMembers: [] },
  executor: { name: ACCOUNT_NAMES.executor, uid: 994, gid: 982, groupName: "oxdeai-executor", groupMembers: [] },
};
const withRole = (role: keyof Facts, patch: object): Facts => ({ ...ok, [role]: { ...ok[role]!, ...patch } });

test("ID1 the approved configuration (synthetic copy of this deployment) is accepted", () => {
  assert.equal(validateIdentities(ok, operator), null);
});

test("ID2 unsafe synthetic configurations are rejected", () => {
  const cases: Array<[string, Facts, RegExp]> = [
    ["R4 case: agent in the gateway's group", withRole("agent", { uid: 4242, gid: 984 }), /agent gid 984 is not distinct from gateway|gateway gid 984 is not distinct from agent/],
    ["agent shares the executor's group", withRole("agent", { gid: 982 }), /not distinct/],
    ["agent is the operator", withRole("agent", { uid: 1000 }), /agent uid 1000 is not distinct from the operator/],
    ["agent in the operator's group", withRole("agent", { gid: 1000 }), /agent gid 1000 is not distinct from the operator/],
    ["gateway is root", withRole("gateway", { uid: 0 }), /gateway uid 0 is not distinct from root/],
    ["executor in root's group", withRole("executor", { gid: 0 }), /executor gid 0 is not distinct from root/],
    ["auth and executor share a uid", withRole("auth", { uid: 994 }), /not distinct from (auth|executor)/],
    ["agent added to the gateway's group", withRole("gateway", { groupMembers: ["oxdeai-agent"] }), /gateway primary group oxdeai-gateway has members/],
    ["any member in a service group", withRole("auth", { groupMembers: ["someone"] }), /auth primary group oxdeai-auth has members/],
    ["missing primary group", withRole("executor", { groupName: null }), /executor primary group 982 does not exist/],
    ["account under another name (override-style uid-4242)", withRole("agent", { name: "uid-4242" }), /agent must be the account oxdeai-agent/],
    ["negative uid", withRole("agent", { uid: -1 }), /invalid uid/],
  ];
  for (const [label, facts, reason] of cases) assert.match(validateIdentities(facts, operator) ?? "ACCEPTED", reason, label);
  const { executor: _e, ...missing } = ok;
  assert.match(validateIdentities(missing, operator) ?? "ACCEPTED", /account oxdeai-executor does not exist/);
});

const BLOCKED = identitiesUnavailableReason();
const opts = BLOCKED === null ? {} : { skip: `BLOCKED: ${BLOCKED}` };
/** The real agent account, read independently of src/isolation/identity.ts (the code under test). */
const realAgent = (() => {
  const [, , uid, gid] = spawnSync("getent", ["passwd", "oxdeai-agent"], { encoding: "utf8" }).stdout.trim().split(":");
  return { uid: Number(uid), gid: Number(gid) };
})();
let trusted: Awaited<ReturnType<typeof trustedArtifact>>;
before(async () => {
  if (BLOCKED === null) trusted = await trustedArtifact();
});
after(() => trusted?.cleanup());

test("ID3 the real accounts pass validation, and the override variables are ignored", opts, () => {
  assert.equal(validateIdentities(identityFacts(), { uid: process.getuid!(), gid: process.getgid!() }), null);
  assert.notEqual(realAgent.uid, 4242, "precondition: the override differs from the real account");
  assert.equal(identityOf("agent")!.uid, realAgent.uid, "OXDEAI_AGENT_UID=4242 has no effect");
  assert.equal(identityOf("agent")!.gid, realAgent.gid, "OXDEAI_AGENT_GID=984 has no effect");
});

test("ID4 process level, override variables set (R4 F5 configuration): the agent is still oxdeai-agent and cannot reach the auth, executor, or settle sockets", opts, async () => {
  const s = await trusted.launch({});
  try {
    const probe = join(REPO_ROOT, "tests", "isolation", "agent-probe.ts");
    assert.deepEqual((await s.runAgent(probe, ["whoami"])).result, { uid: realAgent.uid, gid: realAgent.gid, groups: [realAgent.gid] });
    const c = (await s.runAgent(probe, ["connect", s.paths.authSocket, s.paths.executorSocket, s.paths.settleSocket, s.paths.publicSocket])).result as Record<string, { ok: boolean; code?: string }>;
    assert.equal(c[s.paths.authSocket]!.code, "EACCES");
    assert.equal(c[s.paths.executorSocket]!.code, "EACCES");
    assert.equal(c[s.paths.settleSocket]!.code, "EACCES");
    assert.equal(c[s.paths.publicSocket]!.ok, true, "positive control");
    assert.equal(s.ledger().length, 0);
  } finally {
    await s.stop();
  }
});

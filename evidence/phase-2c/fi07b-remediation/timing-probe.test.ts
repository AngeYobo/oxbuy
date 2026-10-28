import { test } from "node:test";
import { join } from "node:path";
import { freshExecutorState, freshPolicyState, REPO_ROOT, removeStateRoot, trustedArtifact } from "/workspaces/oxdeai-celo-poc/tests/isolation/trusted-artifact.ts";
test("fi07b timing probe", async () => {
  const t = await trustedArtifact();
  const P = freshPolicyState({ budget: "10000", ttlSeconds: 3 }); const E = freshExecutorState();
  const PROBE = join(REPO_ROOT, "tests/isolation/agent-probe.ts");
  const now = () => Date.now() / 1000;
  const d1 = await t.launch({ policyStateRoot: P, executorStateRoot: E, ttlSeconds: 3 });
  const a = (await d1.runAgent(PROBE, ["authorize-only", d1.paths.publicSocket])).result as any;
  const tAuth = now();
  await d1.stop();
  const d2 = await t.launch({ policyStateRoot: P, executorStateRoot: E, ttlSeconds: 3 });
  const tBeforeSubmit = now();
  const r = (await d2.runAgent(PROBE, ["submit", d2.paths.publicSocket, JSON.stringify({ request: a.request, intent_ref: a.intent_ref, authorization: a.authorization })])).result as any;
  const tAfterSubmit = now();
  console.log("TIMING", JSON.stringify({ issued_at: a.authorization.issued_at, expiry: a.authorization.expiry, ttl: a.authorization.expiry - a.authorization.issued_at,
    authorized_at: tAuth.toFixed(2), submit_start: tBeforeSubmit.toFixed(2), submit_end: tAfterSubmit.toFixed(2),
    expired_before_submit: tBeforeSubmit >= a.authorization.expiry, redeploy_s: (tBeforeSubmit - tAuth).toFixed(2), reason: r.reason, decision: r.decision }));
  await d2.stop(); removeStateRoot(P); removeStateRoot(E); t.cleanup();
});

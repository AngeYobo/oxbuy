// Phase 2C invariant investigation: try to reproduce two suspected counterexamples. Disposable state only, mock only.
import { spawnSync } from "node:child_process";
import { join } from "node:path";
const REPO = "/workspaces/oxdeai-celo-poc";
const { trustedArtifact, freshPolicyState, freshExecutorState, removeStateRoot } = await import(`${REPO}/tests/isolation/trusted-artifact.ts`);
const { SERVICES } = await import(`${REPO}/src/system.ts`);
const PROBE = join(REPO, "tests/isolation/agent-probe.ts");
const out = (k: string, v: unknown) => process.stderr.write(`${k}: ${JSON.stringify(v).slice(0, 500)}\n`);
const sudo = (args: string[], input?: string) => spawnSync("sudo", ["-n", ...args], { encoding: "utf8", input });
const req = (s: any) => ({ service_id: s.service_id, method: "POST", url: `${s.resource}?city=lagos`, body: JSON.stringify({ units: "metric", days: 3 }), network: s.network, asset: s.asset, recipient: s.pay_to, max_amount: s.price.toString() });
const gwAuth = async (sys: any) => { const r = (await sys.runAs("gateway", PROBE, ["post", sys.paths.authSocket, "/v1/authorize", JSON.stringify(req(SERVICES.weather)), "{}"])).result as any; const b = r?.value?.body; return b ? (b.decision === "ALLOW" ? "ALLOW" : `DENY:${b.reasons}`) : `ERR:${r?.code}`; };
const state = (sys: any) => JSON.parse(sudo(["cat", join(sys.paths.authStateDir, "state.json")]).stdout);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const which = process.argv[2] ?? "both";

const t = await trustedArtifact();
const cleanup: string[] = [];
try {
  if (which !== "cx2") {
    // CX1: one-step rollback accepted as a "torn commit".
    const P = freshPolicyState({ budget: "20000" }); cleanup.push(P);
    const s = await t.launch({ policyStateRoot: P });
    try {
      const f = join(s.paths.authStateDir, "state.json");
      out("CX1_first", await gwAuth(s));
      const snapshot = sudo(["cat", f]).stdout;            // state after 1 authorization (v1)
      out("CX1_second", await gwAuth(s));                  // v2: budget now fully reserved
      out("CX1_third_before_rollback", await gwAuth(s));   // expected DENY:BUDGET_EXCEEDED
      await s.stopAuth();
      sudo(["tee", f], snapshot);                          // put back the state from one commit earlier
      let started = "STARTED";
      try { await s.startAuth(); } catch (e) { started = (e as Error).message.slice(0, 160); }
      out("CX1_restart_after_one_step_rollback", started);
      if (started === "STARTED") {
        out("CX1_authorize_after_rollback", await gwAuth(s));
        const st = state(s);
        out("CX1_result", { budget: "20000", spent: st.state.budget.spent_in_period, reservations: Object.keys(st.reservations).length, anchor_tail: sudo(["tail", "-2", s.paths.anchorPath]).stdout.split("\n").map((l: string) => l.slice(0, 90)) });
      }
    } finally { await s.stop(); }
  }
  if (which !== "cx1") {
    // CX2: reservation released by a NEW deployment's executor while the OLD deployment's executor is still paying it.
    const P = freshPolicyState({ budget: "10000", ttlSeconds: 3 }); cleanup.push(P);
    const E1 = freshExecutorState(); cleanup.push(E1);
    const E2 = freshExecutorState(); cleanup.push(E2);
    const d1 = await t.launch({ policyStateRoot: P, executorStateRoot: E1, ttlSeconds: 3, executorFaults: { delayPayMs: 9000 }, gatewayTimeoutMs: 20000, reconcileIntervalMs: 600000, cancelGraceSeconds: 1 });
    let d2: any;
    try {
      const a = (await d1.runAgent(PROBE, ["authorize-only", d1.paths.publicSocket])).result as any;
      out("CX2_authorized", { auth_id: a.authorization.auth_id.slice(0, 12), expiry_in_s: a.authorization.expiry - Math.floor(Date.now() / 1000) });
      const purchase = d1.runAgent(PROBE, ["submit", d1.paths.publicSocket, JSON.stringify({ request: a.request, intent_ref: a.intent_ref, authorization: a.authorization })], 60_000);
      await sleep(800);                                   // the old executor has accepted it and is paying (9 s)
      await d1.crashAuth();                               // old auth dies; old gateway + executor keep running
      d2 = await t.launch({ policyStateRoot: P, executorStateRoot: E2, ttlSeconds: 3, reconcileIntervalMs: 300, cancelGraceSeconds: 1 });
      await sleep(4500);                                  // past expiry + grace: new executor cancels, auth releases
      const mid = state(d2).reservations[a.authorization.auth_id];
      out("CX2_reservation_after_new_deployment_cancel", { state: mid?.state, charged: mid?.charged, spent: state(d2).state.budget.spent_in_period });
      const result = (await purchase).result as any;
      out("CX2_old_executor_payment", { decision: result?.decision, executed: result?.executed, ledger_old: d1.ledger().length });
      out("CX2_new_deployment_can_authorize_again", await gwAuth(d2));
      out("CX2_result", { budget: "10000", payments_made: d1.ledger().length + d2.ledger().length, final_spent: state(d2).state.budget.spent_in_period, reservation: state(d2).reservations[a.authorization.auth_id]?.state });
    } finally { if (d2) await d2.stop(); await d1.stop(); }
  }
} finally {
  for (const r of cleanup) removeStateRoot(r);
  t.cleanup();
}

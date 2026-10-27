// SPDX-License-Identifier: MIT
/**
 * P2A-01..14: adversarial tests against independently launched processes.
 *
 *   Process A  agent     tests/isolation/agent-probe.ts, as the agent OS identity (nobody)
 *   Process B  gateway   src/isolation/gateway-main.ts, as the operator identity
 *   Process C  executor  src/isolation/executor-main.ts, as the operator identity
 *
 * Every "denied by the OS" assertion is an errno returned by the kernel to a
 * process running as the agent identity, next to a positive control showing
 * the same resource works for its intended user. If the agent identity
 * cannot be assumed here, every test is skipped as BLOCKED, never passed.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { INTERNAL_EXECUTOR_TOKEN_HEADER } from "@oxdeai/guard";
import { signAuthorizationEd25519, type AuthorizationV1 } from "@oxdeai/core";
import type { PurchaseResult } from "../../src/agent/agent.ts";
import type { IntentRef, PurchaseRequest } from "../../src/agent/purchase-request.ts";
import { AGENT_UID, agentIdentityUnavailableReason } from "../../src/isolation/identity.ts";
import type { IsolatedSystem, LaunchOptions } from "../../src/isolation/launcher.ts";
import { SERVICES } from "../../src/system.ts";
import { REPO_ROOT, trustedArtifact } from "./trusted-artifact.ts";

const PROBE = join(REPO_ROOT, "tests", "isolation", "agent-probe.ts");
const BLOCKED = agentIdentityUnavailableReason();
const opts = BLOCKED === null ? {} : { skip: `BLOCKED: ${BLOCKED}` };
const BUDGET = "1000000000";

type Authorized = { request: PurchaseRequest; intent_ref: IntentRef; authorization: AuthorizationV1 };

async function agent<T = any>(sys: IsolatedSystem, ...args: string[]): Promise<T> {
  const r = await sys.runAgent(PROBE, args);
  assert.equal(r.code, 0, `agent probe ${args[0]} failed: ${r.stderr}`);
  return r.result as T;
}

const authorizeOnly = (sys: IsolatedSystem) => agent<Authorized>(sys, "authorize-only", sys.paths.publicSocket);
const submit = (sys: IsolatedSystem, input: unknown) => agent<PurchaseResult>(sys, "submit", sys.paths.publicSocket, JSON.stringify(input));

/** Operator re-signs an authorization with the real PDP key after patching it. */
function mint(sys: IsolatedSystem, base: AuthorizationV1, patch: Partial<AuthorizationV1>): AuthorizationV1 {
  return signAuthorizationEd25519({ ...base, ...patch } as Parameters<typeof signAuthorizationEd25519>[0], sys.operatorSecrets.pdpPrivateKeyPem);
}

/** A token holder (e.g. a compromised gateway) calling the executor directly. */
function direct(sys: IsolatedSystem, a: Authorized, authorization: unknown = a.authorization, token = sys.operatorSecrets.internalToken) {
  return sys.executorPost(
    "/v1/execute",
    { action: { request: a.request, intent_ref: a.intent_ref }, authorization },
    { [INTERNAL_EXECUTOR_TOKEN_HEADER]: token },
  );
}

function assertDenied(r: PurchaseResult, reason: string | RegExp) {
  assert.equal(r.decision, "DENY", JSON.stringify(r));
  assert.equal(r.executed, false);
  if (typeof reason === "string") assert.equal(r.reason, reason);
  else assert.match(String(r.reason), reason);
}

function assertExecutorRefused(res: { status: number; body: unknown }, error: string | RegExp) {
  const body = res.body as { outcome: string; error: string };
  assert.equal(res.status, 409, JSON.stringify(res.body));
  assert.equal(body.outcome, "NOT_EXECUTED");
  if (typeof error === "string") assert.equal(body.error, error);
  else assert.match(body.error, error);
}

function procUid(pid: number): number {
  const line = readFileSync(`/proc/${pid}/status`, "utf8").split("\n").find((l) => l.startsWith("Uid:"))!;
  return Number(line.split(/\s+/)[1]);
}

// Every system is launched from a sealed, approved artifact (docs/ISOLATION.md §3).
let trusted: Awaited<ReturnType<typeof trustedArtifact>>;
const launchIsolatedSystem = (opts: LaunchOptions = {}) => trusted.launch(opts);

let sys: IsolatedSystem;
before(async () => {
  if (BLOCKED !== null) return;
  trusted = await trustedArtifact();
  sys = await launchIsolatedSystem({ budget: BUDGET });
});
after(async () => {
  await sys?.stop();
  trusted?.cleanup();
});

// ── P2A-01 ────────────────────────────────────────────────────────────────

test("P2A-01 authorized mock payment from the agent process: ALLOW, exactly one payment", opts, async () => {
  const before = sys.ledger().length;
  const who = await agent(sys, "whoami");
  assert.equal(who.uid, AGENT_UID);
  const { executor, gateway } = sys.pids();
  assert.notEqual(procUid(executor!), AGENT_UID, "executor runs as a different OS identity than the agent");
  assert.notEqual(procUid(gateway!), AGENT_UID);
  assert.equal(new Set([process.pid, executor, gateway]).size, 3, "three independent processes");

  const out = await agent(sys, "buy", sys.paths.publicSocket, "weather");
  assert.equal(out.stage, "purchase");
  assert.equal(out.result.decision, "ALLOW");
  assert.equal(out.result.executed, true);
  const ledger = sys.ledger();
  assert.equal(ledger.length, before + 1, "exactly one payment");
  assert.equal(ledger.at(-1)!.intent_hash, out.result.intent_hash);
  assert.deepEqual(sys.journal().get(out.result.intent_hash), { state: "SETTLED" });
});

// ── P2A-02 ────────────────────────────────────────────────────────────────

test("P2A-02 agent identity cannot connect to the executor socket (EACCES); public socket works", opts, async () => {
  const res = await agent(sys, "connect", sys.paths.executorSocket, sys.paths.publicSocket);
  assert.deepEqual(res[sys.paths.executorSocket], { ok: false, code: "EACCES" });
  assert.deepEqual(res[sys.paths.publicSocket], { ok: true }, "positive control: the agent's one door is open");

  // Positive control: the trusted identity can reach the executor (403 without the token).
  const op = await sys.executorPost("/v1/execute", {}, {});
  assert.equal(op.status, 403);

  assert.equal(statSync(sys.paths.executorDir).mode & 0o777, 0o700);
  assert.equal(statSync(sys.paths.executorSocket).mode & 0o777, 0o600);

  // No TCP or UDP listener belongs to the executor.
  const { executor } = sys.pids();
  const ss = spawnSync("ss", ["-H", "-ltunp"], { encoding: "utf8" });
  assert.equal(ss.status, 0, ss.stderr);
  assert.ok(!ss.stdout.includes(`pid=${executor},`), `executor has an inet listener:\n${ss.stdout}`);
  const unix = spawnSync("ss", ["-H", "-lxp"], { encoding: "utf8" }).stdout;
  assert.ok(unix.includes(sys.paths.executorSocket) && unix.includes(`pid=${executor},`), "executor listens on its Unix socket only");
});

// ── P2A-03 ────────────────────────────────────────────────────────────────

test("P2A-03 forged authorizations from the agent: DENY at the gateway, no payment", opts, async () => {
  const before = sys.ledger().length;
  const res = await agent<Record<string, PurchaseResult>>(sys, "forge", sys.paths.publicSocket);
  const expected: Record<string, string> = {
    self_signed_pdp_issuer: "AUTH_SIGNATURE_INVALID",
    self_signed_foreign_issuer: "AUTH_ISSUER_POLICY_NOT_AUTHORIZED,AUTH_KID_UNKNOWN",
    audience_edited: "AUTH_AUDIENCE_MISMATCH,AUTH_SIGNATURE_INVALID",
    signature_garbled: "AUTH_SIGNATURE_INVALID",
  };
  for (const [name, reason] of Object.entries(expected)) assertDenied(res[name]!, reason);
  assert.equal(sys.ledger().length, before);
});

// ── P2A-04 ────────────────────────────────────────────────────────────────

test("P2A-04 expired authorization: DENY at the gateway, and rejected by the executor directly", opts, async () => {
  const short = await launchIsolatedSystem({ ttlSeconds: 1, budget: BUDGET });
  try {
    const r = await agent<PurchaseResult>(short, "expire", short.paths.publicSocket, "2100");
    assertDenied(r, /AUTH_EXPIRED/);
    assert.equal(short.ledger().length, 0);
  } finally {
    await short.stop();
  }

  const a = await authorizeOnly(sys);
  const now = Math.floor(Date.now() / 1000);
  const expired = mint(sys, a.authorization, { issued_at: now - 120, expiry: now - 60 });
  const before = sys.ledger().length;
  assertDenied(await submit(sys, { ...a, authorization: expired }), /AUTH_EXPIRED/);
  assertExecutorRefused(await direct(sys, a, expired), /^EXECUTOR_AUTHORIZATION_INVALID:.*AUTH_EXPIRED/);
  assert.equal(sys.ledger().length, before);
});

// ── P2A-05 ────────────────────────────────────────────────────────────────

test("P2A-05 wrong issuer or audience, signed with the real PDP key: rejected by gateway and executor", opts, async () => {
  const before = sys.ledger().length;
  const cases: Array<[string, Partial<AuthorizationV1>, string]> = [
    ["audience", { audience: "some-other-gateway" }, "AUTH_AUDIENCE_MISMATCH"],
    ["issuer", { issuer: "rogue-pdp" }, "AUTH_ISSUER_POLICY_NOT_AUTHORIZED,AUTH_KID_UNKNOWN"],
    ["policy", { policy_id: "f".repeat(64) }, "AUTH_ISSUER_POLICY_NOT_AUTHORIZED"],
  ];
  for (const [name, patch, code] of cases) {
    const a = await authorizeOnly(sys);
    const bad = mint(sys, a.authorization, patch);
    assertDenied(await submit(sys, { ...a, authorization: bad }), code);
    assertExecutorRefused(await direct(sys, a, bad), `EXECUTOR_AUTHORIZATION_INVALID:${code}`);
    assert.equal(sys.ledger().length, before, name);
  }
});

// ── P2A-06 ────────────────────────────────────────────────────────────────

test("P2A-06 payment intent modified after authorization: INTENT_HASH_MISMATCH at gateway and executor", opts, async () => {
  const before = sys.ledger().length;
  const res = await agent<Record<string, PurchaseResult>>(sys, "tamper", sys.paths.publicSocket);
  for (const field of ["recipient", "max_amount", "url", "body"]) assertDenied(res[field]!, "INTENT_HASH_MISMATCH");

  const a = await authorizeOnly(sys);
  const modified = { ...a, request: { ...a.request, recipient: SERVICES.unlisted.pay_to } };
  assertExecutorRefused(await direct(sys, modified, a.authorization), "EXECUTOR_INTENT_HASH_MISMATCH");
  assert.equal(sys.ledger().length, before);
});

// ── P2A-07 ────────────────────────────────────────────────────────────────

test("P2A-07 replayed authorization: second submit DENY AUTH_REPLAY; executor refuses it directly too", opts, async () => {
  const before = sys.ledger().length;
  const a = await authorizeOnly(sys);
  const first = await submit(sys, a);
  const second = await submit(sys, a);
  assert.equal(first.decision, "ALLOW");
  assertDenied(second, "AUTH_REPLAY");
  const res = await direct(sys, a);
  assertExecutorRefused(res, "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT");
  assert.equal((res.body as { prior_state: string }).prior_state, "SETTLED");
  assert.equal(sys.ledger().length, before + 1);
});

// ── P2A-08 ────────────────────────────────────────────────────────────────

test("P2A-08 executor (and gateway) restart, then the same intent again: rejected from the durable journal", opts, async () => {
  const s = await launchIsolatedSystem({ budget: BUDGET });
  try {
    const a = await authorizeOnly(s);
    assert.equal((await submit(s, a)).decision, "ALLOW");

    // Graceful restart of both: the gateway's in-memory replay store is gone.
    await s.stopExecutor();
    await s.startExecutor();
    await s.restartGateway();
    const again = await submit(s, a);
    assert.equal(again.decision, "DENY", JSON.stringify(again));
    assert.equal(again.detail, "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT");

    // Crash (SIGKILL) and restart: stale lock is recovered, intent still refused.
    await s.crashExecutor();
    await s.startExecutor();
    assertExecutorRefused(await direct(s, a), "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT");
    assert.equal(s.ledger().length, 1, "exactly one payment across restarts");
    assert.deepEqual(s.journal().get(a.authorization.intent_hash), { state: "SETTLED" });
  } finally {
    await s.stop();
  }
});

// ── P2A-09 ────────────────────────────────────────────────────────────────

for (const [fault, paid] of [
  ["crashAfterPay", 1],
  ["crashBeforePay", 0],
] as const) {
  test(`P2A-09 executor killed after the payment started (${fault}): INDETERMINATE; STARTED survives restart; no retry`, opts, async () => {
    const s = await launchIsolatedSystem({ budget: BUDGET, executorFaults: { [fault]: true } });
    try {
      const a = await authorizeOnly(s);
      const r = await submit(s, a);
      assert.equal(r.decision, "INDETERMINATE", JSON.stringify(r));
      assert.equal(r.executed, "unknown");
      assert.equal(r.reason, "PAYMENT_UNKNOWN");
      await s.executorExited();
      assert.equal(s.ledger().length, paid, "ground truth of the mock chain");
      const h = a.authorization.intent_hash;
      assert.deepEqual(s.journal().get(h), { state: "STARTED" });

      await s.startExecutor();
      assert.deepEqual(s.journal().get(h), { state: "STARTED" }, "restart does not convert STARTED to a definitive outcome");
      const log = readFileSync(join(s.paths.journalDir, "journal.log"), "utf8");
      assert.match(log, new RegExp(`"needs_reconciliation":\\["${h}"\\]`));

      // Resubmission after a gateway restart: still unknown, never paid again.
      await s.restartGateway();
      const again = await submit(s, a);
      assert.equal(again.decision, "INDETERMINATE");
      assert.equal(again.detail, "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT");
      assert.equal(s.ledger().length, paid);

      // Operator reconciliation: needs the executor stopped (single-writer lock).
      const cli = join(s.paths.app, "src", "isolation", "journal-cli.ts");
      const verdict = paid ? "SETTLED" : "NOT_SETTLED";
      const locked = spawnSync(process.execPath, [cli, s.paths.journalDir, "resolve", h, verdict, "ledger checked"], { encoding: "utf8" });
      assert.notEqual(locked.status, 0);
      assert.match(locked.stderr, /JOURNAL_LOCKED/);
      await s.stopExecutor();
      const ok = spawnSync(process.execPath, [cli, s.paths.journalDir, "resolve", h, verdict, "ledger checked"], { encoding: "utf8" });
      assert.equal(ok.status, 0, ok.stderr);
      const rec = s.journal().inspect(h)!;
      assert.equal(rec.state, "STARTED", "state is history; the verdict is attached, not substituted");
      assert.equal(rec.resolution?.verdict, verdict);
    } finally {
      await s.stop();
    }
  });
}

// ── P2A-10 ────────────────────────────────────────────────────────────────

for (const [fault, startedAtTimeout] of [
  [{ delayResponseMs: 1500 }, "SETTLED"],
  [{ delayPayMs: 1500 }, "STARTED"],
] as const) {
  test(`P2A-10 gateway->executor IPC timeout (${Object.keys(fault)[0]}): INDETERMINATE 504, settles once later`, opts, async () => {
    const s = await launchIsolatedSystem({ budget: BUDGET, gatewayTimeoutMs: 400, executorFaults: fault });
    try {
      const a = await authorizeOnly(s);
      const r = await submit(s, a);
      assert.equal(r.decision, "INDETERMINATE", JSON.stringify(r));
      assert.equal(r.status, 504);
      assert.equal(r.detail, "UPSTREAM_TIMEOUT");
      assert.equal(s.journal().get(a.authorization.intent_hash)?.state, startedAtTimeout);
      await new Promise((resolve) => setTimeout(resolve, 2000));
      assert.equal(s.ledger().length, 1);
      assert.deepEqual(s.journal().get(a.authorization.intent_hash), { state: "SETTLED" });
    } finally {
      await s.stop();
    }
  });
}

// ── P2A-11 ────────────────────────────────────────────────────────────────

test("P2A-11 agent identity cannot read the journal, ledger, wallet key, or any config (EACCES)", opts, async () => {
  const journalFiles = readdirSync(join(sys.paths.journalDir, "intents")).map((n) => join(sys.paths.journalDir, "intents", n));
  assert.ok(journalFiles.length > 0, "there are journal records to steal");
  const targets = [
    join(sys.paths.journalDir, "journal.log"),
    journalFiles[0]!,
    sys.paths.ledgerPath,
    sys.paths.walletKeyPath,
    sys.paths.executorConfig,
    sys.paths.gatewayConfig,
  ];
  const res = await agent(sys, "read", ...targets, join(REPO_ROOT, "package.json"), join(sys.paths.app, "package.json"));
  for (const t of targets) {
    assert.deepEqual(res[t], { ok: false, code: "EACCES" }, t);
    readFileSync(t); // positive control: the trusted identity can read it
  }
  assert.equal(res[join(REPO_ROOT, "package.json")].ok, true, "positive control: the agent can read public files");
  assert.deepEqual(res[join(sys.paths.app, "package.json")], { ok: false, code: "EACCES" }, "trusted artifact is not even readable");
  for (const t of targets) assert.equal(statSync(t).mode & 0o077, 0, `${t} is private to its owner`);
});

// ── P2A-12 ────────────────────────────────────────────────────────────────

test("P2A-12 agent imports the trusted payment runtime and pays directly: blocked by the OS", opts, async () => {
  const before = readFileSync(sys.paths.ledgerPath, "utf8");
  const res = await agent(sys, "direct-pay", REPO_ROOT, sys.paths.walletKeyPath, sys.paths.ledgerPath, "a".repeat(64));
  assert.deepEqual(res.pay, { ok: false, code: "MOCK_WALLET_UNAVAILABLE:EACCES" });
  assert.deepEqual(res.forgeLedger, { ok: false, code: "EACCES" });
  assert.equal(readFileSync(sys.paths.ledgerPath, "utf8"), before, "ledger unchanged");

  // It also cannot alter the trusted code, signal, or inspect the trusted processes.
  const { executor, gateway } = sys.pids();
  const trustedFile = join(sys.paths.app, "src", "executor", "executor.ts");
  const w = await agent(sys, "write", trustedFile);
  assert.deepEqual(w[trustedFile], { ok: false, code: "EACCES" });
  const sig = await agent(sys, "signal", String(executor), String(gateway));
  assert.deepEqual(sig[String(executor)], { ok: false, code: "EPERM" });
  assert.deepEqual(sig[String(gateway)], { ok: false, code: "EPERM" });
  const proc = await agent(sys, "proc", String(executor), String(gateway));
  for (const pid of [executor, gateway]) {
    assert.deepEqual(proc[String(pid)].environ, { ok: false, code: "EACCES" });
    assert.deepEqual(proc[String(pid)].mem, { ok: false, code: "EACCES" });
    // argv is world-readable on Linux: it carries only a config path.
    const argv = JSON.stringify(proc[String(pid)].cmdline);
    assert.ok(!argv.includes(sys.operatorSecrets.internalToken) && !argv.includes("PRIVATE KEY"), "no secret in argv");
  }
  const esc = await agent(sys, "escalate");
  assert.notEqual(esc.sudo_status, 0, "no privilege escalation from the agent identity");
});

// ── P2A-13 ────────────────────────────────────────────────────────────────

test("P2A-13 token holder bypassing the gateway's checks: executor verifies the authorization itself", opts, async () => {
  const before = sys.ledger().length;
  const journalBefore = sys.journal().list().length;
  const a = await authorizeOnly(sys);
  const b = await authorizeOnly(sys);
  const now = Math.floor(Date.now() / 1000);
  const action = { request: a.request, intent_ref: a.intent_ref };
  const token = { [INTERNAL_EXECUTOR_TOKEN_HEADER]: sys.operatorSecrets.internalToken };
  const { generateKeyPairSync } = await import("node:crypto");
  const rogue = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  // Token only, no authorization.
  assertExecutorRefused(await sys.executorPost("/v1/execute", { action }, token), "EXECUTOR_INVALID_REQUEST");
  assertExecutorRefused(await sys.executorPost("/v1/execute", action, token), "EXECUTOR_INVALID_REQUEST");
  assertExecutorRefused(await direct(sys, a, null), "EXECUTOR_AUTHORIZATION_MISSING");
  // Signed by a key the executor does not trust.
  const selfSigned = signAuthorizationEd25519(a.authorization as Parameters<typeof signAuthorizationEd25519>[0], rogue);
  assertExecutorRefused(await direct(sys, a, selfSigned), /^EXECUTOR_AUTHORIZATION_INVALID:.*AUTH_SIGNATURE_INVALID/);
  // Valid authorization for a different intent.
  assertExecutorRefused(await direct(sys, a, b.authorization), "EXECUTOR_INTENT_HASH_MISMATCH");
  // Expired, and issued in the future.
  assertExecutorRefused(await direct(sys, a, mint(sys, a.authorization, { issued_at: now - 120, expiry: now - 60 })), /AUTH_EXPIRED/);
  assertExecutorRefused(await direct(sys, a, mint(sys, a.authorization, { issued_at: now + 3600, expiry: now + 3700 })), /AUTH_ISSUED_AT_IMPLAUSIBLE/);
  // Without the token, nothing is evaluated at all.
  assert.equal((await direct(sys, a, a.authorization, "0".repeat(64))).status, 403);

  assert.equal(sys.ledger().length, before, "no payment from any bypass attempt");
  assert.equal(sys.journal().list().length, journalBefore, "no intent was reserved");

  // Positive control: the same channel with the genuine authorization pays once.
  const ok = await direct(sys, a);
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(sys.ledger().length, before + 1);
});

// ── P2A-14 ────────────────────────────────────────────────────────────────

test("P2A-14 concurrent duplicate requests: at most one payment (via gateway and directly at the executor)", opts, async () => {
  const before = sys.ledger().length;
  const results = await agent<PurchaseResult[]>(sys, "concurrent", sys.paths.publicSocket, "12");
  assert.equal(results.filter((r) => r.decision === "ALLOW").length, 1);
  assert.ok(results.every((r) => r.decision === "ALLOW" || r.reason === "AUTH_REPLAY"), JSON.stringify(results));
  assert.equal(sys.ledger().length, before + 1);

  const a = await authorizeOnly(sys);
  const direct12 = await Promise.all(Array.from({ length: 12 }, () => direct(sys, a)));
  const executed = direct12.filter((r) => (r.body as { outcome: string }).outcome === "EXECUTED");
  assert.equal(executed.length, 1, JSON.stringify(direct12.map((r) => r.body)));
  for (const r of direct12) {
    if (r !== executed[0]) assert.equal((r.body as { error: string }).error, "EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT");
  }
  assert.equal(sys.ledger().length, before + 2);
  assert.equal(sys.ledger().filter((e) => e.intent_hash === a.authorization.intent_hash).length, 1);

  // A second executor process cannot open the same journal (single writer).
  const second = spawnSync(process.execPath, [join(sys.paths.app, "src", "isolation", "executor-main.ts"), sys.paths.executorConfig], {
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.notEqual(second.status, 0);
  assert.match(second.stderr, /JOURNAL_LOCKED/);
});

// ── Secret hygiene ────────────────────────────────────────────────────────

test("P2A secrets never appear in trusted-process logs or in responses to the agent", opts, async () => {
  const out = await agent(sys, "buy", sys.paths.publicSocket, "weather");
  const text = JSON.stringify(out);
  const logs = readdirSync(sys.paths.logsDir).map((n) => readFileSync(join(sys.paths.logsDir, n), "utf8")).join("\n");
  const walletKey = readFileSync(sys.paths.walletKeyPath).toString("hex");
  for (const secret of [sys.operatorSecrets.internalToken, walletKey, "PRIVATE KEY"]) {
    assert.ok(!text.includes(secret), "agent-visible response leaks a secret");
    assert.ok(!logs.includes(secret), "process log leaks a secret");
  }
});

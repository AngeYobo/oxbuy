// SPDX-License-Identifier: MIT
/**
 * x402 / EIP-3009 testnet rail, process level: four OS identities (agent, gateway, auth, executor),
 * the sealed artifact, the executor-private wallet key file, and the x402 adapter in the real
 * executor process, against SimChain / SimFacilitator / x402 seller served on loopback by the test.
 *
 *   XP1  valid payment end to end; the agent cannot read the wallet key; the key is in no config or log
 *   XP2  process crash after the signed payment was sent (SIGKILL): PAYMENT_UNKNOWN, restart, replay
 *        refused, fully charged; operator reconciliation from the chain (journal-cli resolve-x402)
 *   XP3  journal rollback: journal-only restore refused at startup; journal + checkpoint restored together
 *        and re-armed: the replay is refused by the auth service; never paid twice
 *   XP4  authorization service outage: no settlement, non-final rejection
 *   XP5  an x402 executor configured for mainnet refuses to start
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { addressOfPrivateKey, eip3009NonceForIntent } from "../../src/chain/evm.ts";
import { identitiesUnavailableReason } from "../../src/isolation/identity.ts";
import type { IsolatedSystem } from "../../src/isolation/launcher.ts";
import { AGENT_ID } from "../../src/system.ts";
import { startSeller, type Seller } from "../../src/x402/seller.ts";
import { TESTNET_NETWORK, TESTNET_SELLER_ORIGIN, TESTNET_SELLER_PATH, TESTNET_USDC, testnetPolicyState, testnetRequirements, testnetService } from "../../src/x402/testnet-profile.ts";
import { createSimChain, createSimFacilitator, type SimChain } from "../x402/sim.ts";
import { freshExecutorState, freshPolicyState, REPO_ROOT, removeStateRoot, trustedArtifact } from "./trusted-artifact.ts";

const BLOCKED = identitiesUnavailableReason();
const opts = BLOCKED === null ? {} : { skip: `BLOCKED: ${BLOCKED}` };
const PROBE = join(REPO_ROOT, "tests", "isolation", "agent-probe.ts");
const PRICE = 1_000n;

let trusted: Awaited<ReturnType<typeof trustedArtifact>>;
const roots: string[] = [];
const systems: IsolatedSystem[] = [];
const closers: (() => Promise<void>)[] = [];
before(async () => {
  if (BLOCKED === null) trusted = await trustedArtifact();
});
after(async () => {
  for (const s of systems.splice(0)) await s.stop();
  for (const c of closers.splice(0)) await c();
  for (const r of roots.splice(0)) removeStateRoot(r);
  trusted?.cleanup();
});

const sudo = (args: string[]) => spawnSync("sudo", ["-n", ...args], { encoding: "utf8" });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor<T>(what: string, fn: () => T | undefined | false, timeoutMs = 20_000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await sleep(250);
  }
}

type World = Awaited<ReturnType<typeof world>>;

async function world(o: { network?: string; launch?: boolean } = {}) {
  const key = randomBytes(32);
  const payer = addressOfPrivateKey(key);
  const payee = addressOfPrivateKey(randomBytes(32));
  const chain: SimChain = createSimChain({ network: TESTNET_NETWORK, asset: TESTNET_USDC, now: () => Math.floor(Date.now() / 1000) });
  const rpcUrl = await chain.listen();
  chain.mint(payer, 1_000_000n);
  const facilitator = createSimFacilitator(chain, TESTNET_NETWORK);
  const service = testnetService(payee, PRICE);
  const seller: Seller = await startSeller({
    publicOrigin: TESTNET_SELLER_ORIGIN,
    routes: [{ method: "POST", path: TESTNET_SELLER_PATH, requirements: testnetRequirements(service), body: () => JSON.stringify({ report: "paid" }) }],
    facilitator: facilitator.client,
  });
  closers.push(() => seller.close(), () => chain.close());
  const policyStateRoot = freshPolicyState({ state: testnetPolicyState(service), ttlSeconds: 60 });
  const executorStateRoot = freshExecutorState();
  roots.push(policyStateRoot, executorStateRoot);
  const s = await trusted.launch({
    policyStateRoot,
    executorStateRoot,
    ttlSeconds: 60,
    reconcileIntervalMs: 300,
    expiryReleaseIntervalMs: 300,
    payment: {
      kind: "x402-evm",
      network: o.network ?? TESTNET_NETWORK.caip2,
      rpcUrl,
      approvedRecipients: [payee],
      endpoints: { [TESTNET_SELLER_ORIGIN]: seller.url },
      receiptTimeoutMs: 3_000,
      walletKeyHex: key.toString("hex"),
    },
  });
  systems.push(s);
  const policyTemp = mkdtempSync(join(tmpdir(), "rpc-policy-"));
  try {
    const source = join(policyTemp, "policy.json");
    writeFileSync(source, JSON.stringify({ network: TESTNET_NETWORK.caip2, endpoints: [rpcUrl] }), { mode: 0o600 });
    const installed = sudo(["install", "-o", "oxdeai-executor", "-m", "600", source, join(executorStateRoot, "reconciliation-rpc.json")]);
    assert.equal(installed.status, 0, installed.stderr);
  } finally { rmSync(policyTemp, { recursive: true }); }

  const request = (q: string) => ({
    service_id: service.service_id,
    method: "POST",
    url: `${service.resource}?topic=${q}`,
    body: JSON.stringify({ q }),
    network: service.network,
    asset: service.asset,
    recipient: service.pay_to,
    max_amount: PRICE.toString(),
  });
  const authorize = async (q = "celo") => {
    const r = (await s.runAgent(PROBE, ["authorize-request", s.paths.publicSocket, JSON.stringify(request(q))])).result as any;
    assert.ok(r?.authorization, `authorize: ${JSON.stringify(r)}`);
    return r as { request: unknown; intent_ref: unknown; authorization: { auth_id: string; intent_hash: string } };
  };
  const submit = async (a: unknown) => (await s.runAgent(PROBE, ["submit", s.paths.publicSocket, JSON.stringify(a)])).result as any;
  const policy = () => JSON.parse(s.privileged.read(join(s.paths.authStateDir, "state.json")).toString("utf8"));
  const reservation = (id: string) => policy().reservations[id];
  const spent = () => BigInt(policy().state.budget.spent_in_period[AGENT_ID]?.$bigint ?? "0");
  const keyHex = key.toString("hex");
  key.fill(0);
  return { s, chain, facilitator, seller, rpcUrl, payer, payee, service, authorize, submit, reservation, spent, keyHex };
}

/** journal-cli as the executor identity, asynchronously: this process serves the simulated RPC meanwhile. */
const cli = (w: World, ...args: string[]) => w.s.runAs("executor", join(w.s.paths.apps.executor, "src/isolation/journal-cli.ts"), [w.s.paths.journalDir, ...args]);
const walletKeyPath = (w: World) => join(w.s.paths.executorDir, "x402-wallet.key");

test("XP1 x402 testnet payment through the four isolated identities; the wallet key is executor-private and in no config or log", opts, async () => {
  const w = await world();
  const a = await w.authorize();
  const r = await w.submit(a);
  assert.deepEqual([r.decision, r.executed], ["ALLOW", true], JSON.stringify(r));
  const t = w.chain.transfers();
  assert.deepEqual([t.length, t[0]!.from, t[0]!.to, t[0]!.value, t[0]!.nonce], [1, w.payer, w.payee, PRICE, eip3009NonceForIntent(a.authorization.intent_hash)]);
  await waitFor("confirmed", () => w.reservation(a.authorization.auth_id).state === "CONFIRMED", 20_000);
  assert.equal(w.spent(), PRICE);
  // The agent identity cannot read the key file; the config names only its path.
  const read = (await w.s.runAgent(PROBE, ["read", walletKeyPath(w)])).result as any;
  assert.deepEqual(read[walletKeyPath(w)], { ok: false, code: "EACCES" }, JSON.stringify(read));
  const cfg = w.s.privileged.read(w.s.paths.executorConfig).toString("utf8");
  assert.ok(!cfg.includes(w.keyHex), "the key is not in the executor config");
  for (const n of w.s.privileged.list(w.s.paths.logsDir)) {
    if (n === "staging") continue;
    assert.ok(!w.s.privileged.read(join(w.s.paths.logsDir, n)).toString("utf8").includes(w.keyHex), `key leaked in ${n}`);
  }
  const mode = sudo(["stat", "-c", "%U %a", walletKeyPath(w)]).stdout.trim();
  assert.equal(mode, "oxdeai-executor 600");
});

test("XP2 SIGKILL after the signed payment was sent: PAYMENT_UNKNOWN; after restart the replay is refused and it stays fully charged; reconciled only from the mined receipt", opts, async () => {
  const w = await world();
  const a = await w.authorize();
  await w.s.stopExecutor();
  await w.s.startExecutor({ crashAfterPaymentSent: true });
  const r = await w.submit(a);
  assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
  assert.equal(r.executed, "unknown");
  assert.equal(w.chain.transfers().length, 1, "it paid before the crash");
  await sleep(500);
  await w.s.startExecutor(); // restart, no faults
  await w.s.restartGateway();
  const again = await w.submit(a);
  assert.notEqual(again.decision, "ALLOW", JSON.stringify(again));
  assert.equal(w.chain.transfers().length, 1, "never paid twice");
  const held = await waitFor("uncertain", () => w.reservation(a.authorization.auth_id).state === "UNCERTAIN" && w.reservation(a.authorization.auth_id));
  assert.equal(held.charged, PRICE.toString(), "fully charged, never released without evidence");
  // Operator reconciliation from the chain.
  await w.s.stopExecutor();
  const wrongTx = await cli(w, "resolve-x402", a.authorization.intent_hash, "0x" + "ab".repeat(32), w.rpcUrl, walletKeyPath(w), "wrong tx");
  assert.notEqual(wrongTx.code, 0);
  assert.match(wrongTx.stderr, /NO_SETTLEMENT_EVIDENCE/);
  const ok = await cli(w, "resolve-x402", a.authorization.intent_hash, w.chain.transfers()[0]!.hash, w.rpcUrl, walletKeyPath(w), "XP2: settled on chain");
  assert.equal(ok.code, 0, ok.stderr);
  assert.match(ok.stdout, /EIP3009_ONCHAIN/);
  await w.s.startExecutor();
  await waitFor("confirmed", () => w.reservation(a.authorization.auth_id).state === "CONFIRMED", 20_000);
  assert.equal(w.spent(), PRICE);
});

test("XP3 rollback: a journal-only restore is refused at startup; journal + checkpoint restored together and re-armed: the replay is refused by the auth service; one transfer", opts, async () => {
  const w = await world();
  const a = await w.authorize();
  await w.s.stopExecutor();
  const parent = mkdtempSync(join(tmpdir(), "oxdeai-x402-snap-"));
  roots.push(join(parent, "journal"));
  const jsnap = join(parent, "journal");
  const csnap = join(parent, "checkpoint.log");
  assert.equal(sudo(["cp", "-a", w.s.paths.journalDir, jsnap]).status, 0);
  assert.equal(sudo(["cp", "-a", w.s.paths.executorAnchorPath, csnap]).status, 0);
  await w.s.startExecutor();
  assert.equal((await w.submit(a)).decision, "ALLOW");
  await w.s.stopExecutor();
  // (a) journal alone.
  assert.equal(sudo(["mv", "-T", w.s.paths.journalDir, `${w.s.paths.journalDir}.newer`]).status, 0);
  assert.equal(sudo(["cp", "-a", jsnap, w.s.paths.journalDir]).status, 0);
  await assert.rejects(w.s.startExecutor(), /JOURNAL_ROLLBACK_DETECTED/);
  // (b) journal and checkpoint together, +a re-armed by hand (the F-SIBLING laundering end state).
  const cp = w.s.paths.executorAnchorPath;
  assert.equal(sudo(["chattr", "-a", cp]).status, 0);
  assert.equal(sudo(["cp", "-a", csnap, cp]).status, 0);
  assert.equal(sudo(["chattr", "+a", cp]).status, 0);
  await w.s.startExecutor();
  await w.s.restartGateway();
  const r = await w.submit(a);
  assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
  assert.match(JSON.stringify(r), /CLAIM_REFUSED:NOT_ELIGIBLE/);
  assert.equal(w.chain.transfers().length, 1);
  assert.equal(w.chain.balanceOf(w.payee), PRICE);
});

test("XP4 authorization service outage: nothing reaches the facilitator; the rejection is not final", opts, async () => {
  const w = await world();
  const a = await w.authorize();
  await w.s.stopAuth();
  const r = await w.submit(a);
  assert.notEqual(r.decision, "ALLOW", JSON.stringify(r));
  assert.equal(r.final, false);
  assert.equal(w.facilitator.calls.settle, 0);
  assert.equal(w.chain.transfers().length, 0);
  await w.s.startAuth();
});

test("XP5 an x402 executor configured for a mainnet network refuses to start", opts, async () => {
  await assert.rejects(world({ network: "eip155:42220" }), /NETWORK_NOT_AUTHORIZED:mainnet/);
});

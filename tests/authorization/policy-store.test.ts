// SPDX-License-Identifier: MIT
/**
 * Phase 2D: the durable policy store (src/authorization/policy-state-file.ts)
 * on a temporary directory, with the real anchor code and no module mocks.
 *
 *   PF1-PF4  L-1: an uncertain PREPARE append or read-back blocks every later
 *            load and commit until a restart; nothing is ever appended to a
 *            stale tip; a restart recovers through the crash-state table;
 *            DONE-before-confirmation holds.
 *   RB1-RB5  D2: the anchor rebuilds the exact head state (every field); a
 *            tampered payload is refused at startup; a legacy anchor (no
 *            payloads) is not rebuildable until its first Phase 2D commit;
 *            aborted PREPAREs never contribute; a rolled-back state file is
 *            refused and the rebuild restores the head.
 */
import assert from "node:assert/strict";
import { appendFileSync, chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import type { State } from "@oxdeai/core";
import { nextEntry, parseAnchor, readAnchor, rebuildMaterial, sealEntry, sha256, type AnchorEntry } from "../../src/authorization/policy-anchor.ts";
import { anchorPayload, initialStateFile, openFilePolicyStateStore, rebuildStateBytes, type PolicyStateFaults } from "../../src/authorization/policy-state-file.ts";
import { newReservation } from "../../src/authorization/reservations.ts";
import { AGENT_ID, initialPolicyState } from "../../src/system.ts";

const dirs: string[] = [];
after(() => {
  for (const d of dirs) {
    chmodSync(d, 0o700);
    rmSync(d, { recursive: true, force: true });
  }
});
const binding = { issuer: "test", policyId: "p", policyVersion: "v", agentId: AGENT_ID };
const lock = { path: "fake", assertOwned() {}, release() {} };

/** A Phase 2D-initialized state directory (INIT with a full payload), or a legacy one (no payloads). */
function fresh(o: { legacy?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "oxdeai-store-test-"));
  dirs.push(dir);
  const state = initialPolicyState();
  const bytes = initialStateFile(binding, state);
  writeFileSync(join(dir, "state.json"), bytes);
  const anchorPath = join(dir, "anchor.log");
  const genesis = { kind: "PREPARE" as const, op: "INIT" as const, version: 0, state_sha256: sha256(bytes), spent: {}, ...(o.legacy ? {} : { payload: anchorPayload({ state }, {}, true) }) };
  let text = nextEntry(undefined, genesis).text;
  text += nextEntry(parseAnchor(text), { kind: "DONE", version: 0, state_sha256: sha256(bytes) }).text;
  writeFileSync(anchorPath, text);
  const open = (faults?: PolicyStateFaults) => openFilePolicyStateStore(dir, { binding, lock, anchorPath, requireAppendOnly: false, faults });
  return { dir, anchorPath, open, chain: () => parseAnchor(readFileSync(anchorPath, "utf8")), file: () => readFileSync(join(dir, "state.json"), "utf8") };
}

type Store = ReturnType<ReturnType<typeof fresh>["open"]>;
let n = 0;
/** One commit that charges 1 and adds a reservation (like an ALLOW). */
async function charge(store: Store): Promise<boolean> {
  const cur = await store.load();
  n += 1;
  const id = `auth-${n}`;
  const next: State = { ...cur.state, budget: { ...cur.state.budget, spent_in_period: { ...cur.state.budget.spent_in_period, [AGENT_ID]: (cur.state.budget.spent_in_period[AGENT_ID] ?? 0n) + 1n } } };
  const r = newReservation({ auth_id: id, intent_hash: "a".repeat(64), agent_id: AGENT_ID, domain: null, amount: "1", expiry: 100 + n, at: n });
  return store.commit(next, cur.version, { ...cur.reservations, [id]: r });
}
async function tryIt(f: () => Promise<unknown>): Promise<{ ok: boolean; error?: string }> {
  try {
    await f();
    return { ok: true };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

for (const mode of ["full", "torn", "readback"] as const) {
  test(`PF1 PREPARE failure (${mode}): not confirmed; every later load and commit refused without touching the anchor; a restart recovers`, async () => {
    const f = fresh();
    const store = f.open({ failPrepare: mode });
    const first = await tryIt(() => charge(store));
    assert.equal(first.ok, false, "the faulted commit never returns true");
    const before = readFileSync(f.anchorPath, "utf8");
    const retry = await tryIt(() => charge(store));
    assert.equal(retry.ok, false);
    assert.match(String(retry.error), /POLICY_STATE_UNCONFIRMED/);
    assert.match(String((await tryIt(() => store.load())).error), /POLICY_STATE_UNCONFIRMED/, "loads refused too");
    assert.equal(readFileSync(f.anchorPath, "utf8"), before, "nothing appended after the uncertain write (no stale tip)");
    // Restart: the crash-state table resolves the uncertain entry (torn tail acknowledged / open PREPARE aborted).
    const again = f.open();
    assert.equal(f.chain().pending, undefined);
    assert.equal(f.chain().head!.version, 0);
    assert.equal((await again.load()).state.budget.spent_in_period[AGENT_ID] ?? 0n, 0n, "the uncertain commit never took effect");
    assert.equal(await charge(again), true);
    assert.equal(f.chain().head!.version, 1);
    assert.equal((await again.load()).state.budget.spent_in_period[AGENT_ID], 1n, "exactly one charge, from the successful commit");
    assert.equal(rebuildStateBytes(f.chain(), binding).bytes, f.file(), "the recovered anchor still rebuilds exactly");
  });
}

for (const mode of ["full", "torn", "readback"] as const) {
  test(`PF5 PREPARE failure (${mode}) invalidates the writer state at once: the very next load is refused, before any further commit`, async () => {
    // The `broken` flag itself, not the stale-tip guard (which only acts when another append is attempted).
    const f = fresh();
    const store = f.open({ failPrepare: mode });
    assert.equal((await tryIt(() => charge(store))).ok, false);
    const r = await tryIt(() => store.load());
    assert.equal(r.ok, false, "no state is served by a writer whose anchor tip is unknown");
    assert.match(String(r.error), new RegExp(`POLICY_STATE_UNCONFIRMED:PREPARE of version 1 outcome unknown`));
  });
}

test("PF2 stale-tip guard: an entry appended by anyone else between commits stops this writer before it appends", async () => {
  const f = fresh();
  const store = f.open();
  assert.equal(await charge(store), true);
  // A valid PREPARE for the next version, written by another writer (the chain still parses).
  appendFileSync(f.anchorPath, nextEntry(f.chain(), { kind: "PREPARE", op: "COMMIT", version: 2, state_sha256: sha256("other"), spent: {} }).text);
  assert.equal(f.chain().pending!.version, 2, "the foreign entry is a valid chain entry");
  const before = readFileSync(f.anchorPath, "utf8");
  const r = await tryIt(() => charge(store));
  assert.equal(r.ok, false);
  assert.match(String(r.error), /anchor tip changed/);
  assert.equal(readFileSync(f.anchorPath, "utf8"), before, "this writer appended nothing");
  assert.match(String((await tryIt(() => store.load())).error), /POLICY_STATE_UNCONFIRMED/, "and refuses from then on");
});

test("PF3 DONE before confirmation: a DONE failure is never confirmed, blocks the store, and the restart completes the PREPARE whose state is in place", async () => {
  const f = fresh();
  const store = f.open({ failDoneAppend: true });
  assert.equal((await tryIt(() => charge(store))).ok, false);
  assert.match(String((await tryIt(() => store.load())).error), /POLICY_STATE_UNCONFIRMED/);
  const again = f.open();
  assert.equal(f.chain().head!.version, 1);
  assert.equal((await again.load()).version, 1);
});

test("PF4 every confirmed commit has its DONE as the anchor tip and the head hash of the state file", async () => {
  const f = fresh();
  const store = f.open();
  for (let i = 0; i < 3; i++) {
    assert.equal(await charge(store), true);
    const log = f.chain();
    assert.equal(log.tip!.kind, "DONE");
    assert.equal(log.head!.state_sha256, sha256(f.file()));
  }
});

test("RB1 rebuild reproduces the head state file byte for byte, including every non-budget field (kill switch, velocity, nonces, tool limits, concurrency)", async () => {
  const f = fresh();
  const store = f.open();
  for (let i = 0; i < 4; i++) assert.equal(await charge(store), true);
  const cur = await store.load();
  const changed = {
    ...cur.state,
    kill_switch: { global: false, agents: { [AGENT_ID]: true } },
    velocity: { ...cur.state.velocity, counters: { [AGENT_ID]: { window_start: 1000, count: 7 } } },
    replay: { ...cur.state.replay, nonces: { [AGENT_ID]: [{ nonce: "42", ts: 1000 }] } },
    tool_limits: { ...cur.state.tool_limits, calls: { [AGENT_ID]: [{ ts: 1000 }] } },
    concurrency: { ...cur.state.concurrency, active: { [AGENT_ID]: 1 }, active_auths: { [AGENT_ID]: { "auth-1": { expires_at: 2000 } } } },
  } as unknown as State;
  assert.equal(await store.commit(changed, cur.version, cur.reservations), true);
  const { bytes, version } = rebuildStateBytes(f.chain(), binding);
  assert.equal(version, 5);
  assert.equal(bytes, f.file(), "bit-exact");
  const parsed = JSON.parse(bytes);
  assert.deepEqual(parsed.state.kill_switch.agents, { [AGENT_ID]: true });
  assert.deepEqual(parsed.state.velocity.counters[AGENT_ID], { window_start: 1000, count: 7 });
  assert.equal(parsed.state.replay.nonces[AGENT_ID][0].nonce, "42");
  assert.equal(parsed.state.concurrency.active[AGENT_ID], 1);
  assert.equal(Object.keys(parsed.reservations).length, 4);
  assert.equal(parsed.state.budget.spent_in_period[AGENT_ID].$bigint, "4");
});

test("RB2 a tampered payload with a re-sealed chain is refused at startup and by rebuild (the rebuilt state does not hash to the head)", async () => {
  const f = fresh();
  const store = f.open();
  assert.equal(await charge(store), true);
  assert.equal(await charge(store), true);
  // Rewrite history: mark the first reservation RELEASED in the version-2 payload and re-seal every hash.
  const entries = f.chain().entries.map((e) => ({ ...e })) as AnchorEntry[];
  const target = entries.find((e) => e.kind === "PREPARE" && e.version === 1)!;
  const res = { ...(target.payload!.reservations as Record<string, Record<string, unknown>>) };
  const id = Object.keys(res)[0]!;
  res[id] = { ...res[id], state: "RELEASED", charged: "0" };
  (target as { payload: unknown }).payload = { ...target.payload!, reservations: res };
  let text = "";
  let prev = "0".repeat(64);
  for (const e of entries) {
    const { hash: _h, ...body } = e;
    const sealed = sealEntry({ ...body, prev });
    text += `${JSON.stringify(sealed)}\n`;
    prev = sealed.hash;
  }
  writeFileSync(f.anchorPath, text);
  assert.equal(parseAnchor(text).head!.version, 2, "the re-sealed chain itself parses");
  assert.throws(() => f.open(), /POLICY_ANCHOR_INCONSISTENT:POLICY_REBUILD_MISMATCH/);
  assert.throws(() => rebuildStateBytes(readAnchor(f.anchorPath), binding), /POLICY_REBUILD_MISMATCH/);
});

test("RB3 a legacy anchor (no payloads) is not rebuildable; its first Phase 2D commit carries the full table and makes it rebuildable", async () => {
  const f = fresh({ legacy: true });
  assert.equal(rebuildMaterial(f.chain()).covered, false);
  assert.throws(() => rebuildStateBytes(f.chain(), binding), /POLICY_REBUILD_INCOMPLETE/);
  const store = f.open();
  assert.equal(await charge(store), true);
  assert.equal(f.chain().entries.filter((e) => e.kind === "PREPARE").at(-1)!.payload?.full, true);
  assert.equal(rebuildStateBytes(f.chain(), binding).bytes, f.file());
  assert.equal(await charge(store), true);
  assert.notEqual(f.chain().entries.filter((e) => e.kind === "PREPARE").at(-1)!.payload?.full, true, "later commits carry only their changes");
  assert.equal(rebuildStateBytes(f.chain(), binding).bytes, f.file());
});

test("RB4 an aborted PREPARE never contributes to a rebuild", async () => {
  const f = fresh();
  const store = f.open();
  assert.equal(await charge(store), true);
  // The next commit's temp file cannot be created: its PREPARE is appended, then aborted.
  chmodSync(f.dir, 0o500);
  const failed = await tryIt(() => charge(store));
  chmodSync(f.dir, 0o700);
  assert.equal(failed.ok, false);
  const log = f.chain();
  assert.equal(log.tip!.kind, "ABORT");
  const aborted = log.entries.filter((e) => e.kind === "PREPARE").at(-1)!;
  assert.equal(Object.keys(aborted.payload!.reservations).length, 1, "the aborted PREPARE carried a new reservation");
  const ghost = Object.keys(aborted.payload!.reservations)[0]!;
  const { bytes } = rebuildStateBytes(log, binding);
  assert.equal(bytes, f.file());
  assert.equal(JSON.parse(bytes).reservations[ghost], undefined, "its reservation is not in the rebuilt state");
  assert.equal(await charge(store), true, "the store continues after a clean abort");
  assert.equal(rebuildStateBytes(f.chain(), binding).bytes, f.file());
});

test("RB5 a rolled-back state file is refused at startup; the rebuilt head bytes are the current state again", async () => {
  const f = fresh();
  const store = f.open();
  assert.equal(await charge(store), true);
  const older = f.file();
  assert.equal(await charge(store), true);
  const head = f.file();
  writeFileSync(join(f.dir, "state.json"), older);
  assert.throws(() => f.open(), /POLICY_STATE_ROLLBACK/);
  const { bytes } = rebuildStateBytes(f.chain(), binding);
  assert.equal(bytes, head, "the anchor alone reproduces the head");
  writeFileSync(join(f.dir, "state.json"), bytes);
  assert.equal((await f.open().load()).version, 2);
});

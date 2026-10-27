// SPDX-License-Identifier: MIT
/** R-F3: missing, empty, or malformed required allowlists fail closed before issuance. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createLocalSystem, initialPolicyState } from "../../src/system.ts";
import { assertNoPayment, requestFor, SERVICES } from "../helpers.ts";

type Allowlists = Record<string, unknown>;

const CONFIGS: Array<[string, (al: Allowlists) => void, string]> = [
  ["empty targets (no allowed services)", (al) => (al.targets = []), "ALLOWLIST_TARGETS_EMPTY"],
  ["empty assets", (al) => (al.assets = []), "ALLOWLIST_ASSETS_EMPTY"],
  ["empty action_types", (al) => (al.action_types = []), "ALLOWLIST_ACTION_TYPES_EMPTY"],
  ["targets absent", (al) => delete al.targets, "ALLOWLIST_TARGETS_MISSING"],
  ["assets absent", (al) => delete al.assets, "ALLOWLIST_ASSETS_MISSING"],
  ["action_types absent", (al) => delete al.action_types, "ALLOWLIST_ACTION_TYPES_MISSING"],
  ["targets not an array", (al) => (al.targets = "x402:*"), "ALLOWLIST_TARGETS_MISSING"],
  ["targets with empty string", (al) => (al.targets = [""]), "ALLOWLIST_TARGETS_INVALID"],
  ["assets with non-string entry", (al) => (al.assets = [42]), "ALLOWLIST_ASSETS_INVALID"],
];

for (const [name, mutate, code] of CONFIGS) {
  for (const service of [SERVICES.weather, SERVICES.unlisted]) {
    test(`R-F3 ${name}: PDP DENY for ${service.service_id}, no authorization, no state change`, async () => {
      const state = initialPolicyState();
      mutate(state.allowlists as unknown as Allowlists);
      const sys = createLocalSystem({ initialState: state });
      const result = await sys.client.authorize(requestFor(service));
      assert.equal(result.decision, "DENY");
      if (result.decision !== "DENY") return;
      assert.deepEqual(result.reasons, [`POLICY_STATE_INVALID:${code}`]);
      assert.equal((await sys.harness.policyStore.load()).version, 0, "no policy state was committed");
      assertNoPayment(sys);
    });
  }
}

test("R-F3 allowlists object absent: PDP DENY", async () => {
  const state = initialPolicyState() as unknown as Record<string, unknown>;
  delete state.allowlists;
  const sys = createLocalSystem({ initialState: state as never });
  const result = await sys.client.authorize(requestFor(SERVICES.weather));
  assert.equal(result.decision, "DENY");
  if (result.decision !== "DENY") return;
  assert.deepEqual(result.reasons, ["POLICY_STATE_INVALID:ALLOWLISTS_MISSING"]);
  assertNoPayment(sys);
});

// SPDX-License-Identifier: MIT
/**
 * Policy state store used by the authorization service.
 *
 * Contract: `load` throws when state is unavailable (never returns a default),
 * and `commit` is compare-and-set on `version`. The authorization service
 * treats both a throw and a CAS failure as DENY.
 */
import type { State } from "@oxdeai/core";

export type VersionedPolicyState = { readonly state: State; readonly version: number };

export interface PolicyStateStore {
  load(): Promise<VersionedPolicyState>;
  commit(next: State, expectedVersion: number): Promise<boolean>;
}

/** In-memory store. `setAvailable(false)` simulates an unreachable backend. */
export function createInMemoryPolicyStateStore(initial: State | undefined) {
  let current: State | undefined = initial === undefined ? undefined : structuredClone(initial);
  let version = 0;
  let available = true;
  const store: PolicyStateStore & { setAvailable(value: boolean): void; clear(): void } = {
    async load() {
      if (!available) throw new Error("POLICY_STATE_UNAVAILABLE");
      if (current === undefined) throw new Error("POLICY_STATE_MISSING");
      return { state: structuredClone(current), version };
    },
    async commit(next, expectedVersion) {
      if (!available) throw new Error("POLICY_STATE_UNAVAILABLE");
      if (expectedVersion !== version) return false;
      current = structuredClone(next);
      version += 1;
      return true;
    },
    setAvailable(value) {
      available = value;
    },
    clear() {
      current = undefined;
    },
  };
  return store;
}

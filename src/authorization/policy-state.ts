// SPDX-License-Identifier: MIT
/**
 * Policy state store used by the authorization service.
 *
 * Contract: `load` throws when state is unavailable (never returns a default),
 * and `commit` is compare-and-set on `version`. The authorization service
 * treats both a throw and a CAS failure as DENY.
 */
import type { State } from "@oxdeai/core";

const REQUIRED_ALLOWLISTS = ["action_types", "assets", "targets"] as const;

/**
 * Throws unless every required allowlist is a non-empty array of non-empty
 * strings. `@oxdeai/core`'s AllowlistModule treats an empty or absent
 * allowlist as "allow all"; this PoC refuses to evaluate such state instead
 * of changing core semantics.
 */
export function assertRequiredAllowlists(state: unknown): void {
  const allowlists = typeof state === "object" && state !== null ? (state as { allowlists?: unknown }).allowlists : undefined;
  if (typeof allowlists !== "object" || allowlists === null) throw new Error("ALLOWLISTS_MISSING");
  for (const name of REQUIRED_ALLOWLISTS) {
    const list = (allowlists as Record<string, unknown>)[name];
    const label = `ALLOWLIST_${name.toUpperCase()}`;
    if (!Array.isArray(list)) throw new Error(`${label}_MISSING`);
    if (list.length === 0) throw new Error(`${label}_EMPTY`);
    if (list.some((v) => typeof v !== "string" || v.length === 0)) throw new Error(`${label}_INVALID`);
  }
}

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

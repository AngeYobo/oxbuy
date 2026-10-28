// SPDX-License-Identifier: MIT
/**
 * Configuration of the process-isolated deployment.
 *
 * Each trusted process reads one JSON file from its own private directory
 * (mode 0700, file 0600). Only the file's path is passed on the command line;
 * secrets never appear in argv, the environment, logs, or responses.
 */
import { readFileSync } from "node:fs";
import type { AuthorizationAuthority, KeySet } from "@oxdeai/core";

/** Fault injection, set only by the operator in the executor's private config. */
export type ExecutorFaults = {
  /** SIGKILL the executor after STARTED is journaled, before `pay`. */
  readonly crashBeforePay?: boolean;
  /** SIGKILL the executor after `pay` settled, before the journal records it. */
  readonly crashAfterPay?: boolean;
  /** Hold `pay` this long before it starts. */
  readonly delayPayMs?: number;
  /** Hold the /v1/execute response this long after the executor finished. */
  readonly delayResponseMs?: number;
};

export type ServiceConfig = {
  readonly service_id: string;
  readonly resource: string;
  readonly network: string;
  readonly asset: string;
  readonly pay_to: string;
  /** Atomic units, decimal string. */
  readonly price: string;
};

export type ExecutorConfig = {
  readonly socketPath: string;
  readonly internalToken: string;
  readonly journalDir: string;
  readonly walletKeyPath: string;
  readonly ledgerPath: string;
  readonly verification: {
    readonly expectedAudience: string;
    readonly trustedKeySets: readonly KeySet[];
    readonly trustedAuthorizationAuthorities: readonly AuthorizationAuthority[];
  };
  readonly services: readonly ServiceConfig[];
  readonly faults?: ExecutorFaults;
};

/** Gateway (PEP). Holds no signing key and no payment credential. */
export type GatewayConfig = {
  readonly publicSocketPath: string;
  readonly authSocketPath: string;
  readonly executorSocketPath: string;
  /** Defence in depth only: the executor also verifies every authorization. */
  readonly internalToken: string;
  readonly timeoutMs: number;
  /** Public verification material for the PEP. */
  readonly trust: {
    readonly audience: string;
    readonly keySet: KeySet;
    readonly authority: AuthorizationAuthority;
  };
};

/** Fault injection, set only by the operator in the auth service's private config. */
export type AuthFaults = {
  /** SIGKILL the auth service after the policy decision is committed, before the authorization is returned. */
  readonly crashBeforeIssue?: boolean;
};

/** Authorization service (PDP + signer). Holds no payment credential. */
export type AuthConfig = {
  readonly socketPath: string;
  /**
   * Persistent policy state for this policy identity:
   * <stateRoot>/<binding id> (src/isolation/policy-state-admin.ts). Must
   * already be initialized; the service never creates it.
   */
  readonly stateDir: string;
  /** flock(1) target; locked by the launcher's flock wrapper (single writer only when started that way, N1). */
  readonly lockPath: string;
  /** Append-only decision audit log (kept with the persistent state). */
  readonly decisionLogPath: string;
  readonly pdp: {
    readonly privateKeyPem: string;
    readonly kid: string;
    readonly issuer: string;
    readonly audience: string;
    readonly policyVersion: string;
    readonly ttlSeconds: number;
    readonly agentId: string;
  };
  readonly faults?: AuthFaults;
};

export function readConfig<T>(path: string | undefined): T {
  if (!path) throw new Error("usage: <process> <config.json>");
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

/** Line protocol on stdout: one JSON object per line, never a secret. */
export function emit(event: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

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
  /** SIGKILL after the auth_id is consumed (RESERVED), before the intent record exists. */
  readonly crashAfterAuthRecord?: boolean;
  /** The live quote exceeds every authorized amount: an authentic authorization is rejected before execution. */
  readonly quoteDrift?: boolean;
  /** Hold the live quote this long (the authorization can expire meanwhile; Phase 2D, L-4). */
  readonly delayQuoteMs?: number;
  /** `pay` refuses before signing (PaymentRefusedError) after the intent is STARTED. */
  readonly refuseBeforeSigning?: boolean;
  /** SIGKILL after the auth service acknowledged an outcome report, before the ack is journaled. */
  readonly crashBeforeAck?: boolean;
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
  /** Persistent, operator-initialized (Phase 2C; N2): <executorStateRoot>/journal. */
  readonly journalDir: string;
  readonly walletKeyPath: string;
  /** Persistent (Phase 2C; N2): <executorStateRoot>/ledger.jsonl. */
  readonly ledgerPath: string;
  /** Settle channel to the auth service (Phase 2C; src/isolation/settle-channel.ts). */
  readonly settleSocketPath: string;
  readonly proofDir: string;
  /** Ed25519 key that signs outcome reports; only the executor can read it. */
  readonly reportKey: { readonly privateKeyPem: string; readonly kid: string };
  readonly reconcileIntervalMs: number;
  /** Timeout of a claim or VOID request to the auth service (Phase 2D). A timeout abandons the attempt. */
  readonly claimTimeoutMs: number;
  /**
   * Execution domain (Phase 2C; CX2). The executor refuses to start unless its
   * open journal's journal_id, its own uid, and verification.expectedAudience
   * all agree with this.
   */
  readonly domain: { readonly baseAudience: string; readonly journal_id: string; readonly executor_uid: number };
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
  /** CX1 crash windows of the policy-state commit protocol (src/authorization/policy-anchor.ts). */
  readonly crashAfterPrepare?: boolean;
  readonly crashAfterRename?: boolean;
  readonly crashAfterDirSync?: boolean;
  readonly failDoneAppend?: boolean;
  /** SIGKILL after an outcome report was committed, before it is acknowledged. */
  readonly crashAfterSettleCommit?: boolean;
  /** SIGKILL after an execution claim was committed, before it is acknowledged (Phase 2D). */
  readonly crashAfterClaimCommit?: boolean;
  /** SIGKILL after a VOID was committed, before it is acknowledged (Phase 2D). */
  readonly crashAfterVoidCommit?: boolean;
  /** PREPARE append fails: "full" (written, then EIO), "torn" (partial line, then ENOSPC); "readback": written, re-read fails (Phase 2D, L-1). */
  readonly failPrepare?: "full" | "torn" | "readback";
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
  /** Exclusive writer lock, taken by the service itself on its own descriptor (Phase 2C; N1). */
  readonly lockPath: string;
  /** Append-only rollback anchor for this policy identity (Phase 2C; N3). */
  readonly anchorPath: string;
  /** Settle channel (Phase 2C): socket, peer-proof directory, and the executor's identity and report key. */
  readonly settleSocketPath: string;
  readonly proofDir: string;
  readonly executorUid: number;
  readonly executorReportKey: { readonly publicKeyPem: string; readonly kid: string };
  /** Execution domain every reservation is bound to (Phase 2C; CX2); pdp.audience names it. */
  readonly executionDomain: { readonly journal_id: string; readonly executor_uid: number };
  /** Append-only decision audit log (kept with the persistent state). */
  readonly decisionLogPath: string;
  /** How often expired, unclaimed reservations are released (Phase 2D). */
  readonly expiryReleaseIntervalMs: number;
  /** A claim needs `now < expiry - minRemainingSeconds` (Phase 2D; D4). */
  readonly minRemainingSeconds: number;
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

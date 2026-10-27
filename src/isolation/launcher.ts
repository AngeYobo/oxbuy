// SPDX-License-Identifier: MIT
/**
 * Operator launcher for the process-isolated deployment (Phase 2A, mock only).
 *
 * Runs as the operator (the trusted identity, here `codespace`). It:
 *   1. refuses to run unless this module was loaded from an approved,
 *      sealed artifact in the operator's trust store, and that artifact
 *      passes `verifyArtifact` (manifest hashes, ownership, modes, and a
 *      kernel check that the agent identity cannot write it, the store, the
 *      approval, any ancestor, or the node binary). This happens before any
 *      directory is created or process started. The development checkout is
 *      writable by the agent identity in this Codespace, so trusted
 *      processes never load code from it (see src/isolation/artifact.ts);
 *   2. provisions secrets (internal executor token, PDP Ed25519 key, mock
 *      wallet key) into per-process private directories (0700 / 0600) and
 *      the executor's trust anchor (PDP public KeySet + authority);
 *   3. starts Process C (executor) and Process B (gateway) as the operator
 *      identity, with an empty environment except PATH;
 *   4. runs agent programs (Process A) as a different OS identity, by default
 *      the existing unprivileged `nobody` account, through
 *      `sudo setpriv --no-new-privs`. No OS user is created and no system
 *      configuration is changed.
 *
 * Trusted code runs from <store>/artifacts/<digest> (read-only, operator-only).
 * Runtime layout under <root> (mkdtemp, mode 0711):
 *   public/              0755  gateway.sock (0666): the agent's only door
 *   gateway/             0700  config.json (PDP key, executor token)
 *   executor/            0700  config.json, executor.sock (0600),
 *                              mock-wallet.key, ledger.jsonl, journal/
 *   logs/                0700  process stdout/stderr
 */
import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, createWriteStream, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../authorization/policy-state.ts";
import { readFilePaymentJournal } from "../executor/payment-journal.ts";
import { readMockLedger } from "../adapters/mock-buy/mock-settlement.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, GATEWAY_TIMEOUT_MS, PDP_ISSUER, POLICY, POLICY_VERSION, SERVICES } from "../system.ts";
import { selfRoot, verifyArtifact } from "./artifact.ts";
import type { ExecutorConfig, ExecutorFaults, GatewayConfig } from "./config.ts";
import { agentCommand } from "./identity.ts";
import { postJson } from "./ipc.ts";

export { AGENT_GID, AGENT_UID, agentIdentityUnavailableReason } from "./identity.ts";

/** Root of the artifact (or checkout) this launcher was loaded from. */
export const SELF_ROOT = selfRoot(fileURLToPath(import.meta.url));

function secureDir(path: string, mode: number): string {
  mkdirSync(path, { recursive: true });
  chmodSync(path, mode);
  return path;
}

/** Write a private file. chmod after write: a default ACL overrides `mode`. */
function writePrivate(path: string, data: string | Buffer): void {
  writeFileSync(path, data, { mode: 0o600, flag: "wx" });
  chmodSync(path, 0o600);
}

export type LaunchOptions = {
  readonly ttlSeconds?: number;
  readonly gatewayTimeoutMs?: number;
  readonly executorFaults?: ExecutorFaults;
  /** Per-agent budget, atomic units. */
  readonly budget?: string;
  /** Directory in which the runtime root is created. Default: os.tmpdir(). */
  readonly runtimeParent?: string;
  /** Working directory for agent programs (must be readable by the agent). Default: process.cwd(). */
  readonly agentCwd?: string;
};

export type AgentRun = { code: number | null; stdout: string; stderr: string; result: unknown };

export async function launchIsolatedSystem(opts: LaunchOptions = {}) {
  // 1. Verify the artifact this code runs from. Throws before anything is created.
  const artifact = verifyArtifact(SELF_ROOT);
  const app = SELF_ROOT;

  const root = mkdtempSync(join(opts.runtimeParent ?? tmpdir(), "oxdeai-p2a-"));
  chmodSync(root, 0o711);
  const publicDir = secureDir(join(root, "public"), 0o755);
  const gatewayDir = secureDir(join(root, "gateway"), 0o700);
  const executorDir = secureDir(join(root, "executor"), 0o700);
  const logsDir = secureDir(join(root, "logs"), 0o700);

  // 2. Secrets and trust material.
  const internalToken = randomBytes(32).toString("hex");
  const { privateKey } = generateKeyPairSync("ed25519");
  const pdpPrivateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const kid = `pdp-${randomBytes(4).toString("hex")}`;
  const ttlSeconds = opts.ttlSeconds ?? POLICY.ttlSeconds;
  const pdpSettings = {
    issuer: PDP_ISSUER,
    audience: GATEWAY_AUDIENCE,
    policyVersion: POLICY_VERSION,
    ttlSeconds,
    agentId: AGENT_ID,
  };
  const trust = createAuthorizationService({
    ...pdpSettings,
    stateStore: createInMemoryPolicyStateStore(undefined),
    now: () => Math.floor(Date.now() / 1000),
    signingKey: { privateKeyPem: pdpPrivateKeyPem, kid },
  }).trustMaterial;

  const paths = {
    root,
    app,
    publicSocket: join(publicDir, "gateway.sock"),
    gatewayDir,
    gatewayConfig: join(gatewayDir, "config.json"),
    executorDir,
    executorConfig: join(executorDir, "config.json"),
    executorSocket: join(executorDir, "executor.sock"),
    journalDir: join(executorDir, "journal"),
    walletKeyPath: join(executorDir, "mock-wallet.key"),
    ledgerPath: join(executorDir, "ledger.jsonl"),
    logsDir,
  };
  writePrivate(paths.walletKeyPath, randomBytes(32));

  const executorConfig = (faults: ExecutorFaults): ExecutorConfig => ({
    socketPath: paths.executorSocket,
    internalToken,
    journalDir: paths.journalDir,
    walletKeyPath: paths.walletKeyPath,
    ledgerPath: paths.ledgerPath,
    verification: {
      expectedAudience: trust.audience,
      trustedKeySets: [trust.keySet],
      trustedAuthorizationAuthorities: [trust.authority],
    },
    services: Object.values(SERVICES).map((s) => ({ ...s, price: s.price.toString() })),
    faults,
  });
  const gatewayConfig: GatewayConfig = {
    publicSocketPath: paths.publicSocket,
    executorSocketPath: paths.executorSocket,
    internalToken,
    timeoutMs: opts.gatewayTimeoutMs ?? GATEWAY_TIMEOUT_MS,
    pdp: { ...pdpSettings, privateKeyPem: pdpPrivateKeyPem, kid, ...(opts.budget ? { budget: opts.budget } : {}) },
  };
  writePrivate(paths.gatewayConfig, JSON.stringify(gatewayConfig));

  // 3. Trusted processes.
  const procs: { executor?: ChildProcess; gateway?: ChildProcess } = {};
  let generation = 0;

  async function start(role: "executor" | "gateway", configPath: string): Promise<ChildProcess> {
    generation += 1;
    const log = createWriteStream(join(logsDir, `${role}-${generation}.log`), { mode: 0o600 });
    const child = spawn(process.execPath, [join(app, "src", "isolation", `${role}-main.ts`), configPath], {
      cwd: app,
      env: { PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout!.pipe(log, { end: false });
    child.stderr!.pipe(log, { end: false });
    await new Promise<void>((resolveReady, reject) => {
      let buf = "";
      const timer = setTimeout(() => reject(new Error(`${role} did not become ready`)), 15_000);
      child.stdout!.on("data", (chunk: Buffer) => {
        buf += chunk.toString("utf8");
        if (buf.split("\n").some((l) => l.includes('"event":"ready"'))) {
          clearTimeout(timer);
          resolveReady();
        }
      });
      child.once("exit", (code) => {
        clearTimeout(timer);
        reject(new Error(`${role} exited during startup (code ${code}); see ${logsDir}`));
      });
    });
    return child;
  }

  function exited(child: ChildProcess | undefined): Promise<void> {
    if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
    return new Promise((r) => child.once("exit", () => r()));
  }

  async function startExecutor(faults: ExecutorFaults = {}): Promise<void> {
    rmSync(paths.executorConfig, { force: true });
    writePrivate(paths.executorConfig, JSON.stringify(executorConfig(faults)));
    procs.executor = await start("executor", paths.executorConfig);
  }

  await startExecutor(opts.executorFaults);
  procs.gateway = await start("gateway", paths.gatewayConfig);

  return {
    artifact: { digest: artifact.digest, store: artifact.store },
    paths,
    pids: () => ({ executor: procs.executor?.pid, gateway: procs.gateway?.pid }),
    /** Operator-only material, for adversarial tests that impersonate a compromised token holder. */
    operatorSecrets: { internalToken, pdpPrivateKeyPem, kid },
    trust,

    /** Run an agent program as the agent OS identity. Its last stdout line is parsed as JSON. */
    runAgent(script: string, args: readonly string[] = [], timeoutMs = 30_000): Promise<AgentRun> {
      const [cmd, cmdArgs] = agentCommand([process.execPath, script, ...args]);
      return new Promise((resolveRun) => {
        const child = spawn(cmd, cmdArgs, { cwd: opts.agentCwd ?? process.cwd(), stdio: ["ignore", "pipe", "pipe"], timeout: timeoutMs });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
        child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
        child.on("close", (code) => {
          const last = stdout.trim().split("\n").at(-1) ?? "";
          let result: unknown;
          try {
            result = JSON.parse(last);
          } catch {
            result = undefined;
          }
          resolveRun({ code, stdout, stderr, result });
        });
      });
    },

    /** Operator (or simulated compromised gateway) request straight to the executor socket. */
    executorPost(path: string, body: unknown, headers: Record<string, string> = {}) {
      return postJson(paths.executorSocket, path, body, headers);
    },
    ledger: () => readMockLedger(paths.ledgerPath),
    journal: () => readFilePaymentJournal(paths.journalDir),

    async crashExecutor(): Promise<void> {
      procs.executor?.kill("SIGKILL");
      await exited(procs.executor);
    },
    async stopExecutor(): Promise<void> {
      procs.executor?.kill("SIGTERM");
      await exited(procs.executor);
    },
    startExecutor,
    async restartGateway(): Promise<void> {
      procs.gateway?.kill("SIGTERM");
      await exited(procs.gateway);
      procs.gateway = await start("gateway", paths.gatewayConfig);
    },
    /** Wait for an executor killed by an injected fault. */
    executorExited: () => exited(procs.executor),

    async stop(opts: { keep?: boolean } = {}): Promise<void> {
      for (const child of [procs.gateway, procs.executor]) child?.kill("SIGTERM");
      await Promise.all([exited(procs.gateway), exited(procs.executor)]);
      if (!opts.keep) rmSync(root, { recursive: true, force: true });
    },
  };
}

export type IsolatedSystem = Awaited<ReturnType<typeof launchIsolatedSystem>>;

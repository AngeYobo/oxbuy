// SPDX-License-Identifier: MIT
/**
 * Operator launcher for the trust-separated deployment (Phase 2B-P0, mock only).
 *
 * Runs as the operator (`codespace`). It:
 *   1. refuses to run unless this module was loaded from an approved,
 *      sealed artifact that passes `verifyArtifact` (manifest hashes,
 *      ownership, modes, and a kernel check that none of the four domain
 *      identities can write it, the store, the approval, any ancestor, or the
 *      node binary). The development checkout is writable by other local
 *      users, so trusted processes never load code from it;
 *   2. refuses (ISOLATION_BLOCKED) unless the four dedicated accounts exist,
 *      are distinct, and can be assumed;
 *   3. deploys one read-only copy of the verified artifact per service, each
 *      re-verified against the manifest, readable only by that service (and
 *      the operator), and kernel-checked as unwritable by every domain
 *      identity. The services share no group, so a single copy would have to
 *      be world-readable, and the agent would then be able to read it;
 *   4. provisions each domain's secrets into a directory only that identity
 *      can enter, and IPC directories that only the legitimate client can
 *      traverse;
 *   5. requires an operator-provisioned, persistent policy state root
 *      (`policyStateRoot` / OXDEAI_POLICY_STATE_ROOT; see
 *      policy-state-admin.ts) with its root-owned anchor root, and a
 *      persistent executor state root (`executorStateRoot` /
 *      OXDEAI_EXECUTOR_STATE_ROOT; see executor-state-admin.ts), each
 *      kernel-checked as unwritable by every identity but its owner. Neither
 *      policy state nor the payment journal is kept in the runtime directory,
 *      so a new deployment gets neither a new budget nor an empty journal;
 *   6. starts auth (which takes its writer lock itself), executor, and
 *      gateway, each as its own identity through
 *      `sudo setpriv --no-new-privs --clear-groups --reset-env`.
 *
 * Runtime layout under <root> (mkdtemp, operator, 0711):
 *   app-<svc>/  operator:<svc>    0750  app/ (0555/0444): verified code copy for one service
 *   public/     gateway:agent     2750  gateway.sock 0660   agent -> gateway
 *   auth-ipc/   auth:gateway      2750  auth.sock 0660      gateway -> auth
 *   exec-ipc/   executor:gateway  2750  executor.sock 0660  gateway -> executor
 *   settle-ipc/ auth:executor     2750  settle.sock 0660    executor -> auth (outcome reports)
 *   settle-proof/ executor:auth   2750  per-request peer-identity proofs (settle-channel.ts)
 *   gateway/    gateway   0700  config.json (public trust material, executor token)
 *   auth/       auth      0700  config.json (signing key)
 *   executor/   executor  0700  config.json (incl. outcome-report key), mock-wallet.key
 *   logs/       operator  0700  process output; staging/ for config installs
 * Everything under <root> is deleted by `stop()` and by the failed-startup
 * cleanup. Persistent, outside <root> (Phase 2C; N2, N3):
 *   <policyStateRoot>/<binding id>/  auth 0700  state.json, writer.lock, decisions.jsonl
 *   <policyStateRoot>.anchor/        root 0755  <binding id>.log (auth 0600, append-only)
 *   <executorStateRoot>/             executor 0700  journal/, ledger.jsonl
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, createWriteStream, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createAuthorizationService } from "../authorization/authorization-service.ts";
import { createInMemoryPolicyStateStore } from "../authorization/policy-state.ts";
import type { MockLedgerEntry } from "../adapters/mock-buy/mock-settlement.ts";
import type { AuthRecord, PaymentJournalEntry, PaymentJournalRecord } from "../executor/payment-journal.ts";
import { AGENT_ID, GATEWAY_AUDIENCE, GATEWAY_TIMEOUT_MS, PDP_ISSUER, POLICY, POLICY_VERSION, SERVICES } from "../system.ts";
import { ancestorDirs, assertUntrustedCannotWrite, selfRoot, setReadOnly, treePaths, verifyArtifact, verifyCopy } from "./artifact.ts";
import type { AuthConfig, AuthFaults, ExecutorConfig, ExecutorFaults, GatewayConfig } from "./config.ts";
import { commandAs, identitiesUnavailableReason, identityOf, writableBy, type Role } from "./identity.ts";
import { domainAudience } from "../executor/execution-domain.ts";
import { executorJournalDir, executorLedgerPath } from "./executor-state-admin.ts";
import { anchorPathOf, anchorRootOf, policyBinding, policyStateDir } from "./policy-state-admin.ts";

export { AGENT_GID, AGENT_UID, agentIdentityUnavailableReason } from "./identity.ts";

/** Root of the artifact (or checkout) this launcher was loaded from. */
export const SELF_ROOT = selfRoot(fileURLToPath(import.meta.url));

type Service = "gateway" | "auth" | "executor";

function sudo(args: readonly string[], input?: string): Buffer {
  const r = spawnSync("sudo", ["-n", ...args], { input, maxBuffer: 64 << 20 });
  if (r.status !== 0) throw new Error(`PRIVILEGED_OP_FAILED:${args[0]}:${r.stderr.toString().trim()}`);
  return r.stdout;
}

export type LaunchOptions = {
  readonly ttlSeconds?: number;
  readonly gatewayTimeoutMs?: number;
  readonly executorFaults?: ExecutorFaults;
  readonly authFaults?: AuthFaults;
  /**
   * Operator-provisioned persistent policy state root (default
   * $OXDEAI_POLICY_STATE_ROOT). Required. The state for this deployment's
   * policy identity must already be initialized (policy-cli.ts init).
   */
  readonly policyStateRoot?: string;
  /**
   * Operator-provisioned persistent executor state root (default
   * $OXDEAI_EXECUTOR_STATE_ROOT). Required; its journal must already be
   * initialized (executor-state-admin.ts).
   */
  readonly executorStateRoot?: string;
  /** Executor outcome-report pass interval. Default 2000 ms. */
  readonly reconcileIntervalMs?: number;
  /** Cancel a reservation this long after its authorization expired. Default 5 s. */
  readonly cancelGraceSeconds?: number;
  /** Directory in which the runtime root is created. Default: os.tmpdir(). */
  readonly runtimeParent?: string;
  /** Working directory for programs run as a domain identity (must be readable by it). Default: process.cwd(). */
  readonly agentCwd?: string;
};

export type RoleRun = { code: number | null; stdout: string; stderr: string; result: unknown };

export async function launchIsolatedSystem(opts: LaunchOptions = {}) {
  // 1. Verify the artifact this code runs from. Throws before anything is created.
  const artifact = verifyArtifact(SELF_ROOT);
  // 2. Four distinct, assumable identities, or nothing starts.
  const blocked = identitiesUnavailableReason();
  if (blocked !== null) throw new Error(`ISOLATION_BLOCKED:${blocked}`);
  // Persistent policy state: required, outside the runtime directory, writable only by auth.
  const policyStateRoot = opts.policyStateRoot ?? process.env.OXDEAI_POLICY_STATE_ROOT;
  if (!policyStateRoot) throw new Error("POLICY_STATE_ROOT_REQUIRED");
  const stateRootStat = spawnSync("sudo", ["-n", "stat", "-c", "%u %a", policyStateRoot], { encoding: "utf8" });
  if (stateRootStat.status !== 0 || stateRootStat.stdout.trim() !== `${identityOf("auth")!.uid} 700`) {
    throw new Error(`POLICY_STATE_ROOT_INVALID:${policyStateRoot} must exist, owned by oxdeai-auth, mode 0700`);
  }
  assertUntrustedCannotWrite(ancestorDirs(policyStateRoot), { anchors: [policyStateRoot], protectedRoots: [] });
  for (const role of ["agent", "gateway", "executor"] as const) {
    if (writableBy(role, [policyStateRoot]).length > 0) throw new Error(`POLICY_STATE_ROOT_WRITABLE_BY:${role}`);
  }
  // Rollback anchor root: root-owned, unwritable by every domain identity (the
  // auth service may only append to its own append-only file inside it).
  const anchorRoot = anchorRootOf(policyStateRoot);
  const anchorStat = spawnSync("sudo", ["-n", "stat", "-c", "%u %a", anchorRoot], { encoding: "utf8" });
  if (anchorStat.status !== 0 || anchorStat.stdout.trim() !== "0 755") throw new Error(`POLICY_ANCHOR_ROOT_INVALID:${anchorRoot} must exist, owned by root, mode 0755`);
  assertUntrustedCannotWrite([anchorRoot, ...ancestorDirs(anchorRoot)], { anchors: [anchorRoot], protectedRoots: [anchorRoot] });

  // Persistent executor state: required, outside the runtime directory, writable only by the executor.
  const executorStateRoot = opts.executorStateRoot ?? process.env.OXDEAI_EXECUTOR_STATE_ROOT;
  if (!executorStateRoot) throw new Error("EXECUTOR_STATE_ROOT_REQUIRED");
  const exStat = spawnSync("sudo", ["-n", "stat", "-c", "%u %a", executorStateRoot], { encoding: "utf8" });
  if (exStat.status !== 0 || exStat.stdout.trim() !== `${identityOf("executor")!.uid} 700`) {
    throw new Error(`EXECUTOR_STATE_ROOT_INVALID:${executorStateRoot} must exist, owned by oxdeai-executor, mode 0700`);
  }
  assertUntrustedCannotWrite(ancestorDirs(executorStateRoot), { anchors: [executorStateRoot], protectedRoots: [] });
  for (const role of ["agent", "gateway", "auth"] as const) {
    if (writableBy(role, [executorStateRoot]).length > 0) throw new Error(`EXECUTOR_STATE_ROOT_WRITABLE_BY:${role}`);
  }

  const root = mkdtempSync(join(opts.runtimeParent ?? tmpdir(), "oxdeai-p2b-"));
  chmodSync(root, 0o711);
  const dir = (name: string) => {
    const p = join(root, name);
    mkdirSync(p);
    chmodSync(p, 0o700);
    return p;
  };
  const logsDir = dir("logs");
  const staging = join(logsDir, "staging");
  mkdirSync(staging);
  chmodSync(staging, 0o700);

  // 3. One read-only code copy per service, verified and kernel-checked.
  const services: readonly Service[] = ["gateway", "auth", "executor"];
  const apps = {} as Record<Service, string>;
  for (const role of services) {
    const parent = join(root, `app-${role}`);
    mkdirSync(parent);
    const copy = join(parent, "app");
    for (const rel of [...artifact.manifest.files.map((f) => f.path), "MANIFEST.json"]) {
      mkdirSync(dirname(join(copy, rel)), { recursive: true });
      writeFileSync(join(copy, rel), readFileSync(join(SELF_ROOT, rel)));
    }
    verifyCopy(copy, artifact.manifest);
    setReadOnly(copy);
    chmodSync(parent, 0o750);
    sudo(["chown", `${process.getuid!()}:${identityOf(role)!.gid}`, parent]);
    apps[role] = copy;
  }
  const node = realpathSync(process.execPath);
  assertUntrustedCannotWrite(
    [...services.flatMap((r) => [dirname(apps[r]), ...treePaths(apps[r])]), root, node, ...ancestorDirs(root), ...ancestorDirs(node)],
    { anchors: [root, node], protectedRoots: [root, node] },
  );

  // 4. Secrets and trust material.
  const internalToken = randomBytes(32).toString("hex");
  const { privateKey } = generateKeyPairSync("ed25519");
  const pdpPrivateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const kid = `pdp-${randomBytes(4).toString("hex")}`;
  // Outcome-report key: the private half only in the executor's config, the public half only in auth's.
  const reportKeys = generateKeyPairSync("ed25519");
  const reportKey = {
    privateKeyPem: reportKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: reportKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    kid: `exec-${randomBytes(4).toString("hex")}`,
  };
  const ttlSeconds = opts.ttlSeconds ?? POLICY.ttlSeconds;
  // Execution domain (CX2): this deployment's executor uid and its journal's immutable identity.
  const journalMarker = spawnSync("sudo", ["-n", "cat", join(executorJournalDir(executorStateRoot), "JOURNAL.json")], { encoding: "utf8" });
  let journalId: unknown;
  try {
    journalId = (JSON.parse(journalMarker.stdout) as { journal_id?: unknown }).journal_id;
  } catch {
    journalId = undefined;
  }
  if (journalMarker.status !== 0 || typeof journalId !== "string") throw new Error(`EXECUTION_DOMAIN_UNAVAILABLE:journal ${executorJournalDir(executorStateRoot)} is missing or not initialized`);
  const executionDomain = { journal_id: journalId, executor_uid: identityOf("executor")!.uid };
  const audience = domainAudience(GATEWAY_AUDIENCE, executionDomain);
  const binding = policyBinding({ ttlSeconds });
  const stateDir = policyStateDir(policyStateRoot, binding);
  const pdpSettings = { issuer: PDP_ISSUER, audience, policyVersion: POLICY_VERSION, ttlSeconds, agentId: AGENT_ID };
  const trust = createAuthorizationService({
    ...pdpSettings,
    stateStore: createInMemoryPolicyStateStore(undefined),
    now: () => Math.floor(Date.now() / 1000),
    signingKey: { privateKeyPem: pdpPrivateKeyPem, kid },
  }).trustMaterial;

  const paths = {
    root,
    /** The executor's code copy (kept as `app` for existing callers); see `apps`. */
    app: apps.executor,
    apps,
    publicDir: dir("public"),
    authIpcDir: dir("auth-ipc"),
    execIpcDir: dir("exec-ipc"),
    settleIpcDir: dir("settle-ipc"),
    proofDir: dir("settle-proof"),
    settleSocket: "",
    gatewayDir: dir("gateway"),
    authDir: dir("auth"),
    executorDir: dir("executor"),
    logsDir,
    publicSocket: "",
    authSocket: "",
    executorSocket: "",
    gatewayConfig: "",
    authConfig: "",
    policyStateRoot,
    /** Persistent policy state for this deployment's policy identity (outside `root`). */
    authStateDir: stateDir,
    writerLock: join(stateDir, "writer.lock"),
    decisionLog: join(stateDir, "decisions.jsonl"),
    /** Append-only rollback anchor for this policy identity (outside `root` and outside the state root). */
    anchorPath: anchorPathOf(policyStateRoot, binding),
    executorStateRoot,
    executorConfig: "",
    /** Persistent journal and ledger (outside `root`). */
    journalDir: executorJournalDir(executorStateRoot),
    walletKeyPath: "",
    ledgerPath: executorLedgerPath(executorStateRoot),
  };
  paths.publicSocket = join(paths.publicDir, "gateway.sock");
  paths.authSocket = join(paths.authIpcDir, "auth.sock");
  paths.executorSocket = join(paths.execIpcDir, "executor.sock");
  paths.gatewayConfig = join(paths.gatewayDir, "config.json");
  paths.authConfig = join(paths.authDir, "config.json");
  paths.executorConfig = join(paths.executorDir, "config.json");
  paths.settleSocket = join(paths.settleIpcDir, "settle.sock");
  paths.walletKeyPath = join(paths.executorDir, "mock-wallet.key");

  /** Install a 0600 file owned by `role` (via a private operator staging file). */
  function install(role: Role, dest: string, data: string | Buffer): void {
    const tmp = join(staging, `${randomBytes(8).toString("hex")}`);
    writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
    chmodSync(tmp, 0o600);
    try {
      const id = identityOf(role)!;
      sudo(["install", "-o", String(id.uid), "-g", String(id.gid), "-m", "0600", tmp, dest]);
    } finally {
      rmSync(tmp, { force: true });
    }
  }

  const executorConfig = (faults: ExecutorFaults): ExecutorConfig => ({
    socketPath: paths.executorSocket,
    internalToken,
    journalDir: paths.journalDir,
    walletKeyPath: paths.walletKeyPath,
    ledgerPath: paths.ledgerPath,
    verification: { expectedAudience: trust.audience, trustedKeySets: [trust.keySet], trustedAuthorizationAuthorities: [trust.authority] },
    services: Object.values(SERVICES).map((s) => ({ ...s, price: s.price.toString() })),
    settleSocketPath: paths.settleSocket,
    proofDir: paths.proofDir,
    reportKey: { privateKeyPem: reportKey.privateKeyPem, kid: reportKey.kid },
    reconcileIntervalMs: opts.reconcileIntervalMs ?? 2_000,
    cancelGraceSeconds: opts.cancelGraceSeconds ?? 5,
    domain: { baseAudience: GATEWAY_AUDIENCE, ...executionDomain },
    faults,
  });
  const authConfig = (faults: AuthFaults): AuthConfig => ({
    socketPath: paths.authSocket,
    stateDir: paths.authStateDir,
    lockPath: paths.writerLock,
    anchorPath: paths.anchorPath,
    decisionLogPath: paths.decisionLog,
    settleSocketPath: paths.settleSocket,
    proofDir: paths.proofDir,
    executorUid: identityOf("executor")!.uid,
    executorReportKey: { publicKeyPem: reportKey.publicKeyPem, kid: reportKey.kid },
    executionDomain,
    pdp: { ...pdpSettings, privateKeyPem: pdpPrivateKeyPem, kid },
    faults,
  });
  const gatewayConfig: GatewayConfig = {
    publicSocketPath: paths.publicSocket,
    authSocketPath: paths.authSocket,
    executorSocketPath: paths.executorSocket,
    internalToken,
    timeoutMs: opts.gatewayTimeoutMs ?? GATEWAY_TIMEOUT_MS,
    trust: { audience: trust.audience, keySet: trust.keySet, authority: trust.authority },
  };

  // Ownership and modes of the domain directories.
  const layout: Array<[string, Role, Role, string]> = [
    [paths.gatewayDir, "gateway", "gateway", "0700"],
    [paths.authDir, "auth", "auth", "0700"],
    [paths.executorDir, "executor", "executor", "0700"],
    [paths.publicDir, "gateway", "agent", "2750"],
    [paths.authIpcDir, "auth", "gateway", "2750"],
    [paths.execIpcDir, "executor", "gateway", "2750"],
    [paths.settleIpcDir, "auth", "executor", "2750"],
    [paths.proofDir, "executor", "auth", "2750"],
  ];
  for (const [p, u, g, mode] of layout) {
    sudo(["chown", `${identityOf(u)!.uid}:${identityOf(g)!.gid}`, p]);
    sudo(["chmod", mode, p]);
  }
  install("executor", paths.walletKeyPath, randomBytes(32));

  // 5. Trusted processes, each as its own identity.
  const procs: Partial<Record<Service, { child: ChildProcess; pid: number }>> = {};
  let generation = 0;

  async function start(role: Service, configPath: string): Promise<void> {
    generation += 1;
    const log = createWriteStream(join(logsDir, `${role}-${generation}.log`), { mode: 0o600 });
    // Auth takes its writer lock itself, on its own descriptor (exit 75 if held).
    const argv = [node, join(apps[role], "src", "isolation", `${role}-main.ts`), configPath];
    const [cmd, args] = commandAs(role, argv);
    const child = spawn(cmd, args, { cwd: apps[role], stdio: ["ignore", "pipe", "pipe"] });
    child.stdout!.pipe(log, { end: false });
    child.stderr!.pipe(log, { end: false });
    const pid = await new Promise<number>((resolveReady, reject) => {
      let buf = "";
      let errBuf = "";
      child.stderr!.on("data", (chunk: Buffer) => (errBuf = (errBuf + chunk.toString("utf8")).slice(-2000)));
      const timer = setTimeout(() => reject(new Error(`${role} did not become ready; see ${logsDir}`)), 20_000);
      child.stdout!.on("data", (chunk: Buffer) => {
        buf += chunk.toString("utf8");
        const line = buf.split(/\r?\n/).find((l) => l.includes('"event":"ready"'));
        if (line) {
          clearTimeout(timer);
          resolveReady((JSON.parse(line.trim()) as { pid: number }).pid);
        }
      });
      child.once("exit", (code) => {
        clearTimeout(timer);
        // Include the tail of its output (e.g. the auth service's "refused" reason; never secrets).
        const tail = `${buf}${errBuf}`.trim().split(/\r?\n/).slice(-3).join(" | ");
        reject(new Error(`${role} exited during startup (code ${code}): ${tail}`));
      });
    });
    procs[role] = { child, pid };
  }

  function exited(role: Service): Promise<void> {
    const child = procs[role]?.child;
    if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
    return new Promise((r) => child.once("exit", () => r()));
  }

  async function signal(role: Service, sig: "TERM" | "KILL"): Promise<void> {
    const p = procs[role];
    if (!p) return;
    spawnSync("sudo", ["-n", "kill", `-${sig}`, String(p.pid)]);
    await exited(role);
  }

  async function startExecutor(faults: ExecutorFaults = {}): Promise<void> {
    install("executor", paths.executorConfig, JSON.stringify(executorConfig(faults)));
    await start("executor", paths.executorConfig);
  }
  async function startAuth(faults: AuthFaults = {}): Promise<void> {
    install("auth", paths.authConfig, JSON.stringify(authConfig(faults)));
    await start("auth", paths.authConfig);
  }

  function runAs(role: Role, script: string, args: readonly string[] = [], o: { input?: string; timeoutMs?: number } = {}): Promise<RoleRun> {
    const [cmd, cmdArgs] = commandAs(role, [node, script, ...args]);
    return new Promise((resolveRun) => {
      const child = spawn(cmd, cmdArgs, { cwd: opts.agentCwd ?? process.cwd(), stdio: ["pipe", "pipe", "pipe"], timeout: o.timeoutMs ?? 30_000 });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
      child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
      child.stdin.end(o.input ?? "");
      child.on("close", (code) => {
        const last = stdout.trim().split(/\r?\n/).at(-1) ?? "";
        let result: unknown;
        try {
          result = JSON.parse(last);
        } catch {
          result = undefined;
        }
        resolveRun({ code, stdout, stderr, result });
      });
    });
  }

  function runAsSync(role: Role, argv: readonly string[], timeoutMs = 20_000) {
    const [cmd, args] = commandAs(role, argv);
    return spawnSync(cmd, args, { cwd: role === "agent" ? "/" : apps[role], encoding: "utf8", timeout: timeoutMs });
  }

  /** One IPC request made by `role` (trusted ipc-cli from the deployed copy). */
  async function postAs(role: Service, socket: string, path: string, body: unknown, headers: Record<string, string> = {}) {
    const r = await runAs(role, join(apps[role], "src", "isolation", "ipc-cli.ts"), [], { input: JSON.stringify({ socket, path, body, headers }) });
    const out = r.result as { status?: number; body?: unknown; error?: string } | undefined;
    if (!out || out.error !== undefined) throw Object.assign(new Error(out?.error ?? `ipc-cli failed: ${r.stderr}`), { code: out?.error });
    return out as { status: number; body: unknown };
  }

  /** Operator inspection through sudo; never handed to a domain. */
  const privileged = {
    read: (p: string): Buffer => sudo(["cat", p]),
    exists: (p: string): boolean => spawnSync("sudo", ["-n", "test", "-e", p]).status === 0,
    stat: (p: string) => {
      const [mode, user, group] = sudo(["stat", "-c", "%a %U %G", p]).toString().trim().split(" ");
      return { mode: Number.parseInt(mode!, 8), user: user!, group: group! };
    },
    list: (p: string): string[] => sudo(["ls", "-1", p]).toString().split("\n").filter(Boolean),
  };

  function ledger(): MockLedgerEntry[] {
    if (!privileged.exists(paths.ledgerPath)) return [];
    return privileged
      .read(paths.ledgerPath)
      .toString("utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as MockLedgerEntry);
  }

  /** Snapshot of the journal, read as the executor identity with the trusted journal CLI. */
  function journal() {
    const r = runAsSync("executor", [node, join(apps.executor, "src", "isolation", "journal-cli.ts"), paths.journalDir, "list"]);
    if (r.status !== 0) throw new Error(`journal read failed: ${r.stderr}`);
    const records = JSON.parse(r.stdout) as PaymentJournalRecord[];
    const by = new Map(records.map((x) => [x.intent_hash, x]));
    const a = runAsSync("executor", [node, join(apps.executor, "src", "isolation", "journal-cli.ts"), paths.journalDir, "auths"]);
    if (a.status !== 0) throw new Error(`journal read failed: ${a.stderr}`);
    const auths = JSON.parse(a.stdout) as AuthRecord[];
    return {
      list: () => records,
      /** Per-authorization dispositions (consumed auth_ids). */
      auths: () => auths,
      auth: (authId: string) => auths.find((x) => x.auth_id === authId),
      inspect: (h: string) => by.get(h),
      get: (h: string): PaymentJournalEntry | undefined => {
        const x = by.get(h);
        return x && (x.detail === undefined ? { state: x.state } : { state: x.state, detail: x.detail });
      },
    };
  }

  try {
    await startAuth(opts.authFaults);
    await startExecutor(opts.executorFaults);
    install("gateway", paths.gatewayConfig, JSON.stringify(gatewayConfig));
    await start("gateway", paths.gatewayConfig);
  } catch (err) {
    // A refused startup (e.g. auth rejecting its policy state) leaves nothing running.
    await Promise.all((["gateway", "executor", "auth"] as const).map((r) => signal(r, "TERM")));
    spawnSync("sudo", ["-n", "rm", "-rf", "--", root]);
    throw err;
  }

  return {
    artifact: { digest: artifact.digest, store: artifact.store },
    paths,
    identities: { agent: identityOf("agent")!, gateway: identityOf("gateway")!, auth: identityOf("auth")!, executor: identityOf("executor")! },
    pids: () => ({ executor: procs.executor?.pid, gateway: procs.gateway?.pid, auth: procs.auth?.pid }),
    /** Operator-provisioned material, for adversarial tests that need crafted artifacts. */
    operatorSecrets: { internalToken, pdpPrivateKeyPem, kid },
    trust,
    privileged,

    runAs,
    runAsSync,
    postAs,
    /** Run an agent program as the agent OS identity. Its last stdout line is parsed as JSON. */
    runAgent: (script: string, args: readonly string[] = [], timeoutMs = 30_000) => runAs("agent", script, args, { timeoutMs }),
    /** Request to the executor made by the gateway identity (its only legitimate client). */
    executorPost: (path: string, body: unknown, headers: Record<string, string> = {}) => postAs("gateway", paths.executorSocket, path, body, headers),
    /** Request to the authorization service made by the gateway identity. */
    authPost: (path: string, body: unknown) => postAs("gateway", paths.authSocket, path, body),
    ledger,
    journal,

    crashExecutor: () => signal("executor", "KILL"),
    stopExecutor: () => signal("executor", "TERM"),
    startExecutor,
    executorExited: () => exited("executor"),
    crashAuth: () => signal("auth", "KILL"),
    stopAuth: () => signal("auth", "TERM"),
    startAuth,
    authExited: () => exited("auth"),
    async restartAuth(faults: AuthFaults = {}): Promise<void> {
      await signal("auth", "TERM");
      await startAuth(faults);
    },
    async restartGateway(): Promise<void> {
      await signal("gateway", "TERM");
      await start("gateway", paths.gatewayConfig);
    },

    async stop(o: { keep?: boolean } = {}): Promise<void> {
      await Promise.all((["gateway", "executor", "auth"] as const).map((r) => signal(r, "TERM")));
      if (!o.keep) spawnSync("sudo", ["-n", "rm", "-rf", "--", root]);
    },
  };
}

export type IsolatedSystem = Awaited<ReturnType<typeof launchIsolatedSystem>>;

# Process Isolation: Phase 2A / 2B (mock only)

Phase 2A splits the Phase 1 system into three independently launched
processes and puts an OS-enforced boundary between the untrusted agent and
the payment capability. Payments are still the mock adapter: no wallet, no
signing, no network, no chain.

Results and commands: `docs/CONFORMANCE.md`. Environment: `evidence/environment.txt`.

**Current deployment: Phase 2B (four security domains).** §0 describes it
and supersedes the Phase 2A topology in §1-§4, which is kept as history.
Phase 2B moves the PDP and its signing key out of the gateway into a separate
authorization service, and runs the agent, the gateway, the auth service, and
the executor under four dedicated OS accounts. The operator (`codespace`)
still has passwordless sudo and is trusted (§0.7).

## 0. Phase 2B: four security domains

### 0.1 Processes and identities

```text
  oxdeai-agent (999)        oxdeai-gateway (996)          oxdeai-auth (995)              oxdeai-executor (994)
 ┌───────────────┐  public  ┌──────────────────┐  auth-ipc ┌────────────────────┐
 │ agent         │ ───────> │ gateway (PEP)    │ ────────> │ auth (PDP+signer)  │
 │ no secrets    │  socket  │ public trust     │  socket   │ Ed25519 key        │
 └───────────────┘          │ material, token  │           │ policy state       │
                            │ no key, no wallet│           │ no wallet          │
                            └────────┬─────────┘           └────────────────────┘
                                     │ exec-ipc socket                ▲ signed AuthorizationV1
                                     ▼ {action, authorization}        │ (via gateway)
                            ┌──────────────────────────────┐
                            │ executor                     │  verifies signature, issuer/policy,
                            │ mock wallet key, ledger,     │  audience, expiry, intent hash;
                            │ journal; no signing key      │  reserves intent; pays (mock)
                            └──────────────────────────────┘
```

| Step | Process (identity) | Protected resource / check |
| --- | --- | --- |
| Receive agent request | gateway | Public socket `0660 gateway:agent` in `public/` (`2750`) |
| Evaluate policy | auth | Its own persistent policy state; exact request schema |
| Construct and sign AuthorizationV1 | auth | Signing key in `auth/config.json` (`0600`). issuer, audience, expiry, `agent_id`, nonce, and policy id are set by auth, never taken from the caller |
| Verify (PEP) | gateway | Public KeySet and authority |
| Verify again | executor | Its own trust anchor (operator-provisioned). Signature, issuer/policy, audience, expiry, `intent_hash` recomputed from the action |
| Reserve intent | executor | Durable journal, O_EXCL |
| Mock payment | executor | Wallet key `0600`; payment binding re-checked before signing |
| Record settlement | executor | Ledger file and journal SETTLED |

The accounts are dedicated system accounts with no login shell, a locked
password, no sudo rights, and only their own primary group. They were created
in this disposable Codespace with the user's approval; sudoers was not
changed.

### 0.2 Filesystem layout and observed permissions

Runtime (per deployment, operator-owned root `0711`):

```text
app-<svc>/   operator:<svc>     0750   app/ 0555/0444: verified code copy for one service only
public/      gateway:agent      2750   gateway.sock 0660
auth-ipc/    auth:gateway       2750   auth.sock 0660
exec-ipc/    executor:gateway   2750   executor.sock 0660
gateway/     gateway            0700   config.json (public trust material, executor token)
auth/        auth               0700   config.json (signing key)
executor/    executor           0700   config.json, mock-wallet.key, ledger.jsonl, journal/
logs/        operator           0700
```

Persistent (outside any deployment; §0.4):

```text
<policyStateRoot>/                 auth 0700
  <binding id>/                    auth 0700   state.json 0600, writer.lock, decisions.jsonl 0600
```

The table below is what the kernel answered to a probe run as each identity
during the Phase 2B-R2 review. R = read, W = write (checked with
`access(W_OK)`, nothing written), C = connect, `—` = cannot even reach the
path (`stat`: `EACCES`).

| Resource | agent | gateway | auth | executor | operator (no sudo) |
| --- | --- | --- | --- | --- | --- |
| Signing key (`auth/config.json`) | — | — | R W | — | — |
| Mock wallet key | — | — | — | R W | — |
| Policy state (`state.json`, its directory) | — | — | R W | — | — |
| Decision log | — | — | R W | — | — |
| Payment journal, `journal.log` | — | — | — | R W | — |
| Ledger | — | — | — | R W | — |
| Executor config | — | — | — | R W | — |
| Gateway config | — | R W | — | — | — |
| Gateway socket | C | C (owner) | — | — | — |
| Auth socket | — | C | C (owner) | — | — |
| Executor socket | — | C | — | C (owner) | — |
| Approved artifact, approval record | — | — | — | — | R, not W |
| Code copy of gateway / auth / executor | — | R own copy only | R own copy only | R own copy only | R, not W |
| Runtime root | not R, not W | not R, not W | not R, not W | not R, not W | R W |

Observed matched intended in every cell. The operator reaches service-owned
files only through sudo. The independent Phase 2B-R4 audit reproduced the
gateway, auth, executor, and agent cells it probed (CONFORMANCE.md, "Phase
2B-R4 independent audit").

This matrix holds for the standard launch, where all four accounts are
looked up by name. It is not unconditional: with the `OXDEAI_AGENT_UID` /
`OXDEAI_AGENT_GID` override (F5, B7), the R4 audit launched an "agent" in the
gateway's group, and that agent could connect to the auth and executor
sockets.

### 0.3 The authorization service is not a signing oracle

- **One route.** `/v1/authorize` is the only route; anything else is 404.
- **Exact input.** The body must be exactly a `PurchaseRequest`, with no
  extra keys. A pre-built `decision: "ALLOW"` authorization, extra
  caller-chosen fields (`agent_id`, `expiry`, `audience`, `issuer`,
  `intent_ref`), or a wrapped `{request, decision}` are all refused with
  `REQUEST_INVALID` before anything is evaluated.
- **Independent evaluation.** The service validates the request itself, runs
  the published `PolicyEngine` against its own persistent state (allowlists
  that fail closed, per-action cap, budget, velocity, nonce replay), commits
  the next state, and only then builds and signs the authorization.
- **Bound to the request.** Every request field is bound into the intent
  hash. Every identity, validity, and policy field comes from the service's
  own configuration.
- **Limit:** a compromised gateway can still obtain authorizations that the
  policy allows. It cannot obtain any other.

### 0.4 Persistent policy state (budget)

Implementation: `src/authorization/policy-state-file.ts` and
`src/isolation/policy-state-admin.ts`. Operator tool:
`src/isolation/policy-cli.ts`.

- **Location.** An operator-provisioned state root outside every deployment
  (`policyStateRoot` or `OXDEAI_POLICY_STATE_ROOT`). The launcher refuses to
  start without one (`POLICY_STATE_ROOT_REQUIRED`). The root must be owned by
  `oxdeai-auth` with mode 0700. The kernel must confirm, as each other
  identity, that it cannot write the root or any ancestor directory (a sticky
  ancestor such as `/tmp` is accepted under the §3a rule).
- **Binding.** State for a policy identity lives in
  `<root>/<sha256(issuer, policy_id, policy_version, agent_id)>/`. The same
  binding is stored inside `state.json`, and the auth service checks it
  against the binding it computes from its own engine configuration. Another
  policy identity therefore finds no state and refuses to start; state copied
  into the wrong directory is refused with `POLICY_STATE_BINDING_MISMATCH`.
- **Initialization: explicit, operator-run, once.**
  `policy-cli.ts init <root> [budget]` runs `mkdir` on the binding directory
  without `-p`; that is the atomic first-time test. It then installs
  `state.json` with a rename. A second init fails with `POLICY_STATE_EXISTS`
  and leaves the existing state unchanged. A partial init leaves a directory
  without `state.json`: the service refuses to start and re-init is refused,
  so the operator must inspect it.
- **Normal startup never creates state.** Missing state gives
  `POLICY_STATE_MISSING`, unreadable state `POLICY_STATE_UNREADABLE`,
  corrupt state `POLICY_STATE_CORRUPT`, and a foreign binding
  `POLICY_STATE_BINDING_MISMATCH`. In each case the auth service exits with
  code 78, and the gateway answers DENY `PDP_UNAVAILABLE`. While the service
  is running, the same conditions give DENY
  `POLICY_STATE_UNAVAILABLE:<cause>`.
- **Updates.** Each update is compare-and-set on `version`: write a temp
  file, fsync it, rename it over `state.json`, fsync the directory.
- **Single writer, when started by the launcher.** The launcher starts the
  service as
  `flock --nonblock --conflict-exit-code 75 <binding dir>/writer.lock node auth-main.ts`.
  `flock(2)` is an exclusive kernel lock, released by the kernel when the
  last holder exits; there is never a stale-lock check-then-delete. For
  services started this way, at most one holds the lock: a second
  launcher-style instance exits with code 75 before Node starts, and a lock
  file that cannot be opened makes `flock` exit with code 66. Both fail
  closed (R3-F4a..F4d).
- **Startup self-check (limited; N1).** At startup the service also refuses
  to run (`POLICY_STATE_LOCK_NOT_HELD`, exit 78) unless both of these hold:
  - some open descriptor in the process refers to the lock file, and
  - a non-blocking probe on the lock conflicts, so *some* process holds it.

  These checks do not prove that *this* process holds the lock. A process
  that only opened `writer.lock`, without locking it, passes both while
  another instance holds the lock. The R4 audit started such a second auth
  service (`exec 9<writer.lock; node auth-main.ts`) next to a running one.
  It started, became a second writer of the same state, and took over the
  auth socket. The self-check reliably refuses only an instance that has no
  descriptor on the lock (R3-F4b) or runs while no one holds it.

  The single-writer property therefore holds only for auth services started
  through the approved launcher's `flock` wrapper. Starting `auth-main.ts`
  any other way is not covered. Doing so requires running code as
  `oxdeai-auth`, which only the operator and root can do; the threat model
  assumes an attacker cannot. Verifying ownership of the lock on the
  inherited descriptor is an open hardening requirement before real
  payments (N1).
- **No rollback resistance (N3).** Persistence protects the budget against
  ordinary restarts, crashes, and redeployments. It does not detect an older
  but valid `state.json` being put back: the file carries its own version
  counter and nothing outside it. The R4 audit restored an earlier copy
  (version 3 → 2), and the service started and issued a new ALLOW from the
  restored, previously consumed capacity. Only the operator or root can
  write the file; a malicious or mistaken operator restore is outside the
  current threat model. Rollback-resistant accounting is required before
  real payments.
- **What the budget counts.** The budget is *reserved authorization
  capacity*. It is charged for an authorization's `max_amount` when the
  decision is committed, not for the amount actually settled. An
  authorization that is never delivered (auth crashes after committing) or
  never used still counts. Nothing is refunded automatically, for example
  when the gateway did not receive a response. Reconciling the budget with
  settled payments is a remaining requirement (CONFORMANCE.md, F3).

**Recovery procedures**
- **Auth crashed:** start it again. The kernel has already released the
  lock.
- **Auth refuses to start (state missing, corrupt, or unreadable):** do not
  re-initialize to "fix" it, because that would restore spending capacity.
  Either restore `state.json` from a backup, or decide explicitly to start a
  new policy identity. A backup is older than the lost state: restoring it
  gives back every authorization committed since it was taken (N3).
  Restoring is therefore not financially safe on its own. Before restarting,
  reconcile the restored budget against the decision log
  (`decisions.jsonl`) and the payments actually made, and reduce the
  remaining capacity accordingly.
- **Partially initialized binding directory:** inspect it, then remove it
  deliberately before running init again.

### 0.5 Trusted code in four domains

- **Verification before import.** The approved artifact is verified before
  import (§3a).
- **One copy per service.** The launcher deploys one copy per service,
  checked against the manifest and readable only by that service. The
  kernel confirms, as each of the four identities, that none of them can
  write any copy, the store, the approval, any ancestor directory, or the
  node binary.
- **Configs.** The operator writes each config with `sudo install`. Each is
  owned by its service with mode 0600. A service can rewrite its own config
  but no other service's.

### 0.6 IPC access control

- **The directory is the access control.** Each service socket sits in a
  setgid directory whose group is its only legitimate client: the agent for
  the gateway socket, the gateway for the auth and executor sockets.
  Sockets are 0660. Only the owning service can create or replace a socket.
- **No peer-uid check.** Node.js exposes no `SO_PEERCRED`, so services do
  not check the caller's uid themselves. The executor token is defence in
  depth; the executor's own verification of every authorization is the real
  control.
- **No inet listeners.** No service opens a TCP or UDP listener.

### 0.7 Limitations of Phase 2B

| # | Limitation |
| --- | --- |
| B1 | The operator (`codespace`) has passwordless sudo and can do everything; nothing here resists root or the operator. |
| B2 | One container, one kernel. Accounts are separated by uid only, with no further sandboxing (seccomp, namespaces). |
| B3 | A compromised gateway can request any payment the policy allows and can exhaust the budget (denial of service). It holds the executor token, which is useless without a valid authorization. The R4 audit demonstrated the exhaustion: 3 ALLOWs requested by the gateway identity used up a 30,000 budget with 0 ledger entries, after which the agent got `BUDGET_EXCEEDED`. |
| B4 | Budget = reserved authorization capacity, charged at decision commit, not settled spend (F3). It never exceeds the configured budget in authorizations, but it is not the amount actually paid. Settlement reconciliation is required before real payments; automatic refunds are not implemented. |
| B5 | The auth service is the single point of policy truth. If it is compromised, the attacker holds the signing key, but not the wallet. |
| B6 | The executor journal still uses its Phase 2A pid-based stale-lock takeover (check-then-delete). In R4 mock experiments (two executors racing on a stale lock, 150 rounds), both opened the journal as writers in 11 rounds. No duplicate reservation occurred in any round, because each intent and `auth_id` is still created O_EXCL. These experiments do not prove that no race can produce a duplicate. A robust exclusive lock is required before real payments. |
| B7 | The `OXDEAI_AGENT_UID` / `OXDEAI_AGENT_GID` override in `identity.ts` is honored by the deployed launcher (F5). The distinctness check compares uids only, not gids. R4 launched with `OXDEAI_AGENT_UID=4242 OXDEAI_AGENT_GID=984` (the gateway's group): the launch was accepted, and the "agent" could connect to the auth and executor sockets and obtain an in-policy ALLOW directly from the auth service. The executor token and the policy still prevented any unauthorized mock payment (ledger 0). The variables are set in the operator's launch environment, which the operator controls in this threat model; this is not a demonstrated bypass by a gateway-only attacker. It weakens socket-level isolation, so the override must be removed, restricted to tests, or hardened before real payments. |
| B8 | The auth service's startup lock check does not prove lock ownership (N1, §0.4). The single-writer property holds only for services started through the launcher's `flock`. Required before real payments: verify the lock on the inherited descriptor. |
| B9 | The executor's payment journal and mock ledger live in the per-deployment runtime root, which `stop()` and the failed-startup cleanup delete (N2, A9). Unresolved STARTED / UNKNOWN records do not survive a full teardown and redeployment. A persistent journal and durable settlement reconciliation are required before real payments. |
| B10 | Policy state is persistent but not rollback-resistant (N3, §0.4). |

#### Phase 2C disposition of B4, B6-B10 (mock only; details in docs/FINANCIAL-INTEGRITY.md)

The rows above record Phase 2B as audited and are kept unchanged.

| # | Phase 2C status |
| --- | --- |
| B4 | Addressed in the mock: every ALLOW is a reservation that moves to CONFIRMED (charge = settled amount), RELEASED (provably never paid), or UNCERTAIN (held) on signed executor outcome reports (F3). Budget remains reserved capacity until an outcome arrives. |
| B6 | Replaced: the journal lock is a kernel `flock(2)` on the executor's own descriptor; no pid-based takeover (FI-12/13, J3). |
| B7 | Removed: identities are looked up by account name only; the UID/GID overrides are ignored and unsafe configurations are rejected before start (F5; ID1-ID4). |
| B8 | Fixed: the auth service takes and re-checks the lock on its own descriptor (N1; R3-F4b). |
| B9 | Fixed: journal and ledger live in a persistent, operator-initialized executor state root outside the runtime root (N2; FI-07a/b, FI-09, FI-10). |
| B10 | Partially addressed: rollback detection with an append-only, hash-chained anchor (N3; CX1a-d, AN1-AN10). CONDITIONAL: does not resist root, the operator, or whole-filesystem rollback. |

## 1. Phase 2A processes and trust boundaries (historical; superseded by §0)

```text
  OS identity: nobody (uid 65534)          OS identity: operator (codespace, uid 1000)
  no_new_privs, no supplementary groups
 ┌──────────────────────────────┐        ┌───────────────────────────────────────────────┐
 │ Process A: agent             │        │ Process B: gateway   src/isolation/gateway-main │
 │ src/isolation/agent-main.ts  │  UDS   │  PDP: PolicyEngine + Ed25519 signing key       │
 │ (tests: agent-probe.ts)      │───────>│  PEP: createPepGatewayExecutor (per request)   │
 │                              │ public │  replay store (in memory), policy state        │
 │ knows: public socket path    │ socket │  outcome boundary (classify)                   │
 └──────────────────────────────┘ 0666   └───────────────────────┬───────────────────────┘
          │                                                       │ UDS, private socket 0600
          │  EACCES: executor dir 0700                            │ in dir 0700
          │  EACCES: wallet key, ledger, journal, configs         │ token header +
          │  EPERM:  signals to B and C                           │ { action, authorization }
          │  EACCES: /proc/<pid>/environ, /mem                    v
          │                                        ┌───────────────────────────────────────────────┐
          └───────────── X ───────────────────────>│ Process C: executor  src/isolation/executor-main│
                                                   │  token check (protectUpstreamExecution)       │
                                                   │  verifyAuthorization (strict) + intent_hash   │
                                                   │  re-quote, binding checks                     │
                                                   │  durable journal: reserve auth_id + intent    │
                                                   │  pay -> mock wallet key + ledger (0600)       │
                                                   │  receipt check                                │
                                                   └───────────────────────────────────────────────┘
```

| Boundary | Mechanism | Enforced by | Evidence |
| --- | --- | --- | --- |
| Agent ↔ executor IPC | executor socket 0600 inside a 0700 directory owned by the operator | kernel (path search + socket write permission) | P2A-02 |
| Agent ↔ payment credential and ledger | `mock-wallet.key`, `ledger.jsonl` 0600 in the executor directory | kernel | P2A-11, P2A-12 |
| Agent ↔ journal, configs, secrets | journal dir 0700, files 0600; configs 0600 in 0700 dirs | kernel | P2A-11 |
| Agent ↔ trusted code at runtime | trusted processes run from the approved artifact in an operator-only trust store (0700; files 0444) | kernel | P2A-11, P2A-12 (read/write EACCES) |
| Agent ↔ trusted code at the next launch | launch only via a verified, operator-approved artifact; working tree and its `node_modules` never used (§3a) | kernel + integrity check | SI-01..SI-07 |
| Agent ↔ trusted processes | different uid: signals EPERM, `/proc/<pid>/environ` and `mem` EACCES | kernel | P2A-12 |
| Agent ↔ privilege escalation | `no_new_privs`, `nobody` has no sudo rights | kernel + sudoers | P2A-12 (`sudo -n true` fails) |
| Gateway ↔ executor | internal token **and** executor-side verification of the signed AuthorizationV1 | application | P2A-13 |
| Executor ↔ duplicate payment | atomic O_EXCL reservation of `auth_id` and `intent_hash` in the durable journal | filesystem + application | P2A-07, P2A-08, P2A-14, J1-J2 |

**Not a boundary in this deployment:** gateway ↔ executor, at the OS level
or otherwise. Both run as the operator identity, and the gateway holds the
key that signs authorizations (see §4, A1).

## 2. IPC design and access control

- Transport: HTTP/1.1 with JSON bodies over Unix-domain sockets
  (`src/isolation/ipc.ts`). No process opens a TCP or UDP port. P2A-02
  checks with `ss -ltunp` that the executor's pid owns no inet listener, and
  with `ss -lxp` that it listens on its Unix socket.
- Access control is filesystem permissions. Connecting to a Unix socket
  needs search (`x`) on every directory in its path and write on the socket.
  Node.js exposes no `SO_PEERCRED`, so the executor does not check the
  peer's uid itself.
- Public socket `<root>/public/gateway.sock`, mode 0666, directory 0755.
  Routes: `POST /v1/quote` (read-only, forwarded to the executor),
  `/v1/authorize` (PDP), `/v1/purchase` (PEP).
- Private socket `<root>/executor/executor.sock`, mode 0600, directory
  0700. Routes: `POST /v1/execute`, `/v1/quote`. Both need the internal
  token. `/v1/execute` also needs a body of exactly
  `{ action, authorization }`.
- Body limit 1 MiB.

### Executor-side authorization (a token alone does not authorize payment)

The guard's `executeUpstream` callback receives only the action. The gateway
therefore builds the guard's PEP **per request** and captures the request's
detached, frozen `authorization` in the callback, which sends
`{ action, authorization }` to the executor. The trust material, replay
store, clock, and timeout are the same on every request. No guard code is
changed.

The executor then performs its own checks, in order:

1. Token: `protectUpstreamExecution`.
2. Envelope: exactly `{action, authorization}`, and `authorization` is an
   object.
3. `hashGatewayAction(action)`.
4. `verifyAuthorization` in strict mode, with the executor's own
   operator-provisioned trust anchor: PDP public KeySet, `(issuer, policy_id)`
   authority, and expected audience. This covers the Ed25519 signature,
   issuer and kid, audience, expiry, and `issued_at` plausibility.
5. `authorization.intent_hash === hash`.
6. Re-quote and the Phase 1R binding checks.
7. Durable reservation of `auth_id` and `intent_hash`.
8. `pay`. The adapter re-checks the binding before signing.
9. Receipt check.

### Replay: gateway and executor

| Store | Scope | When consumed | Stops |
| --- | --- | --- | --- |
| Gateway replay store (`@oxdeai/guard` in-memory) | one gateway lifetime | after guard verification, before the executor call | resubmission while the gateway is up (P2A-07, P2A-14) |
| Executor journal `auths/` + `intents/` (durable) | survives restarts of either process within one deployment; deleted with the runtime root at teardown (A9) | immediately before `pay`, together with STARTED | resubmission after a gateway or executor restart (P2A-08), resubmission by a token holder (P2A-07, P2A-13), concurrent duplicates at the executor (P2A-14) |

A valid first-time request is new to both stores, so it passes both. A
request that the executor refuses before reservation (verification or quote
failure) consumes only the gateway's entry; nothing was paid.

Duplicates seen by the executor are never paid. The response depends on the
earlier attempt's state:
- **SETTLED or REFUSED_BEFORE_SIGNING:** `NOT_EXECUTED`, reported as DENY.
- **STARTED or UNKNOWN:** `PAYMENT_UNKNOWN`, reported as INDETERMINATE.

Both carry `EXECUTOR_DUPLICATE_PAYMENT_ATTEMPT` and `prior_state`.

## 3. Deployment and launch

Requirements:
- Linux.
- Node.js ≥ 22.18 (tested on v24.21.0).
- Passwordless `sudo` for the operator.
- `setpriv` (util-linux) with `--reset-env`.
- Phase 2B: the four dedicated accounts `oxdeai-agent`, `oxdeai-gateway`,
  `oxdeai-auth`, and `oxdeai-executor` (§0.1), and `flock` (util-linux).
  (Phase 2A used `nobody` for the agent.) The `OXDEAI_AGENT_UID` /
  `OXDEAI_AGENT_GID` override is a test hook that weakens isolation if set
  (B7); do not set it for a deployment.

```bash
npm ci                      # no new dependencies in Phase 2A or 2B
npm run typecheck
npm test                    # includes the isolation suites (P2A-*, SI-*, R3-*)
npm run demo:isolated       # agent, gateway, auth, executor under four accounts; prints JSON; exit 2 = BLOCKED
```

One-time operator setup (bootstrap; §3a):

```bash
node src/isolation/trust-cli.ts seal "$PWD"         # prints digest + changes vs the approved artifact
node src/isolation/trust-cli.ts approve <digest> "reviewed <what>"
node src/isolation/trust-cli.ts verify

# Phase 2B-R3: persistent policy state (once per state root and policy identity)
node src/isolation/policy-cli.ts provision /path/to/state-root     # oxdeai-auth 0700
node src/isolation/policy-cli.ts init /path/to/state-root [budget]  # fails if already initialized
export OXDEAI_POLICY_STATE_ROOT=/path/to/state-root
```

The state root's parent directories must not be writable by any service or
agent identity (the launcher checks this with the kernel). The default
`~/.oxdeai-celo-poc` is not reachable by `oxdeai-auth`, so choose a root
such as a dedicated directory under a 0711 operator-owned parent.

Operator code obtains the launcher only through `loadVerifiedLauncher()`
(`src/isolation/trusted-entry.ts`). `npm run demo:isolated` does this; it
reports BLOCKED (exit 2) if no artifact is approved. The steps below are
the Phase 2A launch sequence, kept as history. Steps 1 and 2 are unchanged.
For the current Phase 2B sequence (four accounts, per-service code copies,
auth started under `flock`) and layout, see §0 and the header of
`src/isolation/launcher.ts`.

1. **Verify before import.** The entry imports only Node built-ins and the
   verification code. It verifies the approved artifact, then imports the
   launcher from it. Importing evaluates the whole module graph, so nothing
   from an unverified artifact is ever imported.
2. **Verify again before creating anything.** The launcher re-verifies the
   artifact it was loaded from. If it was not loaded from an approved
   artifact, it refuses with `UNTRUSTED_LAUNCHER_LOCATION`.
3. **Create the runtime root.** `mkdtemp` a root under `os.tmpdir()`, mode
   0711.
4. **Generate the secrets: the internal token (32 random bytes), the PDP
   Ed25519 key and kid, and the mock wallet key (32 random bytes). Compute
   the PDP trust anchor (KeySet and `(issuer, policy_id)`). Write the
   executor and gateway configs as 0600 files in their 0700 directories.
5. Start the executor and then the gateway with
   `node <artifact>/src/isolation/<role>-main.ts <config path>`. They run with
   `cwd=<app>` and an environment of only `PATH=/usr/bin:/bin`. Secrets are
   never passed in argv or the environment. Each process prints a
   `{"event":"ready"}` line.
6. Agent programs run through
   `sudo -n setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs --reset-env -- node <script> <args>`.
   No account is created and no system configuration is changed.
   `agentIdentityUnavailableReason()` returns why this is impossible, if it
   is. The tests and demo then report BLOCKED; they never fall back to a
   same-user run.

Trusted code lives at `<store>/artifacts/<digest>/` (§3a). Phase 2A runtime
layout under `<root>` (historical; current layout: §0.2):

```text
public/     0755  gateway.sock (0666)
gateway/    0700  config.json (0600: PDP private key, token)
executor/   0700  config.json (0600: token, trust anchor, faults), executor.sock (0600),
                  mock-wallet.key (0600), ledger.jsonl (0600), journal/ (0700)
logs/       0700  process stdout/stderr
```

### 3a. Trusted deployment artifact (Phase 2A-R)

**Root cause of the pre-launch tampering finding.** In this Codespace the
whole checkout, including `node_modules`, is writable by every local user
(ACL: dirs 0777, files 0666), and the Phase 2A launcher copied `src/` and
`node_modules/@oxdeai` from it at each launch. The agent could plant code
that then ran as the operator at the next launch (reproduced: uid 1000).
`.git` is equally writable, so a pinned commit read through the local
object store is no anchor either.

**Store layout.** `$OXDEAI_TRUST_STORE`, default
`~/.oxdeai-celo-poc/trust`. `/home/codespace` is 0750, so the agent cannot
even traverse it. Implementation: `src/isolation/artifact.ts`.

```text
<store>/                    0700  operator
  approved                  0400  approved digest (atomic rename)
  approvals.log             0600  approval history
  artifacts/<digest>/       dirs 0555, files 0444
    MANIFEST.json           sha256 + size of every file, dependency pins; <digest> = sha256(MANIFEST.json)
    package.json            fixed {"type":"module"}
    src/**                  application source as sealed
    node_modules/@oxdeai/*  extracted from verified registry tarballs
```

**Trust anchors**

| Input | Anchor | Verified by |
| --- | --- | --- |
| `@oxdeai/core@2.0.2`, `@oxdeai/guard@2.0.3` | Versions pinned in the trusted seal code (not taken from the lockfile). Tarball bytes come from the operator's npm cache (`~/.npm/_cacache`, agent cannot traverse it), whose index records the integrity the registry served for the pinned URL. | Tarball re-hashed (sha512) and extracted with root-owned `/usr/bin/tar`; package name and version checked. The lockfile must agree (`SEAL_LOCKFILE_MISMATCH` otherwise). The working tree's `node_modules` is never read. |
| Application source (`src/`) | **Operator approval** of the sealed digest. There is no independent reference for uncommitted code. | `seal` lists every file added, removed, or changed relative to the approved artifact, so the operator approves a reviewed diff. |
| Launch | The approved digest in the operator-only store | `verifyArtifact` (below), before import and again before start |

**`verifyArtifact` refuses unless all of the following hold:**
- The artifact is the approved one.
- `sha256(MANIFEST.json)` equals the digest.
- The file set equals the manifest's, with no symlinks or special files.
- Every file hash matches.
- Every entry is owned by the operator and has no write bits.
- The store and the approval are owned by the operator and not
  group/other-writable.
- The kernel check passes. It runs as the agent identity (`access(W_OK)`
  under `setpriv`, so ACLs count too). The agent must not be able to write:
  - any artifact path, the store, or the approval;
  - the node binary;
  - any ancestor directory of either.

  A sticky ancestor such as `/tmp` is accepted only when the next component
  is operator- or root-owned and itself not agent-writable. If the check
  cannot be run, the launch fails closed.

**Root of trust and residual limits**
- **Bootstrap.** The first seal and approval run from the checkout, which
  must be trusted at that moment. After that, run
  `trust-cli.ts`/`trusted-entry.ts` from the approved artifact.
- **Operator hygiene.** Code the operator runs from the checkout (`npm test`,
  npm scripts, `trust-cli` at bootstrap, `demo-isolated.ts`) is outside the
  guarantee: it runs as the operator. The guarantee covers *launches through
  the verified entry*: agent changes to the working tree, its
  `node_modules`, or its lockfile cannot become trusted code without a new
  operator approval.
- **Misdeployment.** If the store itself were agent-writable, the entry and
  the verification code could also have been replaced. `verifyArtifact`
  detects such misdeployment (SI-06), but the guarantee requires an
  operator-only store.
- **The npm cache** is trusted as recorded by npm at install time; the
  registry was not re-queried.

`/tmp` in this Codespace has a default ACL that gives "other" `rw-` on new
files. That ACL overrides the `open()` mode, so every file and directory the
launcher and journal create is explicitly `chmod`/`fchmod`ed. J6 and P2A-11
check the resulting modes.

Fault injection (`ExecutorFaults`: `crashBeforePay`, `crashAfterPay`,
`delayPayMs`, `delayResponseMs`) is read only from the executor's private
config, which only the operator writes.

## 4. Security assumptions and limitations

Assumptions:
- The kernel enforces the uid and permission checks.
- The operator identity and root are trusted.
- The checkout is not modified by the agent before launch (A4).

| # | Limitation | Consequence |
| --- | --- | --- |
| A1 | **Resolved in Phase 2B (§0).** Was: gateway and executor share the operator uid, and the gateway process holds the PDP authorization signing key. Creating separate accounts needs approval (not given). | **A compromised gateway is not contained.** It can read the mock wallet key and pay directly through the adapter, bypassing the executor and its journal (reproduced in review: ledger +1, no journal record). It can also sign valid authorizations for any payment, so the executor's own signature check (P2A-13) does **not** constrain a gateway that controls the key, even if the OS identities were separated. P2A-13 only shows that a holder of the *token alone* cannot pay. Fixing this needs the PDP and its key in a separate process and identity, and the executor (and buy) under their own identity. |
| A2 | The operator identity (`codespace`) has passwordless sudo. | Since Phase 2B the gateway, auth service, and executor run as their own non-sudo accounts with `no_new_privs`, so compromising one of them is not root-equivalent (P2B-20: `sudo` refused). The operator itself is root-equivalent and trusted (B1). Was (Phase 2A): gateway and executor ran as the operator and were root-equivalent. |
| A3 | **Resolved in Phase 2B:** the agent is `oxdeai-agent`. Was: the agent uses the shared system account `nobody`. | Any other process running as `nobody` has the same access: the public socket only. Production needs a dedicated agent uid. |
| A4 | The development checkout is world-writable in this Codespace (ACL: dirs 0777, files 0666). | Resolved for launches in Phase 2A-R: trusted code comes only from the verified, approved artifact (§3a, SI-01..07). Residual: bootstrap trust, and code the operator runs from the checkout (tests, npm scripts) runs as the operator. |
| A5 | No peer-credential check on the sockets. | Since Phase 2B, connecting to the executor or auth socket needs the gateway's group (or root/operator via sudo); the directory is the access control (§0.6). Any process in that group can connect. At the executor it still needs the token and a valid authorization. With the F5 override the agent can be placed in that group (B7). |
| A6 | One container, one kernel. | Root inside the container bypasses every control. This is not VM or container isolation. |
| A7 | `/proc/<pid>/cmdline` is world-readable (no `hidepid`). | The agent sees the process list and config paths, but no secrets (P2A-12 checks argv). |
| A8 | **Budget part resolved in Phase 2B-R3 (§0.4).** The gateway replay store is still in memory; the executor's durable journal still stops a second payment of the same intent. Was: the PDP policy state (budget, velocity) and the gateway replay store are in memory. | **Budget is not enforced across gateway restarts.** Reproduced: budget 20,000, price 10,000: ALLOW, ALLOW, DENY; restart; ALLOW, ALLOW, DENY. 40,000 was spent. The executor journal prevents only a second payment of the *same* intent, not new intents. |
| A9 | The journal and mock ledger live on the Codespace's local disk (`/tmp`, ext4, fsync'd), inside the per-deployment runtime root (`<root>/executor/`). | Within one deployment they survive executor and gateway restarts and crashes (P2A-08, P2A-09). They do **not** survive a full teardown: `stop()` and the failed-startup cleanup delete the runtime root, including STARTED / UNKNOWN records not yet reconciled (N2, B9). They do not survive loss or rebuild of the Codespace either. Across deployments, old authorizations are still rejected because each deployment generates a new signing key (R4: `AUTH_KID_UNKNOWN`). That key change is a property of this mock deployment, not a substitute for durable reconciliation of uncertain payments. |
| A10 | A gateway timeout or connection failure is always INDETERMINATE, even when nothing reached the executor. | Conservative. The journal tells the operator whether `pay` started. |
| A11 | A stale lock is recovered when its pid is not alive. pid reuse can make a dead holder look alive. | The executor then refuses to start. This fails closed; the operator removes the lock. |
| A12 | `/v1/quote` forwards agent input to the executor (read-only). | Indirect executor attack surface. Validated by the adapter lookup. |
| A13 | No rate limiting on the public socket. | The agent can exhaust the gateway (DoS). |

## 5. Durable payment journal

> **Phase 2C:** this section describes the Phase 2A/2B journal and is kept as
> history. Since Phase 2C the journal is persistent in
> `<executorStateRoot>/journal/` (never inside the runtime root), the lock is
> `journal.lock` taken with `flock(2)` (no pid file, no stale-lock takeover),
> records are published with `link(2)`/`rename(2)` after fsync, an `acks/`
> directory records delivered outcome reports, and a missing or damaged
> journal makes the executor refuse to start. See docs/FINANCIAL-INTEGRITY.md
> §5 and §6.

Implementation: `openFilePaymentJournal` in
`src/executor/payment-journal.ts`. The executor process opens it as a
writer (see "Locking" below for the limits of single-writer enforcement).

Lifetime: the journal is at `<root>/executor/journal/`, inside the
per-deployment runtime root.

| Event | Journal and ledger |
| --- | --- |
| Gateway restart | kept; resubmissions are refused from the journal (P2A-08) |
| Executor restart or crash | kept; open records listed as `needs_reconciliation` (P2A-08, P2A-09) |
| Auth restart | not affected |
| Full teardown (`stop()`, failed startup) and redeployment | **deleted** with the runtime root; unresolved records are lost (N2) |

Reconcile every STARTED / UNKNOWN record (§6) before tearing a deployment
down. A persistent journal outside the runtime root and durable settlement
reconciliation are required before real payments.

```text
journal/                0700
  executor.lock         0600  pid of the writer; created O_EXCL
  intents/<hash>        0600  one JSON record per intent; created O_EXCL
  auths/<sha256(id)>    0600  consumed auth_ids; created O_EXCL
  journal.log           0600  append-only JSONL audit (OPEN, STARTED, final, RESOLVED)
```

- **Reservation:** `reserve()` is synchronous, so there is no interleaving
  inside the executor. Its steps:
  1. If the intent record exists, return DUPLICATE_INTENT with the prior
     state.
  2. Create the `auths/` entry with O_EXCL. EEXIST means AUTH_REPLAY.
  3. fsync the directory.
  4. Create the intent record (STARTED) with O_EXCL. EEXIST means
     DUPLICATE_INTENT.
  5. fsync the directory, then write the audit line.

  O_EXCL also makes reservation atomic across processes. A crash between
  steps 2 and 4 leaves the auth consumed and no intent, which fails closed:
  nothing was paid.
- **Transitions:** STARTED → SETTLED | REFUSED_BEFORE_SIGNING | UNKNOWN,
  once. Each transition writes a temp file, fsyncs it, renames it, and
  fsyncs the directory. Any other transition throws.
- **Storage errors:**
  - Reservation fails: `NOT_EXECUTED EXECUTOR_JOURNAL_UNAVAILABLE`, and
    `pay` is not called (J9a).
  - Final record fails after `pay`: `PAYMENT_UNKNOWN
    EXECUTOR_JOURNAL_WRITE_FAILED`. The journal still says STARTED (J9b).
- **Unreadable record:** reported as UNKNOWN (`JOURNAL_RECORD_UNREADABLE`),
  never as absent (J7).
- **Locking:** `executor.lock` is created O_EXCL and holds the writer's
  pid. A second executor started while the first is alive fails with
  `JOURNAL_LOCKED` (P2A-14, J3). A lock whose pid is dead is taken over and
  logged as `STALE_LOCK_RECOVERED` (J3, P2A-08). The takeover is a
  check-then-delete. Two executors that both find the same stale lock can
  both become writers: R4 observed this in 11 of 150 mock races (B6).
  Reservation stayed exclusive in all of them, because the `auths/` and
  `intents/` entries are created O_EXCL. So single-writer locking is not
  guaranteed; per-intent exclusivity is what prevented duplicates in these
  experiments.
- **No automatic retry and no automatic resolution.** At open, STARTED and
  UNKNOWN records without a resolution are listed: in `journal.log`
  (`needs_reconciliation`) and on the executor's stdout. Their state is
  never changed (J4, P2A-09).

## 6. Recovery and reconciliation procedure

> **Phase 2C:** the current procedure, including the auth-side reservation
> states, policy-state restore, and execution domains, is in
> docs/FINANCIAL-INTEGRITY.md §8. The journal is now at
> `<executorStateRoot>/journal` and survives teardown; the warning at the end
> of this section applies to Phase 2B only.

1. **After any executor crash,** restart it. It recovers the stale lock and
   prints `needs_reconciliation` for each open record. Duplicates of those
   intents are answered INDETERMINATE and never paid.
2. **For each INDETERMINATE result** (it carries `intent_hash`), inspect the
   record:
   ```bash
   node src/isolation/journal-cli.ts <root>/executor/journal pending
   node src/isolation/journal-cli.ts <root>/executor/journal show <intent_hash>
   ```
3. **Establish ground truth out of band.** For the mock, that is
   `ledger.jsonl`, keyed by `intent_hash`. With real buy it is the payer's
   token transfers (FEASIBILITY.md §2, "Settlement transaction").
4. **Stop the executor** (the resolve step needs the writer lock), then
   record the verdict:
   ```bash
   node src/isolation/journal-cli.ts <root>/executor/journal resolve <intent_hash> SETTLED|NOT_SETTLED "<evidence>"
   ```
   The state is kept as history and the verdict is attached alongside it.
   The intent can never be paid again. A new payment needs a new
   authorization from the PDP.
5. **Restart the executor.**

In Phase 2B the journal belongs to `oxdeai-executor`, so `journal-cli.ts`
must run as that account, from the executor's deployed code copy:
`sudo -n setpriv --reuid=oxdeai-executor --regid=oxdeai-executor --clear-groups --no-new-privs --reset-env -- node <root>/app-executor/app/src/isolation/journal-cli.ts <root>/executor/journal ...`
(the tests use `runAsSync("executor", ...)`). The agent and gateway
identities cannot read the journal (P2A-11, P2B-19).

Do all of this before the deployment is stopped: teardown deletes the
journal (§5, N2).

## 7. Read-only `@celo/buy` assessment

This assessment draws only on the documentation evidence already recorded
in `docs/FEASIBILITY.md`, which cites `celo-org/buy-skill` at `20329ce`. No
`buy`, `buy_curl`, `buy_pay_quote`, wallet setup, signing or settlement was
run. The buy source code was not inspected.

| Question | Finding | Status |
| --- | --- | --- |
| Can the live 402 requirements be pinned before signing? | `buy_curl` / `buy curl` take `url`, `method`, `headers`, `body`, and `maxAmount` only (FEASIBILITY §2, steps 2 and 5). Only the price ceiling is pinned. No documented parameter pins `payTo`, network, asset, or the 402 requirement chosen. | NOT_TESTED. Unsupported by the documented interface (INFERRED). |
| Can `payTo`, network, and asset be verified at execution time? | Not as inputs. `no_matching_requirements` refuses when the **account's** network does not match, with nothing signed (FEASIBILITY §2), but that is account configuration, not per-request pinning. Afterwards, the response carries the transaction hash, and the transfer goes to the gateway's `payTo` (FEASIBILITY §2), so this is detection only, as in R-F1c. An executor could fetch the raw 402 itself just before `buy_curl`, but it would still race buy's own fetch. | NOT_TESTED |
| Do quote and payment use consistent request representations? | The docs say to pay "by repeating the identical request": same `url`, `method`, `headers`, `body` for `buy_pay_quote` and `buy_curl`. Units differ: atomic `maxAmount` for MCP, decimal `--max-amount` for the CLI. **Gap in this PoC:** `PurchaseRequest` does not bind request `headers`, which buy accepts. It is unknown whether `buy_curl` reuses the quoted requirements or fetches a new 402. | Partially documented; NOT_TESTED. Headers must be bound (or forbidden) before Phase 2B. |
| Which errors guarantee nothing was signed or submitted? | Documented as refused before signing: the daily cap, the balance check, and `no_matching_requirements`. Documented as ambiguous: `500 settle_uncertain`, and network loss after sending. Price > `maxAmount` refused before signing: not shown. The exact error codes and output shapes of the MCP and CLI are not verified. | NOT_TESTED. Until verified, every buy `pay` error maps to PAYMENT_UNKNOWN (`PaymentRefusedError` only for documented, matched codes). |
| Can the buy process be isolated from the agent's identity? | buy signs in its own process with the OS keychain wallet. The documented default MCP setup runs under the agent's user, which is a bypass. Phase 2A shows that a uid boundary keeps a mock wallet file and the executor socket from the agent. Unverified: whether buy's keychain backend works for a headless service account on Linux (Secret Service / D-Bus), and whether buy supports another key store. | NOT_TESTED |

Consequence for Phase 2B: a buy-backed adapter can bind the *price* before
signing. It cannot bind the *payee, network, or asset* before signing
through the documented interface. Unless the buy source or maintainers show
otherwise, payment-time recipient binding for buy must be reported as a
DESIGN_LIMITATION. The mock's R-F1a guarantee does not carry over.

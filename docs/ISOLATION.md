# Process Isolation: Phase 2A (mock only)

Phase 2A splits the Phase 1 system into three independently launched
processes and puts an OS-enforced boundary between the untrusted agent and
the payment capability. Payments are still the mock adapter: no wallet, no
signing, no network, no chain.

Results and commands: `docs/CONFORMANCE.md` (Phase 2A and 2A-R sections).
Environment: `evidence/environment.txt`.

**Scope of the guarantee.** The agent is isolated from the trusted side, but
the trusted components are **not** isolated from each other:
- The gateway and executor share one OS identity (`codespace`), which has
  passwordless sudo.
- The gateway holds the PDP signing key and can read the mock wallet.

Nothing here protects against a compromised gateway (§4, A1-A2).

## 1. Processes and trust boundaries

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
| Executor journal `auths/` + `intents/` (durable) | survives restarts of either process | immediately before `pay`, together with STARTED | resubmission after a gateway or executor restart (P2A-08), resubmission by a token holder (P2A-07, P2A-13), concurrent duplicates at the executor (P2A-14) |

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
- An unprivileged account for the agent; default `nobody`, override with
  `OXDEAI_AGENT_UID` / `OXDEAI_AGENT_GID`.

```bash
npm ci                      # no new dependencies in Phase 2A
npm run typecheck
npm test                    # includes the isolation suite (P2A-*)
npm run demo:isolated       # three processes, prints JSON; exit 2 = BLOCKED
```

One-time operator setup (bootstrap; §3a):

```bash
node src/isolation/trust-cli.ts seal "$PWD"         # prints digest + changes vs the approved artifact
node src/isolation/trust-cli.ts approve <digest> "reviewed <what>"
node src/isolation/trust-cli.ts verify
```

Operator code obtains the launcher only through `loadVerifiedLauncher()`
(`src/isolation/trusted-entry.ts`). `npm run demo:isolated` does this; it
reports BLOCKED (exit 2) if no artifact is approved. The steps are:

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

Trusted code lives at `<store>/artifacts/<digest>/` (§3a). Runtime layout
under `<root>`:

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
| A1 | Gateway and executor share the operator uid, and the gateway process holds the PDP authorization signing key. Creating separate accounts needs approval (not given). | **A compromised gateway is not contained.** It can read the mock wallet key and pay directly through the adapter, bypassing the executor and its journal (reproduced in review: ledger +1, no journal record). It can also sign valid authorizations for any payment, so the executor's own signature check (P2A-13) does **not** constrain a gateway that controls the key, even if the OS identities were separated. P2A-13 only shows that a holder of the *token alone* cannot pay. Fixing this needs the PDP and its key in a separate process and identity, and the executor (and buy) under their own identity. |
| A2 | The operator identity (`codespace`) has passwordless sudo. | Gateway and executor are root-equivalent. Compromising either compromises the host. Production needs non-sudo service accounts. |
| A3 | The agent uses the shared system account `nobody`. | Any other process running as `nobody` has the same access: the public socket only. Production needs a dedicated agent uid. |
| A4 | The development checkout is world-writable in this Codespace (ACL: dirs 0777, files 0666). | Resolved for launches in Phase 2A-R: trusted code comes only from the verified, approved artifact (§3a, SI-01..07). Residual: bootstrap trust, and code the operator runs from the checkout (tests, npm scripts) runs as the operator. |
| A5 | No peer-credential check on the sockets. | Any process with the operator uid can connect to the executor. It still needs the token and a valid authorization. |
| A6 | One container, one kernel. | Root inside the container bypasses every control. This is not VM or container isolation. |
| A7 | `/proc/<pid>/cmdline` is world-readable (no `hidepid`). | The agent sees the process list and config paths, but no secrets (P2A-12 checks argv). |
| A8 | The PDP policy state (budget, velocity) and the gateway replay store are in memory. | **Budget is not enforced across gateway restarts.** Reproduced: budget 20,000, price 10,000: ALLOW, ALLOW, DENY; restart; ALLOW, ALLOW, DENY. 40,000 was spent. The executor journal prevents only a second payment of the *same* intent, not new intents. |
| A9 | The journal lives on the Codespace's local disk (`/tmp`, ext4, fsync'd). | It survives process crashes and restarts (tested). It does not survive loss or rebuild of the Codespace. |
| A10 | A gateway timeout or connection failure is always INDETERMINATE, even when nothing reached the executor. | Conservative. The journal tells the operator whether `pay` started. |
| A11 | A stale lock is recovered when its pid is not alive. pid reuse can make a dead holder look alive. | The executor then refuses to start. This fails closed; the operator removes the lock. |
| A12 | `/v1/quote` forwards agent input to the executor (read-only). | Indirect executor attack surface. Validated by the adapter lookup. |
| A13 | No rate limiting on the public socket. | The agent can exhaust the gateway (DoS). |

## 5. Durable payment journal

Implementation: `openFilePaymentJournal` in
`src/executor/payment-journal.ts`. The executor process holds the only writer.

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
- **Locking:** a single writer, via `executor.lock` created O_EXCL. A
  second executor fails with `JOURNAL_LOCKED` (P2A-14, J3). A lock whose pid
  is dead is taken over and logged as `STALE_LOCK_RECOVERED` (J3, P2A-08).
- **No automatic retry and no automatic resolution.** At open, STARTED and
  UNKNOWN records without a resolution are listed: in `journal.log`
  (`needs_reconciliation`) and on the executor's stdout. Their state is
  never changed (J4, P2A-09).

## 6. Recovery and reconciliation procedure

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

All of this runs as the operator identity. The agent identity cannot read
the journal (P2A-11).

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

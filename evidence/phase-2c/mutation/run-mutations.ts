// SPDX-License-Identifier: MIT
/**
 * Phase 2C mutation checks. Each mutant disables one protection in a disposable
 * copy of the working tree (never the repository) and runs the tests that are
 * expected to detect it. A mutant is KILLED when those tests fail.
 *
 *   node evidence/phase-2c/mutation/run-mutations.ts [M01 M02 ...]   (from the repository root)
 *
 * Writes <id>.log and results.json next to this file. Mock only; the
 * process-level tests use disposable state roots, as in the normal suite.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../../..");

type Edit = { file: string; find: string; replace: string };
type Mutant = { id: string; protects: string; edits: Edit[]; tests: string[]; pattern: string };

const M: Mutant[] = [
  {
    id: "M01",
    protects: "CX3 anchor: strict PREPARE version progression in parseAnchor",
    edits: [{ file: "src/authorization/policy-anchor.ts", find: "} else if (e.version !== head.version + 1) {", replace: "} else if (false) {" }],
    tests: ["tests/authorization/policy-anchor.test.ts"],
    pattern: "^AN",
  },
  {
    id: "M02",
    protects: "CX1 / N3: a state one commit older than the anchor head is a rollback (reintroduces the original CX1 acceptance)",
    edits: [{
      file: "src/authorization/policy-anchor.ts",
      find: "  if (head !== undefined && file.version < head.version) {",
      replace: "  if (head !== undefined && file.version === head.version - 1) return { action: \"ACCEPT\" };\n  if (head !== undefined && file.version < head.version) {",
    }],
    tests: ["tests/authorization/policy-anchor.test.ts", "tests/isolation/financial-integrity.test.ts"],
    pattern: "^(AN2|CX1a)",
  },
  {
    id: "M03",
    protects: "F3: an UNCERTAIN outcome is held, never released automatically",
    edits: [{
      file: "src/authorization/reservations.ts",
      find: "      if (f.outcome === \"NOT_EXECUTED\") return \"RELEASED\";\n      if (f.outcome === \"UNCERTAIN\") return \"UNCERTAIN\";",
      replace: "      if (f.outcome === \"NOT_EXECUTED\") return \"RELEASED\";\n      if (f.outcome === \"UNCERTAIN\") return \"RELEASED\";",
    }],
    tests: ["tests/authorization/reservations.test.ts", "tests/isolation/financial-integrity.test.ts"],
    pattern: "^(RS|FI-04)",
  },
  {
    id: "M04",
    protects: "F3: a STARTED payment not in flight is UNCERTAIN, never NOT_EXECUTED",
    edits: [{
      file: "src/executor/outcome-report.ts",
      find: "return inFlight ? { outcome: \"EXECUTING\" } : { outcome: \"UNCERTAIN\" };",
      replace: "return inFlight ? { outcome: \"EXECUTING\" } : { outcome: \"NOT_EXECUTED\", reason: \"NOT_STARTED\" };",
    }],
    tests: ["tests/executor/outcome-report.test.ts", "tests/isolation/financial-integrity.test.ts"],
    pattern: "^(OR|FI-04)",
  },
  {
    id: "M05",
    protects: "CX2: only the reservation's own execution domain may cancel or release it (reintroduces CX2)",
    edits: [
      { file: "src/authorization/authorization-service.ts", find: " && sameDomain(r.domain, options.executionDomain))", replace: ")" },
      { file: "src/authorization/authorization-service.ts", find: "if (!sameDomain(rec.domain, options.executionDomain)) return", replace: "if (false) return" },
    ],
    tests: ["tests/executor/outcome-report.test.ts", "tests/isolation/financial-integrity.test.ts"],
    pattern: "^(OR5|CX2a|CX2b)",
  },
  {
    id: "M06",
    protects: "CX2: reports from a journal that is not the current execution domain are refused",
    edits: [{ file: "src/authorization/authorization-service.ts", find: "if (!sameDomain(reporting, options.executionDomain)) return", replace: "if (false) return" }],
    tests: ["tests/executor/outcome-report.test.ts", "tests/isolation/financial-integrity.test.ts"],
    pattern: "^(OR5|CX2d)",
  },
  {
    id: "M07",
    protects: "B6 / N1: a failed flock is not ownership (an open descriptor is not a lock)",
    edits: [{ file: "src/durable/exclusive-lock.ts", find: "  if (status !== 0) {\n    closeSync(fd);", replace: "  if (false) {\n    closeSync(fd);" }],
    tests: ["tests/executor/payment-journal.test.ts", "tests/isolation/policy-state.test.ts", "tests/isolation/financial-integrity.test.ts"],
    pattern: "^(J3|R3-F4a|R3-F4b|FI-12)",
  },
  {
    id: "M08",
    protects: "N2: a consumed auth_id is refused forever in the journal (AUTH_REPLAY)",
    edits: [{ file: "src/executor/payment-journal.ts", find: "if (isEexist(err)) return { ok: false, reason: \"AUTH_REPLAY\" };", replace: "if (!isEexist(err)) throw err;" }],
    tests: ["tests/executor/payment-journal.test.ts"],
    pattern: "^J",
  },
  {
    id: "M09",
    protects: "N2: an unreadable journal record is UNKNOWN, never absent",
    edits: [{
      file: "src/executor/payment-journal.ts",
      find: "    if (isCode(err, \"ENOENT\")) throw err;\n    const hash = path.slice(-64);",
      replace: "    throw Object.assign(new Error(\"absent\"), { code: \"ENOENT\" });\n    const hash = path.slice(-64);",
    }],
    tests: ["tests/executor/payment-journal.test.ts", "tests/isolation/financial-integrity.test.ts"],
    pattern: "^(J7|FI-09)",
  },
  {
    id: "M10",
    protects: "N3: the auth service refuses to start (or load) on a REFUSE from the anchor reconciliation",
    edits: [{ file: "src/authorization/policy-state-file.ts", find: "  if (r.action === \"REFUSE\") throw new Error(r.reason);", replace: "  if (false) throw new Error(r.reason);" }],
    tests: ["tests/isolation/financial-integrity.test.ts"],
    pattern: "^CX1a",
  },
  {
    id: "M11",
    protects: "F5: unsafe identity configurations are rejected",
    edits: [{
      file: "src/isolation/identity.ts",
      find: "export function validateIdentities(ids: Partial<Record<Role, IdentityFacts>>, operator: { uid: number; gid: number }): string | null {",
      replace: "export function validateIdentities(ids: Partial<Record<Role, IdentityFacts>>, operator: { uid: number; gid: number }): string | null {\n  if (ids) return null;",
    }],
    tests: ["tests/isolation/identity-validation.test.ts"],
    pattern: "^ID",
  },
  {
    id: "M12",
    protects: "F3 / R-F1: the executor refuses a live quote above the authorized maximum before signing",
    edits: [{ file: "src/executor/executor.ts", find: "      if (BigInt(quote.amount) > BigInt(request.max_amount)) throw new Error(\"EXECUTOR_QUOTE_EXCEEDS_AUTHORIZED_MAX\");\n", replace: "" }],
    tests: ["tests/security/payment-binding.test.ts", "tests/isolation/financial-integrity.test.ts"],
    pattern: "^(T3c|R-F1a|FI-02)",
  },
  {
    id: "M13",
    // Run 1 flipped `requireSignatureVerification` to false: an equivalent mutant, because
    // `mode: "strict"` makes the signature check mandatory in @oxdeai/core
    // (verifyAuthorization.js: requireSig = mode === "strict" || ...). It survived for that reason.
    protects: "Phase 2B: the executor verifies the signed authorization itself (verdict ignored)",
    edits: [{ file: "src/executor/executor.ts", find: "      if (verdict.status !== \"ok\") {", replace: "      if (false) {" }],
    tests: ["tests/isolation/process-isolation.test.ts", "tests/executor/execution-domain.test.ts"],
    pattern: "^(P2A-04|P2A-05|P2A-13|CX2e)",
  },
];

function copyTree(): string {
  const dir = mkdtempSync(join(tmpdir(), "oxdeai-mutant-"));
  const r = spawnSync("rsync", ["-a", "--exclude=.git", "--exclude=evidence", "--exclude=.agents", "--exclude=.claude", `${REPO}/`, `${dir}/`]);
  if (r.status !== 0) throw new Error(`rsync failed: ${r.stderr}`);
  return dir;
}

function runTests(dir: string, m: Pick<Mutant, "tests" | "pattern">) {
  const r = spawnSync(process.execPath, ["--test", "--test-reporter=tap", `--test-name-pattern=${m.pattern}`, ...m.tests], { cwd: dir, encoding: "utf8", timeout: 900_000, maxBuffer: 64 << 20 });
  const out = `${r.stdout}${r.stderr}`;
  const count = (k: string) => Number(out.match(new RegExp(`^# ${k} (\\d+)`, "m"))?.[1] ?? NaN);
  const failing = [...out.matchAll(/^not ok \d+ - (.*)$/gm)].map((x) => x[1]!);
  // A run killed by the timeout (e.g. a mutant that leaves a child hanging) has no summary: count the TAP lines.
  const timedOut = r.status === null || r.signal !== null || (r.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT";
  const ran = (out.match(/^(?:not )?ok \d+ - /gm) ?? []).length;
  return { status: r.status, timedOut, out, tests: timedOut ? ran : count("tests"), pass: count("pass"), fail: timedOut ? failing.length : count("fail"), failing };
}

const only = new Set(process.argv.slice(2));
const selected = M.filter((m) => only.size === 0 || only.has(m.id));
const results: unknown[] = [];

// Baseline: the unmutated copy must pass every selected test set.
{
  const dir = copyTree();
  try {
    const all = { tests: [...new Set(selected.flatMap((m) => m.tests))], pattern: selected.map((m) => `(?:${m.pattern})`).join("|") };
    const r = runTests(dir, all);
    writeFileSync(join(HERE, "baseline.log"), r.out);
    results.push({ id: "BASELINE", status: r.status, tests: r.tests, pass: r.pass, fail: r.fail, verdict: r.status === 0 && r.tests > 0 ? "PASS" : "FAIL" });
    if (r.status !== 0 || !(r.tests > 0)) {
      writeFileSync(join(HERE, "results.json"), `${JSON.stringify(results, null, 2)}\n`);
      throw new Error("baseline copy does not pass; mutation results would be meaningless");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

for (const m of selected) {
  const dir = copyTree();
  try {
    for (const e of m.edits) {
      const p = join(dir, e.file);
      const src = readFileSync(p, "utf8");
      const n = src.split(e.find).length - 1;
      if (n !== 1) throw new Error(`${m.id}: expected exactly one match in ${e.file}, found ${n}`);
      writeFileSync(p, src.replace(e.find, e.replace));
    }
    const r = runTests(dir, m);
    writeFileSync(join(HERE, `${m.id}.log`), r.out);
    // KILLED: at least one selected test failed (also when the run was cut off by the timeout).
    const verdict = r.failing.length > 0 ? "KILLED" : "SURVIVED";
    results.push({ id: m.id, protects: m.protects, files: [...new Set(m.edits.map((e) => e.file))], tests: m.tests, pattern: m.pattern, ran: r.tests, fail: r.fail, failing: r.failing, timed_out: r.timedOut, verdict });
    process.stdout.write(`${m.id} ${verdict} (${r.fail}/${r.tests} failed)\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
writeFileSync(join(HERE, "results.json"), `${JSON.stringify(results, null, 2)}\n`);

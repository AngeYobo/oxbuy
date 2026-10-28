// SPDX-License-Identifier: MIT
/**
 * Settle-channel probe for the Phase 2C tests (mock only).
 *
 * Simulates a compromised or misbehaving executor talking to the auth
 * service's settle socket, to show what the auth service accepts. Run as the
 * executor identity (the only one that can read the executor config or reach
 * the socket), or as another identity to show that it cannot.
 *
 * It reads only `settleSocketPath`, `proofDir`, and `reportKey` from the
 * executor config. It imports no payment adapter, never reads the mock wallet
 * key or ledger, and opens no network connection: its only I/O is the local
 * Unix socket and the proof directory. Reports are synthetic (built from the
 * JSON given on the command line).
 *
 *   node settle-probe.ts <executorConfig> <mode> <reportJson>
 *     valid      signed with the executor's report key, with a valid peer proof
 *     wrong-key  signed with a fresh key, with a valid peer proof
 *     no-proof   validly signed, proof file name that does not exist
 *     bad-proof  validly signed, proof file whose content is not this request's hash
 *
 * Prints one JSON line: {status, body} or {error}.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { signReport, type OutcomeReport } from "../../src/executor/outcome-report.ts";
import { postJson } from "../../src/isolation/ipc.ts";
import { settlePost } from "../../src/isolation/settle-channel.ts";

const [configPath, mode, reportJson] = process.argv.slice(2);
let out: unknown;
try {
  const { settleSocketPath, proofDir, reportKey } = JSON.parse(readFileSync(configPath!, "utf8")) as {
    settleSocketPath: string;
    proofDir: string;
    reportKey: { privateKeyPem: string; kid: string };
  };
  const report = { executor_kid: reportKey.kid, ...(JSON.parse(reportJson!) as Partial<OutcomeReport>) } as OutcomeReport;
  const otherKey = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const signed = signReport(report, mode === "wrong-key" ? otherKey : reportKey.privateKeyPem);
  if (mode === "valid" || mode === "wrong-key") {
    out = await settlePost(settleSocketPath, proofDir, "/v1/settle", { report: signed });
  } else if (mode === "no-proof") {
    out = await postJson(settleSocketPath, "/v1/settle", { body: { report: signed }, proof: randomBytes(16).toString("hex") });
  } else if (mode === "bad-proof") {
    const name = randomBytes(16).toString("hex");
    writeFileSync(join(proofDir, name), "0".repeat(64), { mode: 0o640 });
    try {
      out = await postJson(settleSocketPath, "/v1/settle", { body: { report: signed }, proof: name });
    } finally {
      unlinkSync(join(proofDir, name));
    }
  } else {
    throw new Error(`unknown mode ${mode}`);
  }
} catch (err) {
  out = { error: (err as NodeJS.ErrnoException).code ?? (err as Error).message };
}
process.stdout.write(`${JSON.stringify(out)}\n`);

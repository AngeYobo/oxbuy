// SPDX-License-Identifier: MIT
/**
 * Operator tool for the trust store (see src/isolation/artifact.ts).
 *
 *   node trust-cli.ts seal <sourceRoot>     seal src/ + verified deps; prints digest and diff
 *   node trust-cli.ts approve <digest> [note]
 *   node trust-cli.ts verify                full pre-launch verification of the approved artifact
 *   node trust-cli.ts status
 *
 * Store: $OXDEAI_TRUST_STORE or ~/.oxdeai-celo-poc/trust.
 *
 * Bootstrap: the first seal and approval necessarily run this file from the
 * checkout, which must be trusted at that moment (operator review). After
 * that, run it from the approved artifact:
 *   node <store>/artifacts/<approved>/src/isolation/trust-cli.ts ...
 */
import { join } from "node:path";
import { approveArtifact, approvedDigest, defaultTrustStore, sealArtifact, verifyArtifact } from "./artifact.ts";

const [command, ...args] = process.argv.slice(2);
const store = defaultTrustStore();
let out: unknown;

switch (command) {
  case "seal": {
    if (!args[0]) throw new Error("usage: trust-cli seal <sourceRoot>");
    out = sealArtifact({ sourceRoot: args[0], store });
    break;
  }
  case "approve": {
    if (!/^[0-9a-f]{64}$/.test(args[0] ?? "")) throw new Error("usage: trust-cli approve <digest> [note]");
    approveArtifact(args[0]!, { store, note: args.slice(1).join(" ") });
    out = { approved: args[0] };
    break;
  }
  case "verify": {
    const digest = approvedDigest(store);
    if (digest === null) throw new Error("no approved artifact");
    const v = verifyArtifact(join(store, "artifacts", digest));
    out = { verified: v.digest, dependencies: v.manifest.dependencies, files: v.manifest.files.length };
    break;
  }
  case "status":
    out = { store, approved: approvedDigest(store) };
    break;
  default:
    throw new Error("usage: trust-cli seal|approve|verify|status");
}
process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

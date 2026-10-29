// CX3 (found by tests/authorization/policy-anchor.test.ts AN4): the anchor parser accepts an
// open PREPARE whose version is BELOW the latest completed DONE, and reconcile() then accepts
// that older state as a crash to complete. Pure functions only; no processes, no state written.
import { nextEntry, parseAnchor, reconcile, sha256, type AnchorLog } from "../../../src/authorization/policy-anchor.ts";
let text = ""; let log: AnchorLog | undefined;
const add = (b: any) => { text += nextEntry(log, b).text; log = parseAnchor(text); };
const S = (v: number, tag = "") => ({ version: v, state_sha256: sha256(`state-${v}${tag}`) });
add({ kind: "PREPARE", op: "INIT", ...S(0), spent: { a: "0" } }); add({ kind: "DONE", ...S(0) });
for (const v of [1, 2, 3]) { add({ kind: "PREPARE", op: "COMMIT", ...S(v), spent: { a: String(v * 10000) } }); add({ kind: "DONE", ...S(v) }); }
// An appender writes PREPARE for version 2 (an older state, less spent) after DONE 3.
add({ kind: "PREPARE", op: "COMMIT", ...S(2, "-older"), spent: { a: "10000" } });
console.log(JSON.stringify({ head_version: log!.head!.version, pending_version: log!.pending?.version, parse: "accepted",
  reconcile_older_state: reconcile(log!, S(2, "-older")) }));

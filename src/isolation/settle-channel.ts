// SPDX-License-Identifier: MIT
/**
 * Executor -> authorization service settle channel (Phase 2C; F3).
 *
 * Endpoint authorization is enforced by the OS, before any signature is
 * looked at:
 *   1. Socket: `<root>/settle-ipc/settle.sock` (0660) in a setgid directory
 *      auth:executor 2750. Only processes in the executor's group (and root)
 *      can reach it. The gateway and the agent cannot connect at all.
 *   2. Peer identity proof, per request: Node.js exposes no SO_PEERCRED, so
 *      the caller proves its uid through the kernel instead. Before each
 *      request the executor creates `<root>/settle-proof/<random>` containing
 *      sha256(canonical request body). The directory is executor:auth 2750:
 *      only the executor identity (or root) can create files in it, and the
 *      kernel records the creator as the file's owner. The auth service
 *      refuses the request unless that file exists, is a regular file with one
 *      link, is owned by the executor uid, and contains the hash of exactly
 *      this request. The proof is removed by the executor after the call.
 *   3. The report itself must carry a valid executor signature
 *      (src/executor/outcome-report.ts), and the transition must be allowed
 *      by the reservation state machine.
 */
import { randomBytes, createHash } from "node:crypto";
import { closeSync, fchmodSync, fsyncSync, lstatSync, openSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "../executor/outcome-report.ts";
import { postJson } from "./ipc.ts";

const PROOF_NAME = /^[0-9a-f]{32}$/;
const bodyHash = (body: unknown) => createHash("sha256").update(canonicalJson(body)).digest("hex");

/** Server side: throws PEER_PROOF_INVALID:* unless the kernel attests the executor created this request's proof. */
export function verifyPeerProof(proofDir: string, executorUid: number, proof: unknown, body: unknown): void {
  if (typeof proof !== "string" || !PROOF_NAME.test(proof)) throw new Error("PEER_PROOF_INVALID:name");
  const dir = lstatSync(proofDir);
  if (!dir.isDirectory() || dir.uid !== executorUid || (dir.mode & 0o022) !== 0) throw new Error("PEER_PROOF_INVALID:directory");
  const path = join(proofDir, proof);
  let st;
  try {
    st = lstatSync(path);
  } catch {
    throw new Error("PEER_PROOF_INVALID:missing");
  }
  if (!st.isFile() || st.nlink !== 1) throw new Error("PEER_PROOF_INVALID:not a regular file");
  if (st.uid !== executorUid) throw new Error(`PEER_PROOF_INVALID:owner uid ${st.uid}`);
  if (readFileSync(path, "utf8") !== bodyHash(body)) throw new Error("PEER_PROOF_INVALID:content");
}

/** Client side (executor): one request with a fresh proof file. */
export async function settlePost(socketPath: string, proofDir: string, route: string, body: unknown, timeoutMs = 10_000) {
  const name = randomBytes(16).toString("hex");
  const path = join(proofDir, name);
  const fd = openSync(path, "wx", 0o640);
  try {
    fchmodSync(fd, 0o640); // the auth service reads it through the directory's group
    writeSync(fd, bodyHash(body));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    return await postJson(socketPath, route, { body, proof: name }, {}, timeoutMs);
  } finally {
    try {
      unlinkSync(path);
    } catch {
      /* already gone */
    }
  }
}

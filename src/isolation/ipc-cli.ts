// SPDX-License-Identifier: MIT
/**
 * One IPC request from a given OS identity (operator tests run it as the
 * gateway identity to act as a compromised gateway).
 *
 *   echo '{"socket":..., "path":..., "body":..., "headers":{...}}' | node ipc-cli.ts
 *
 * Prints {"status", "body"} or {"error": <errno code>}.
 */
import { readFileSync } from "node:fs";
import { postJson } from "./ipc.ts";

const req = JSON.parse(readFileSync(0, "utf8")) as { socket: string; path: string; body: unknown; headers?: Record<string, string> };
let out: unknown;
try {
  out = await postJson(req.socket, req.path, req.body, req.headers ?? {});
} catch (err) {
  out = { error: (err as NodeJS.ErrnoException).code ?? (err as Error).message };
}
process.stdout.write(`${JSON.stringify(out)}\n`);

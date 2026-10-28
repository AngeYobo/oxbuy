// SPDX-License-Identifier: MIT
/**
 * JSON over HTTP on Unix-domain sockets.
 *
 * Access control is the filesystem: connecting requires search permission on
 * every directory of the socket path and write permission on the socket. The
 * server never opens a TCP port.
 */
import { chmodSync, existsSync, lstatSync, unlinkSync } from "node:fs";
import { createServer, request, type IncomingHttpHeaders, type Server } from "node:http";

export type JsonReply = { status: number; body: unknown };
export type JsonHandler = (body: unknown, headers: Record<string, string | string[] | undefined>) => Promise<JsonReply>;

const MAX_BODY_BYTES = 1 << 20;

function headersOf(h: IncomingHttpHeaders): Record<string, string | string[] | undefined> {
  return { ...h };
}

/** Listen on `socketPath` (replacing a stale socket) and chmod it to `mode`. */
export async function serveJson(socketPath: string, mode: number, routes: Record<string, JsonHandler>): Promise<Server> {
  if (existsSync(socketPath)) {
    if (!lstatSync(socketPath).isSocket()) throw new Error(`IPC_PATH_NOT_A_SOCKET:${socketPath}`);
    unlinkSync(socketPath);
  }
  const server = createServer(async (req, res) => {
    const send = (status: number, body: unknown) => {
      const data = JSON.stringify(body);
      res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(data) });
      res.end(data);
    };
    const handler = req.method === "POST" && req.url ? routes[req.url] : undefined;
    if (!handler) return send(404, { error: "NOT_FOUND" });
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > MAX_BODY_BYTES) return send(413, { error: "BODY_TOO_LARGE" });
      chunks.push(chunk as Buffer);
    }
    let body: unknown;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return send(400, { error: "INVALID_JSON" });
    }
    try {
      const reply = await handler(body, headersOf(req.headers));
      send(reply.status, reply.body);
    } catch (err) {
      send(500, { error: err instanceof Error ? err.message : String(err) });
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  chmodSync(socketPath, mode);
  return server;
}

/** POST JSON to `path` over the socket. Rejects on transport failure or timeout. */
export function postJson(
  socketPath: string,
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
  timeoutMs = 60_000,
): Promise<JsonReply> {
  const data = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = request(
      {
        socketPath,
        path,
        method: "POST",
        headers: { ...headers, "content-type": "application/json", "content-length": Buffer.byteLength(data) },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("error", reject);
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
          } catch (err) {
            reject(err);
          }
        });
      },
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("IPC_TIMEOUT"), { code: "IPC_TIMEOUT" })));
    req.on("error", reject);
    req.end(data);
  });
}

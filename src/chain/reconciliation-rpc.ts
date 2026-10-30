// SPDX-License-Identifier: MIT
import { lstatSync, readFileSync } from "node:fs";
import { RpcError } from "./rpc.ts";

/** Operator-owned policy, independent of the URL passed to resolve-x402. Never log URLs. */
export function approvedReconciliationRpc(url: string, policyPath: string | undefined): string {
  try {
    if (!policyPath) throw new Error();
    const st = lstatSync(policyPath);
    if (!st.isFile() || (st.mode & 0o077) !== 0 || st.uid !== process.getuid?.()) throw new Error();
    const policy = JSON.parse(readFileSync(policyPath, "utf8"));
    if (policy.network !== "eip155:11142220" || !Array.isArray(policy.endpoints)) throw new Error();
    const canonical = (s: string) => {
      const u = new URL(s);
      if (u.hash || u.username || u.password || !["http:", "https:"].includes(u.protocol)) throw new Error();
      if (u.protocol === "http:" && !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)) throw new Error();
      return u.href;
    };
    const selected = canonical(url);
    if (!policy.endpoints.some((x: unknown) => typeof x === "string" && canonical(x) === selected)) throw new Error();
    return selected;
  } catch {
    throw new RpcError("RPC_ENDPOINT_NOT_APPROVED");
  }
}

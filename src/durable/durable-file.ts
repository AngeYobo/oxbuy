// SPDX-License-Identifier: MIT
/**
 * Durable file primitives (Phase 2C). Every financial record written by the
 * authorization service and the executor goes through one of these.
 *
 *   replaceDurable   temp file (0600) -> write -> fsync -> rename over target -> fsync dir
 *   createDurable    temp file (0600) -> write -> fsync -> link(2) to target -> fsync dir -> unlink temp
 *                    link(2) fails with EEXIST if the target exists, so a record is published
 *                    exclusively AND only ever complete: a crash never leaves a partial record
 *                    under its final name, only an orphan temp file.
 *   appendDurable    open O_APPEND -> write one line -> fsync
 *
 * Crash-consistency assumptions: a local POSIX filesystem (ext4 in this
 * Codespace) where rename(2) and link(2) are atomic and fsync(2) on a file and
 * on its directory makes the data and the directory entry durable. Not valid
 * for NFS or filesystems that ignore fsync. Temp files are named `.tmp-*` and
 * are never read as records.
 */
import { randomBytes } from "node:crypto";
import { closeSync, fchmodSync, fsyncSync, linkSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";

export function fsyncDir(dir: string): void {
  const fd = openSync(dir, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Write `data` to a new 0600 temp file in `dir` and fsync it. Returns its path. */
export function writeTemp(dir: string, data: string | Buffer): string {
  const tmp = join(dir, `.tmp-${process.pid}-${randomBytes(6).toString("hex")}`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    // A default ACL on the directory would override the open() mode.
    fchmodSync(fd, 0o600);
    if (typeof data === "string") writeSync(fd, data);
    else writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  return tmp;
}

export function replaceDurable(path: string, data: string | Buffer): void {
  const dir = dirname(path);
  const tmp = writeTemp(dir, data);
  try {
    renameSync(tmp, path);
  } catch (err) {
    unlinkSync(tmp);
    throw err;
  }
  fsyncDir(dir);
}

/** Publish `path` exclusively and atomically. Throws an EEXIST error if it already exists. */
export function createDurable(path: string, data: string | Buffer): void {
  const dir = dirname(path);
  const tmp = writeTemp(dir, data);
  try {
    linkSync(tmp, path);
  } finally {
    unlinkSync(tmp);
  }
  fsyncDir(dir);
}

/** `chmod: false` for append-only (`chattr +a`) files, whose mode the kernel refuses to change. */
export function appendDurable(path: string, line: string, opts: { chmod?: boolean } = {}): void {
  const fd = openSync(path, "a", 0o600);
  try {
    if (opts.chmod !== false) fchmodSync(fd, 0o600);
    writeSync(fd, line.endsWith("\n") ? line : `${line}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function isEexist(err: unknown): boolean {
  return (err as NodeJS.ErrnoException | undefined)?.code === "EEXIST";
}

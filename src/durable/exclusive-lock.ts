// SPDX-License-Identifier: MIT
/**
 * Exclusive single-writer lock owned by this process (Phase 2C; fixes N1, B6).
 *
 * The lock is a kernel flock(2) on an open file description (OFD) that this
 * process opened itself. Node.js has no flock binding, so the lock is taken
 * by running flock(1) on that descriptor (passed as the child's fd 3): the
 * child and this process share the same OFD, and flock(2) locks belong to the
 * OFD, so the lock stays held by this process after the child exits. The
 * kernel releases it when this process closes the descriptor or exits, for
 * any reason (crash, SIGKILL). There is no stale lock file to detect or
 * delete, and the lock file is never unlinked (unlinking would let a later
 * opener lock a different inode).
 *
 * Ownership is real, not inferred: a process that merely has the lock file
 * open (another OFD) gets a conflict on its own `flock -n`, and
 * `assertOwned` re-checks by locking the held OFD again, which succeeds only
 * if this OFD is the holder or nobody holds the lock.
 *
 * Assumptions: a local filesystem with working flock(2) (not NFS), and
 * /usr/bin/flock (util-linux) as a trusted root-owned binary.
 */
import { spawnSync } from "node:child_process";
import { closeSync, constants, openSync } from "node:fs";

const FLOCK = "/usr/bin/flock";
const CONFLICT = 75;

export class LockError extends Error {
  /** LOCK_HELD: another holder; LOCK_UNAVAILABLE: the lock could not be opened or taken. */
  readonly code: "LOCK_HELD" | "LOCK_UNAVAILABLE";
  constructor(code: "LOCK_HELD" | "LOCK_UNAVAILABLE", detail: string) {
    super(`${code}:${detail}`);
    this.code = code;
    this.name = "LockError";
  }
}

export type ExclusiveLock = {
  readonly path: string;
  /** Throws unless this process's descriptor still holds the lock. */
  assertOwned(): void;
  release(): void;
};

function flockOn(fd: number): number | null {
  const r = spawnSync(FLOCK, ["--nonblock", "--conflict-exit-code", String(CONFLICT), "3"], {
    stdio: ["ignore", "ignore", "ignore", fd],
    timeout: 10_000,
  });
  return r.status;
}

/** Take the lock on `path` (created 0600 if missing) or throw LockError. Never waits. */
export function acquireExclusiveLock(path: string, opts: { create?: boolean } = {}): ExclusiveLock {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (opts.create === false ? 0 : constants.O_CREAT), 0o600);
  } catch (err) {
    throw new LockError("LOCK_UNAVAILABLE", `${path}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`);
  }
  const status = flockOn(fd);
  if (status !== 0) {
    closeSync(fd);
    throw status === CONFLICT ? new LockError("LOCK_HELD", path) : new LockError("LOCK_UNAVAILABLE", `${path}: flock status ${status}`);
  }
  let released = false;
  return {
    path,
    assertOwned() {
      if (released) throw new LockError("LOCK_UNAVAILABLE", `${path}: released`);
      // Re-locking our own OFD is a no-op if we hold it; it conflicts if another OFD does.
      const s = flockOn(fd);
      if (s !== 0) throw new LockError(s === CONFLICT ? "LOCK_HELD" : "LOCK_UNAVAILABLE", `${path}: not owned (status ${s})`);
    },
    release() {
      if (released) return;
      released = true;
      closeSync(fd);
    },
  };
}

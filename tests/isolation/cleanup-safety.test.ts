// SPDX-License-Identifier: MIT
/**
 * CS1-CS4 (Phase 2D, after the 2026-10-28 /tmp incident,
 * evidence/phase-2d/INCIDENT-TMP.md): recursive test cleanup is refused for
 * anything that is not a test-owned temporary directory.
 *
 * Written so that a broken guard still cannot delete anything outside this
 * test's own decoys: dangerous targets are only ever passed to the pure
 * check (`assertDisposableTestDir`), never to a removing call; the removing
 * calls get decoy paths whose worst-case effect is confined to a decoy
 * directory this test created.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { assertDisposableTestDir, REPO_ROOT, removeStateRoot, removeTestDir } from "./trusted-artifact.ts";

const TMP = realpathSync(tmpdir());
const rand6 = () => randomBytes(6).toString("base64url").replace(/[^A-Za-z0-9]/g, "a").slice(0, 6);

test("CS1 forbidden targets are refused by the guard: /, the temp root, /workspaces, the repository and its ancestors, other tools' temp entries", () => {
  const targets = ["/", TMP, `${TMP}/`, "/workspaces", REPO_ROOT, dirname(REPO_ROOT), "/home", `${TMP}/claude-1000`, `${TMP}/cc-socks`, `${TMP}/vscode-typescript1000`, "relative/oxdeai-x-abcdef", ""];
  for (const t of targets) assert.throws(() => assertDisposableTestDir(t), /UNSAFE_CLEANUP_TARGET/, JSON.stringify(t));
});

test("CS2 escapes are refused: .., a nested path, a non-mkdtemp name, and a symlink named like a test directory", () => {
  const owned = mkdtempSync(join(tmpdir(), "oxdeai-cs-"));
  assert.equal(assertDisposableTestDir(owned), owned, "a real test-owned directory is accepted");
  for (const t of [`${owned}/..`, `${owned}/../oxdeai-cs-abcdef`, join(owned, "sub"), `${TMP}/oxdeai-`, `${TMP}/oxdeai-abc`, `${TMP}//oxdeai-cs-abcdef`]) {
    assert.throws(() => assertDisposableTestDir(t), /UNSAFE_CLEANUP_TARGET/, t);
  }
  // A symlink that looks like a test directory but points elsewhere (a decoy this test owns).
  const decoy = mkdtempSync(join(tmpdir(), "oxdeai-decoy-"));
  writeFileSync(join(decoy, "keep"), "x");
  const link = join(TMP, `oxdeai-link-${rand6()}`);
  symlinkSync(decoy, link);
  try {
    assert.throws(() => assertDisposableTestDir(link), /is a symlink/);
    assert.throws(() => removeTestDir(link), /UNSAFE_CLEANUP_TARGET/);
    assert.ok(existsSync(join(decoy, "keep")), "the symlink target is untouched");
  } finally {
    unlinkSync(link); // removes the link only
  }
  removeTestDir(decoy);
  removeTestDir(owned);
  assert.equal(existsSync(owned), false);
});

test("CS3 regression for the incident: removeStateRoot given a path whose parent is not a test-owned temp directory throws before removing anything", () => {
  // The incident pattern: the caller registered a directory instead of a path inside it, so the helper's
  // parent was the temp root. Reproduced one level down inside a decoy, so a broken guard could only hit the decoy.
  const decoy = mkdtempSync(join(tmpdir(), "oxdeai-decoy-"));
  mkdirSync(join(decoy, "sub"));
  writeFileSync(join(decoy, "sub", "keep"), "x");
  assert.throws(() => removeStateRoot(join(decoy, "sub", "x")), /UNSAFE_CLEANUP_TARGET/);
  assert.ok(existsSync(join(decoy, "sub", "keep")), "nothing was removed");
  // The incident's actual argument shape (parent = temp root) is refused by the same check, without calling the remover.
  assert.throws(() => assertDisposableTestDir(dirname(decoy)), /UNSAFE_CLEANUP_TARGET/);
  removeTestDir(decoy);
});

test("CS4 a correctly registered fixture root is removed, and only its own mkdtemp parent", () => {
  const parent = mkdtempSync(join(tmpdir(), "oxdeai-cs-root-"));
  const root = join(parent, "policy");
  mkdirSync(root);
  writeFileSync(join(root, "f"), "x");
  const sibling = mkdtempSync(join(tmpdir(), "oxdeai-cs-sibling-"));
  removeStateRoot(root);
  assert.equal(existsSync(parent), false);
  assert.equal(existsSync(sibling), true, "a sibling temp directory is untouched");
  assert.equal(existsSync(TMP), true);
  removeTestDir(sibling);
});

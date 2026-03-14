#!/usr/bin/env node
// scripts/repo-ownership-check.js
//
// Fast repository ownership check that detects root-owned files in user-owned repos.
// This prevents the "unable to unlink old file: Permission denied" error during git pull.
//
// POSIX semantics: file deletion requires write+execute on the PARENT DIRECTORY,
// not on the file itself. Root-owned directories block non-root users from
// creating/deleting files within them.
//
// Reference: https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory

"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..");
const SKIP_DIRS = new Set([".git", "vendor", "node_modules"]);
const CHECK_DIRS = ["test", "pkg", "cmd", "scripts", "assets", "internal"];

function getOwner(filePath) {
  try {
    const stat = fs.statSync(filePath);
    return { uid: stat.uid, gid: stat.gid };
  } catch {
    return null;
  }
}

function main() {
  const rootStat = getOwner(REPO_ROOT);
  if (!rootStat) {
    console.error(`Cannot stat repo root: ${REPO_ROOT}`);
    process.exit(1);
  }

  const expectedUid = rootStat.uid;
  let mismatched = 0;
  let scanned = 0;

  for (const dir of CHECK_DIRS) {
    const dirPath = path.join(REPO_ROOT, dir);
    if (!fs.existsSync(dirPath)) continue;

    const walk = (current) => {
      let entries;
      try {
        entries = fs.readdirSync(current, { withFileTypes: true });
      } catch {
        return; // Permission denied during readdir is itself an indicator
      }

      for (const entry of entries) {
        if (SKIP_DIRS.has(entry.name)) continue;

        const fullPath = path.join(current, entry.name);
        const stat = getOwner(fullPath);
        if (!stat) continue;

        scanned++;
        if (stat.uid !== expectedUid) {
          mismatched++;
          if (mismatched <= 5) {
            const rel = path.relative(REPO_ROOT, fullPath);
            console.error(`  ownership mismatch: ${rel} (uid=${stat.uid}, expected=${expectedUid})`);
          }
        }

        if (entry.isDirectory()) {
          walk(fullPath);
        }
      }
    };

    walk(dirPath);
  }

  if (mismatched > 0) {
    const whoami = process.env.USER || "$(whoami)";
    console.error(`\nOwnership check FAILED: ${mismatched} files/dirs have wrong owner (scanned ${scanned})`);
    console.error(`\nThis will cause 'git pull' to fail with "Permission denied".`);
    console.error(`\nFix with:`);
    console.error(`  sudo chown -R ${whoami}:${whoami} ${REPO_ROOT}`);
    console.error(`\nRoot cause: Running commands as root (sudo go test, sudo make, docker)`);
    console.error(`creates files owned by root in a user-owned repository.\n`);
    process.exit(1);
  }

  console.log(`Ownership check passed: ${scanned} files scanned, all owned by uid ${expectedUid}`);
}

main();

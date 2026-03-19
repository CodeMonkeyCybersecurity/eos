# Self-Update Follow-Up Issues

Date: 2026-03-19
Scope: `eos self update`

1. Issue: Preserve and replay conflicted local changes without leaving the working tree dirty
Description: Add an explicit recovery workflow for the case where a fast-forward update succeeds but re-applying stashed local edits conflicts with the new upstream files.
Why follow up: This iteration now prevents unsafe cross-branch and diverged updates, but overlapping local edits after a legitimate upstream change can still require manual conflict resolution.

2. Issue: Normalize working-tree ownership for sudo-driven self-update runs
Description: Extend sudo ownership normalization beyond `.git/` so root-owned tracked or generated files in `/opt/eos` do not accumulate and block later developer or CI writes.
Why follow up: The current hardening preserves `.git` ownership, but the broader source tree can still contain root-owned files from prior privileged operations.

3. Issue: Persist a durable self-update transaction report on disk
Description: Write the structured transaction summary to a stable JSON artifact under `/var/log/eos/` so operators can inspect the last outcome without reconstructing it from terminal scrollback.
Why follow up: Structured logs are stronger now, but postmortem review is still log-centric rather than artifact-centric.

4. Issue: Add a dry-run mode for branch/remote/stash assessment
Description: Implement `eos self update --dry-run` to report the checked-out branch, remote relation, credential readiness, stash necessity, and planned actions without mutating the repo or installed binary.
Why follow up: The new pull assessment is human-centric, and a dry-run mode would expose it proactively instead of only during execution.

5. Issue: Export self-update outcome counters and branch-relation metrics
Description: Publish metrics for `up_to_date`, `local_ahead`, `remote_ahead`, `diverged`, `failed`, and `rolled_back` outcomes so alerting can distinguish operator action from genuine updater failure.
Why follow up: CI already emits artifacts and alerts, but runtime observability still relies mostly on logs rather than metrics.

---

## Added 2026-03-19 (adversarial review round 2)

6. Issue: Add SIGTERM/SIGINT signal handler for graceful shutdown during self-update
Description: Install a signal handler in UpdateWithRollback that triggers rollback on SIGTERM/SIGINT. Currently, if the process is killed during binary installation, the flock is released (kernel closes FDs) but no rollback runs. The system could be left with a half-written binary.
Why follow up: The lock lifecycle fix (P0 #8) prevents concurrent update races, but doesn't protect against process termination mid-update. Signal handling is a separate concern that adds complexity (goroutine coordination, context cancellation) and should be designed carefully.
Root cause: Linux flock is released on process exit, but Go defers don't run on SIGKILL. Only SIGTERM/SIGINT can be caught. This is inherently imperfect but still valuable for the common `Ctrl+C` case.

7. Issue: Add submodule update step to self-update pull
Description: After `git pull --ff-only`, run `git submodule update --init --recursive` to ensure the `prompts/` submodule (and any future submodules) are at the correct commit. Currently, new commits that add/update submodule dependencies will fail the build with missing files.
Why follow up: The prompts submodule was added after the self-update system was designed. The pull step does not know about submodules, and adding it requires careful error handling (submodule auth, network failures, partial updates).

8. Issue: Decompose updater_enhanced.go (1680+ lines) into focused modules
Description: Split the monolith into focused files: updater_transaction.go (executeUpdateTransaction, shouldBuildBinary), updater_backup.go (createTransactionBackup), updater_rollback.go (rollbackUnlocked, rollback steps), updater_system.go (UpdateSystemPackages, UpdateGoVersion). This improves navigability and testability.
Why follow up: This is a refactoring task that doesn't fix bugs. The file works correctly; it's just too large for comfortable maintenance. Should be done in a dedicated PR with no functional changes to minimize review risk.

9. Issue: Replace curl-based Go version check with net/http + checksum verification
Description: `UpdateGoVersion()` uses `exec.Command("curl")` to download Go archives. This should use Go's `net/http` for portability (curl may not be installed) and MUST verify SHA256 checksums from `https://go.dev/dl/?mode=json` to prevent supply-chain attacks.
Why follow up: This is a supply-chain security gap. An attacker who can MITM the download (or compromise the CDN) could inject a malicious Go toolchain. The fix requires fetching the checksum file, verifying it (ideally against a pinned GPG key), and comparing before extraction.

10. Issue: Improve rollbackUnlocked test coverage from 29.3% to 80%+
Description: The rollback function has 29.3% test coverage. Key untested paths: binary restore from backup, git revert with stash, stash restoration after failed pull, partial rollback error reporting. These are the most critical recovery paths.
Why follow up: Testing rollback requires complex setup (fake binary, git repo with stash, simulated failures). The function works correctly based on code review, but untested rollback code is a risk.

*Last Updated: 2026-03-11*

# Self-Update Follow-Up Issues (2026-03-11)

## P2 - Important

### 1. Reduce disk space checks from 4 to 2

**Problem**: `updater_enhanced.go` runs disk space checks at 4 points (pre-flight, pre-build, pre-install, pre-Go-install). The pre-build and pre-install checks are redundant since the binary size is known by then.

**Root cause**: Defensive coding during initial implementation; no consolidation pass.

**Next step**: Keep pre-flight (catches obvious issues early) and pre-Go-install (different partition may apply). Remove pre-build and pre-install checks.

### 2. Ownership normalization runs twice on success

**Problem**: `normalizeOwnership()` is called both in the success path and in rollback cleanup. On a successful update, the success-path call is sufficient.

**Root cause**: Belt-and-suspenders approach; rollback path added normalization without checking if it was already done.

**Next step**: Gate the rollback normalization on `transaction.RolledBack == true` to avoid redundant work.

### 3. PullOptions named presets

**Problem**: `PullOptions` has 6+ fields, and callers construct them inline with magic combinations (e.g., self-update uses `{Autostash: true, Interactive: true, TrustPolicy: Strict}` while CI uses different settings).

**Root cause**: Organic growth of options without a preset layer.

**Next step**: Add `PullOptions.SelfUpdate()`, `PullOptions.CI()`, `PullOptions.Interactive()` constructors that encode tested defaults.

### 4. vaultInsecureAuditLogPath is a package-level var

**Problem**: `pkg/vault/phase2_env_setup.go` uses a package-level `var` for the audit log path, swapped in tests. This is a test-only seam that weakens production code encapsulation.

**Root cause**: Needed testability without refactoring to dependency injection.

**Next step**: Refactor to pass the audit path via a config struct or function parameter, removing the package-level var.

## P3 - Recommended

### 5. getLatestGoVersion shells out to curl

**Problem**: `updater_enhanced.go` uses `exec.Command("curl", ...)` to fetch the latest Go version from `go.dev`. This bypasses Go's `net/http` client, losing retry logic, timeout control, and proxy support.

**Root cause**: Quick implementation; curl was the fastest path to a working prototype.

**Next step**: Replace with `http.Client` call using the project's standard HTTP patterns (timeouts, retries, user-agent).

### 6. Go install is non-atomic (rm -rf then extract)

**Problem**: The Go toolchain install removes `/usr/local/go` then extracts the new tarball. A crash between rm and extract leaves the system without a Go compiler.

**Root cause**: Following the official Go install docs verbatim (`rm -rf /usr/local/go && tar -C /usr/local -xzf ...`).

**Next step**: Extract to a temp directory first, then `os.Rename` the old dir to `.bak`, rename new dir into place, and only remove `.bak` on success.

### 7. fetchRemoteBranch doesn't validate branch name

**Problem**: The branch name passed to `git fetch origin <branch>` is not validated against injection (e.g., `--upload-pack=...`).

**Root cause**: Branch name comes from internal code (not user input), so validation was deferred.

**Next step**: Add `validateBranchName()` that rejects names starting with `-` or containing shell metacharacters. Defense in depth.

### 8. First-class Vault --force-insecure CLI flag

**Problem**: `pkg/vault/phase2_env_setup.go` relies on env var `Eos_ALLOW_INSECURE_VAULT` for non-interactive insecure fallback rather than a first-class CLI flag.

**Root cause**: Env var was the minimal viable approach for CI/scripted usage.

**Next step**: Introduce `--force-insecure` flag at the command layer, thread through `RuntimeContext.Attributes`, require matching audit record before setting `VAULT_SKIP_VERIFY=1`.

### 9. PullRepository coverage gap

**Problem**: `PullRepository` is the main orchestrator function but only has integration tests that exercise it end-to-end. Individual decision branches (fetch-first skip, stash-not-needed, credential-fail-fast) lack isolated unit tests.

**Root cause**: Function is tightly coupled to real git operations, making unit testing harder.

**Next step**: Extract the decision logic into a pure function (`pullDecision(state) -> action`) that can be unit tested with table-driven tests, keeping the effectful code thin.

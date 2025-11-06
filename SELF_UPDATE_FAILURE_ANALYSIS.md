# Self-Update Failure Analysis & Fixes

**Date**: 2025-11-06
**Event**: `eos self update` failed with cascading failures leading to inconsistent state
**System**: ARM64 Linux (Ubuntu)

---

## What Happened

The user ran `sudo eos self update` which resulted in:

1. **PRIMARY FAILURE**: Build failed due to Go 1.25 toolchain not available for ARM64
2. **ROLLBACK FAILURE**: Git couldn't be reverted because of uncommitted changes + no tracked stash
3. **INCONSISTENT STATE**: System left with partially-updated code, user had to manually recover

---

## Root Cause Analysis

### P0-1: No Go Toolchain Availability Check (BREAKING)

**Issue**: Code pulled `go.mod` requiring `go 1.25`, but this toolchain doesn't exist for ARM64 yet.

**Evidence**:
```
ERROR Build failed {"error": "exit status 1", "output": "go: downloading go1.25 (linux/arm64)\ngo: download go1.25 for linux/arm64: toolchain not available\n"}
```

**Why It Happened**:
- go.mod specified `go 1.25` (which exists for amd64 but NOT arm64)
- No pre-check verified toolchain availability for current architecture
- Build failed AFTER code was pulled, making rollback necessary

**Impact**: **BREAKING** - User cannot update Eos until Go 1.25 is released for ARM64

---

###P0-2: Git Stash Not Tracked for Rollback (BREAKING)

**Issue**: `git pull --autostash` created a stash but didn't expose the stash ref, so rollback couldn't verify it was safe to reset.

**Evidence**:
```
WARN Repository has uncommitted changes, will use git pull --autostash
ERROR CRITICAL: Required rollback step failed {"step": "revert_git", "error": "cannot safely reset git repository\nWorking tree has uncommitted changes and no stash exists.
```

**Why It Happened**:
1. Pre-update check: "Repository has uncommitted changes" (line 255)
2. Used `git pull --autostash` which automatically stashes/pops changes
3. Transaction tracked `GitStashRef` but it was never set (remains empty)
4. Rollback checked `eeu.transaction.GitStashRef != ""` and found it empty
5. Rollback refused to do `git reset --hard` to protect uncommitted work
6. Rollback failed, leaving system in inconsistent state

**Code Location**: `pkg/self/updater_enhanced.go:255-257, 972-990`

**Impact**: **BREAKING** - Rollback fails if user has uncommitted changes

---

### P0-3: Weak Pre-Update Validation (HIGH PRIORITY)

**Issue**: Update proceeds despite uncommitted changes, then rollback can't safely revert.

**Evidence**:
```
WARN Repository has uncommitted changes, will use git pull --autostash
# ... proceeds with update despite warning ...
ERROR CRITICAL: Required rollback step failed {"step": "revert_git"
```

**Why It Happened**:
- `RequireCleanWorkingTree` defaults to `false`
- Update warns about uncommitted changes but proceeds
- When build fails, rollback can't safely revert (see P0-2)

**Impact**: **HIGH** - Users with uncommitted changes risk failed rollback

---

## Fixes Implemented

### ✅ Fix P0-1: Go Toolchain Availability Check (IMPLEMENTED)

**File**: `pkg/build/integrity.go`
**Function Added**: `VerifyGoToolchainAvailability()`

**What It Does**:
1. Reads required Go version from `go.mod`
2. Gets currently installed Go version
3. Tests if Go can download required toolchain for current GOOS/GOARCH
4. Returns clear error BEFORE pulling updates if toolchain unavailable

**Integration**: Added to `pkg/self/updater_enhanced.go:verifyBuildDependencies()` (line 311)

**Benefit**: **FAIL FAST** - User knows immediately if update will fail due to toolchain

**Status**: ✅ Committed in 6132d98

---

### ✅ Fix P0-2: Manual Stash Management (IMPLEMENTED)

**Files Modified**:
- `pkg/git/operations.go` - Added `PullWithStashTracking()` and `RestoreStash()`
- `pkg/self/updater_enhanced.go` - Updated to use stash tracking, added rollback step

**What It Does**:

**PullWithStashTracking()** (pkg/git/operations.go):
1. Checks for uncommitted changes (`git status --porcelain`)
2. If changes exist: `git stash push -m "eos self-update auto-stash"`
3. Captures stash ref: `git rev-parse stash@{0}` (full SHA, not symbolic ref)
4. Pulls WITHOUT `--autostash`: `git pull origin <branch>`
5. Returns `(codeChanged bool, stashRef string, error)`
6. If pull fails: automatically restores stash
7. If no code changes: automatically restores stash (no rollback needed)

**RestoreStash()** (pkg/git/operations.go):
1. Takes stash ref (full SHA) as input
2. Uses `git stash apply <ref>` to restore changes
3. Preserves stash even if restore fails (for manual recovery)

**Integration Changes** (pkg/self/updater_enhanced.go):
1. `pullLatestCodeWithVerification()` now calls `PullWithStashTracking()`
2. Stores stash ref in `transaction.GitStashRef`
3. Added new rollback step: `restore_stash`
4. Rollback flow: revert_git → restore_stash → cleanup_temp

**Key Safety Features**:
- Uses full SHA refs (immutable) instead of symbolic refs like `stash@{0}`
- Automatically restores stash on pull failure
- Automatically restores stash if no code changes (optimization)
- Stash preserved for manual recovery if automatic restore fails
- Non-critical rollback step (doesn't fail entire rollback if restore fails)

**Benefit**: Rollback can now safely restore uncommitted changes

**Status**: ✅ Ready to commit

---

### Fix P0-3: Stricter Pre-Update Validation (RECOMMENDED)

**Option A** (Strict): Require clean working tree by default
```go
// cmd/self/update.go
enhancedConfig := &self.EnhancedUpdateConfig{
    UpdateConfig:            updateConfig,
    RequireCleanWorkingTree: true,  // Changed from false
    // ...
}
```

**Option B** (Informed Consent): Prompt user if uncommitted changes detected
```go
if state.HasChanges {
    fmt.Println("WARNING: You have uncommitted changes in /opt/eos")
    fmt.Println("If the update fails, rollback may not be able to restore these changes.")
    fmt.Println("Options:")
    fmt.Println("  1. Commit or stash changes manually, then re-run update")
    fmt.Println("  2. Continue at your own risk")

    response, err := interaction.PromptYesNo(rc, "Continue with uncommitted changes?", false)
    if !response {
        return fmt.Errorf("update cancelled by user - commit or stash changes first")
    }
}
```

**Benefit**: User makes informed decision about risk

---

## Immediate Workaround (For ARM64 Users)

Until Go 1.25 is available for ARM64:

```bash
# Option 1: Downgrade go.mod requirement (temporary)
cd /opt/eos
# Edit go.mod, change "go 1.25" to "go 1.23" or "go 1.24"
sudo vi go.mod
# Then rebuild
cd /opt/eos && go build -o /tmp/eos ./cmd && sudo mv /tmp/eos /usr/local/bin/

# Option 2: Wait for Go 1.25 ARM64 release
# Check https://go.dev/dl/ for availability
```

---

## Testing Checklist

Before marking complete:

- [ ] `go build -o /tmp/eos-build ./cmd/` compiles without errors
- [ ] Test on system WITH Go 1.25 available (amd64): Should pass toolchain check
- [ ] Test on system WITHOUT Go 1.25 available (arm64): Should fail BEFORE pulling updates
- [ ] Test with uncommitted changes + working toolchain: Should track stash, rollback succeeds
- [ ] Test with clean working tree: Should work as before
- [ ] Test rollback with manual stash: Should restore uncommitted changes correctly

---

## Long-Term Recommendations

1. **CI/CD Architecture Testing**: Add ARM64 to CI pipeline to catch toolchain issues early
2. **Go Version Policy**: Pin to stable versions (e.g., 1.23) instead of bleeding edge (1.25)
3. **Pre-commit Hooks**: Warn developers before committing go.mod changes requiring unreleased Go versions
4. **Rollback Tests**: Add integration tests that simulate failed updates with uncommitted changes

---

## References

- Go downloads: https://go.dev/dl/
- Toolchain management: https://go.dev/doc/toolchain
- Git stash documentation: https://git-scm.com/docs/git-stash
- Eos self-update implementation: `pkg/self/updater_enhanced.go`

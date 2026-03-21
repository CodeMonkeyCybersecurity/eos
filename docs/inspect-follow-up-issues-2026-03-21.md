*Last Updated: 2026-03-21*

# pkg/inspect Follow-Up Issues

Issues discovered during adversarial review of `pkg/inspect/docker.go`.

## Issue 1: output.go / terraform_modular.go — 37 staticcheck warnings (P2)

**Problem**: `WriteString(fmt.Sprintf(...))` should be `fmt.Fprintf(...)` throughout output.go and terraform_modular.go.
**Impact**: Performance (unnecessary string allocation) and lint noise.
**Fix**: Replace all `tf.WriteString(fmt.Sprintf(...))` with `fmt.Fprintf(tf, ...)`.
**Files**: `pkg/inspect/output.go`, `pkg/inspect/terraform_modular.go`
**Effort**: ~30 min mechanical refactor

## Issue 2: services.go — unchecked filepath.Glob error (P2)

**Problem**: `pkg/inspect/services.go:381` ignores `filepath.Glob` error.
**Impact**: Silent failure when glob patterns are invalid.
**Fix**: Check and log the error.
**Effort**: 5 min

## Issue 3: kvm.go — goconst violations (P3)

**Problem**: String constants `"active"`, `"UUID"` repeated without named constants.
**Impact**: Violates P0 Rule #12 (no hardcoded values).
**Fix**: Extract to constants in `kvm.go` or a `constants.go` file.
**Effort**: 15 min

## Issue 4: Pre-existing lint issues across 30+ files on this branch (P1)

**Problem**: `npm run ci` fails due to 165 lint issues across the branch.
**Impact**: Cannot merge until resolved.
**Root cause**: Accumulated tech debt from many feature PRs merged without lint cleanup.
**Fix**: Dedicated lint cleanup pass before PR merge.
**Effort**: 2-4 hours

## Issue 5: Inspector lacks Docker SDK integration (P3)

**Problem**: All Docker operations use shell commands instead of the Docker SDK.
**Impact**: Fragile parsing, no type safety, extra process spawns.
**Fix**: Migrate to `github.com/docker/docker/client` SDK for container/image/network/volume operations.
**Rationale**: CLAUDE.md P1 states "ALWAYS use Docker SDK" for container operations.
**Effort**: 1-2 days

## Issue 6: Compose file search does not guard against TOCTOU (P3)

**Problem**: Between `os.Stat` size check and `os.ReadFile`, the file could be replaced.
**Impact**: Theoretical DoS via race condition on symlink swap.
**Fix**: Read file first, then check size of bytes read (simpler and race-free).
**Effort**: 15 min

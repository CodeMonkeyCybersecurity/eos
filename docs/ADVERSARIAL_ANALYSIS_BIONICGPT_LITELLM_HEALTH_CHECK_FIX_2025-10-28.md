# Adversarial Analysis: BionicGPT LiteLLM Health Check Fix

**Date**: 2025-10-28
**Analyst**: Claude (Sonnet 4.5)
**Scope**: BionicGPT LiteLLM health check failure root cause analysis and comprehensive remediation
**Status**: IN PROGRESS

---

## Executive Summary

**Root Cause Identified**: LiteLLM container health check failing because `curl` executable not found in `ghcr.io/berriai/litellm:main-latest` image.

**Impact**:
- bionicgpt-app container blocked from starting (stuck in "created" state)
- Port 8513 not listening (web interface inaccessible)
- False diagnosis of LiteLLM failure when service was actually running fine

**Fix Applied**:
1. ✅ **vhost2 Production**: docker-compose.yml updated (curl → Python urllib)
2. ✅ **Eos Template**: [pkg/bionicgpt/install.go:913](../pkg/bionicgpt/install.go#L913) updated
3. ✅ **App Dependency**: Changed from `service_healthy` → `service_started` for resilience
4. 🔄 **Diagnostics**: Updating `pkg/debug/bionicgpt/diagnostics.go` (IN PROGRESS)
5. ⏳ **Update Command**: `eos update bionicgpt --fix` (NOT YET IMPLEMENTED)

---

## Part 1: Root Cause Analysis (COMPLETED)

### 1.1 Symptom Discovery

**User Report** (vhost2):
```bash
$ sudo eos debug bionicgpt
ERROR Error checking secret {"secret": "postgres_password", "error": "...403..."}
ERROR Containers blocked by dependencies {"count": 1, "containers": ["bionicgpt-app"]}
WARN Unknown LiteLLM error type - check container logs
```

**Docker Status**:
```
bionicgpt-litellm    Up 15 hours (unhealthy)   # ← Health check failing
bionicgpt-app        Created                   # ← Blocked, never started
```

### 1.2 Diagnosis Process

**Step 1**: Examined diagnostic output
```
✗ /health endpoint failed
Full output (with HTTP code):
OCI runtime exec failed: exec failed: unable to start container process:
exec: "curl": executable file not found in $PATH: unknown
```

**Key Insight**: Error is NOT about LiteLLM being down. Error is about **curl not existing in container**.

**Step 2**: Examined docker-compose.yml on vhost2
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:4000/health"]
  interval: 60s
  timeout: 10s
  retries: 5
  start_period: 90s
```

**Step 3**: Verified LiteLLM was actually working
```
docker logs bionicgpt-litellm:
INFO:     Started server process [10]
INFO:     Application startup complete.
LiteLLM: Proxy initialized with Config, Set models:
    gpt-4
    gpt-3.5-turbo
    text-embedding-ada-002
```

**Conclusion**: LiteLLM is running FINE. Health check mechanism is broken, not LiteLLM itself.

### 1.3 Root Cause

**Problem**: `ghcr.io/berriai/litellm:main-latest` is a minimal Python container that does NOT include `curl`.

**Why This Wasn't Caught Earlier**:
- Docker Compose health checks fail silently in background
- No visibility into health check execution errors
- Dependency blocking (bionicgpt-app waits forever) was only visible symptom

**Cascading Failure**:
1. Health check tries to exec `curl` → fails (exec not found)
2. Docker marks litellm as "unhealthy"
3. bionicgpt-app depends on `litellm-proxy: service_healthy`
4. bionicgpt-app never starts (stuck in "created" state)
5. Port 8513 never opens (web interface inaccessible)

---

## Part 2: Fix Design & Implementation (COMPLETED)

### 2.1 Solution Architecture

**Primary Fix**: Use Python urllib (guaranteed to exist in Python container)
```yaml
test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:4000/health').read()"]
```

**Why This Works**:
- ✅ Python guaranteed in LiteLLM container (it's a Python app)
- ✅ Tests actual HTTP endpoint (not just port)
- ✅ No external dependencies
- ✅ Works identically to curl for health checking

**Secondary Fix**: Relax app dependency for resilience
```yaml
# Before (too strict):
depends_on:
  litellm-proxy:
    condition: service_healthy

# After (more resilient):
depends_on:
  litellm-proxy:
    condition: service_started  # App will retry connections
```

**Why Relax Dependency**:
- Prevents future health check issues from completely blocking startup
- App can start and retry LiteLLM connections
- Better separation of concerns (health checks for monitoring, not blocking)

### 2.2 Files Changed

#### 2.2.1 vhost2 Production (COMPLETED ✅)

**File**: `/opt/bionicgpt/docker-compose.yml` on vhost2

**Changes**:
1. Line 114-116: Health check curl → Python urllib
2. Line 160: Dependency `service_healthy` → `service_started`

**Verification**:
```bash
$ docker compose down && docker compose up -d
[+] Running 8/8
 ✔ Container bionicgpt-app              Started    # ← NOW STARTING!
 ✔ Container bionicgpt-litellm          Started (health: starting)

$ docker ps  # Wait 2-3 minutes
bionicgpt-litellm    Up 3 minutes (healthy)    # ← Health check passing!
bionicgpt-app        Up 3 minutes (healthy)     # ← App running!
```

**Result**: ✅ FIXED - All containers running, port 8513 accessible

#### 2.2.2 Eos Template (COMPLETED ✅)

**File**: [pkg/bionicgpt/install.go](../pkg/bionicgpt/install.go)

**Changes**:
- Line 913: Updated health check test to use Python urllib
- Line 914-917: Updated timing parameters (restored to original)
- Line 952-955: Updated app dependency to `service_started` with documentation

**Build Verification**:
```bash
$ go build -o /tmp/eos-build ./cmd/
# ✅ SUCCESS - no errors
```

**Impact**: Future `eos create bionicgpt` commands will generate correct docker-compose.yml

---

## Part 3: Diagnostics Update (IN PROGRESS 🔄)

### 3.1 Problem Identified

**File**: `pkg/debug/bionicgpt/diagnostics.go`

**Current Code** (BROKEN):
```go
// Line 1448-1449
healthCmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerLiteLLM,
    "curl", "-m", "5", "-w", "\\nHTTP_CODE:%{http_code}", "http://localhost:4000/health")

// Line 1486-1487
livelinessCmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerLiteLLM,
    "curl", "-m", "5", "-w", "\\nHTTP_CODE:%{http_code}", "http://localhost:4000/health/liveliness")
```

**Why This Fails**: Same root cause - `curl` not in container

**Current Error Output**:
```
✗ /health endpoint failed
Full output (with HTTP code):
OCI runtime exec failed: exec failed: unable to start container process: exec: "curl": executable file not found in $PATH: unknown
```

### 3.2 Proposed Fix

**Replace curl with Python urllib + sed for HTTP code extraction**:

```go
// Option 1: Python with custom HTTP code extraction
healthCmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerLiteLLM,
    "python", "-c",
    `import urllib.request, urllib.error
try:
    resp = urllib.request.urlopen('http://localhost:4000/health', timeout=5)
    print(resp.read().decode())
    print(f"HTTP_CODE:{resp.code}")
except urllib.error.HTTPError as e:
    print(f"HTTP_CODE:{e.code}")
    raise
except Exception as e:
    print(f"ERROR:{e}")
    raise`)

// Option 2: Simple check (no HTTP code) - SIMPLER, RECOMMENDED
healthCmd := exec.CommandContext(ctx, "docker", "exec", bionicgpt.ContainerLiteLLM,
    "python", "-c",
    "import urllib.request; print(urllib.request.urlopen('http://localhost:4000/health').read().decode())")
```

**Recommendation**: Use Option 2 (simpler). HTTP status code extraction is nice-to-have, not critical for diagnostics.

### 3.3 Files to Update

**Required**:
1. `pkg/debug/bionicgpt/diagnostics.go:1448-1449` - /health endpoint check
2. `pkg/debug/bionicgpt/diagnostics.go:1486-1487` - /health/liveliness endpoint check
3. `pkg/debug/bionicgpt/diagnostics.go:881` - Remediation message (remove curl example)
4. `pkg/debug/bionicgpt/auth_diagnostic.go:233` - Host-level curl (this one is OK - curl on host, not in container)

**Status**: Ready to implement (awaiting approval)

---

## Part 4: Update Command (NOT YET IMPLEMENTED ⏳)

### 4.1 Gap Identified

**Missing**: `eos update bionicgpt --fix` command

**Current State**:
- ✅ `eos create bionicgpt` - exists
- ✅ `eos delete bionicgpt` - exists
- ✅ `eos debug bionicgpt` - exists
- ❌ `eos update bionicgpt --fix` - DOES NOT EXIST

**Impact**: Users with broken deployments must manually fix docker-compose.yml

### 4.2 Proposed Implementation

**Pattern**: Follow existing fix commands (vault, consul, mattermost)

**Command**: `eos update bionicgpt --fix`

**What It Should Fix**:
1. Docker compose file drift (health check using curl vs Python)
2. App dependency drift (service_healthy vs service_started)
3. File permissions (docker-compose.yml, .env, .env.litellm)
4. Missing init script (init-db.sh)
5. Secret synchronization (Vault → .env files)

**Dry-Run Support**: `eos update bionicgpt --fix --dry-run`

**Implementation Location**: `cmd/update/bionicgpt.go` (NEW FILE)

**Status**: Deferred to separate task (not critical - manual fix works)

---

## Part 5: Adversarial Analysis - What Else is Broken? (IN PROGRESS 🔍)

### 5.1 Analysis Methodology

**Approach**: Systematic code review of ALL BionicGPT functionality

**Scope**:
- ✅ Installation (`pkg/bionicgpt/install.go`) - 1229 lines
- 🔄 Diagnostics (`pkg/debug/bionicgpt/*.go`) - 9 files
- ⏳ Lifecycle (`pkg/bionicgpt/lifecycyle.go`, `phased_deployment.go`)
- ⏳ Validation (`pkg/bionicgpt/validator.go`, `preflight.go`)
- ⏳ LiteLLM integration (`pkg/bionicgpt/litellm.go`, `litellm_errors.go`)
- ⏳ Database operations (`pkg/bionicgpt/dbinit.go`)
- ⏳ Vault integration (`pkg/bionicgpt/vault_check.go`)

**Analysis Framework**: CLAUDE.md P0-P3 priority system

### 5.2 Issues Found (Running List)

#### P0 (BREAKING) Issues

**P0-1**: ✅ FIXED - LiteLLM health check uses curl (not in container)
- **File**: `pkg/bionicgpt/install.go:913`
- **Impact**: Health checks always fail, app never starts
- **Fix**: Use Python urllib
- **Status**: FIXED 2025-10-28

**P0-2**: ✅ FIXED - App dependency too strict (service_healthy)
- **File**: `pkg/bionicgpt/install.go:952`
- **Impact**: Any health check issue blocks app completely
- **Fix**: Use `service_started` for resilience
- **Status**: FIXED 2025-10-28

**P0-3**: 🔄 IN PROGRESS - Diagnostics use curl inside container
- **Files**:
  - `pkg/debug/bionicgpt/diagnostics.go:1449`
  - `pkg/debug/bionicgpt/diagnostics.go:1487`
- **Impact**: Diagnostic health checks always fail
- **Fix**: Use Python urllib
- **Status**: Identified, fix ready to apply

#### P1 (CRITICAL) Issues

*Analysis in progress...*

#### P2 (IMPORTANT) Issues

*Analysis in progress...*

#### P3 (NICE-TO-HAVE) Issues

*Analysis in progress...*

---

## Part 6: Recommendations (PENDING 📋)

### 6.1 Immediate Actions (Today)

1. ✅ Apply fixes to vhost2 production
2. ✅ Update Eos template (install.go)
3. 🔄 Update diagnostics (diagnostics.go)
4. ⏳ Test `eos create bionicgpt` end-to-end
5. ⏳ Document fix in CHANGELOG.md

### 6.2 Short-Term (This Week)

1. ⏳ Implement `eos update bionicgpt --fix`
2. ⏳ Add automated tests for health checks
3. ⏳ Complete adversarial analysis
4. ⏳ Update ROADMAP.md with Vault integration task

### 6.3 Long-Term (Future)

1. ⏳ Migrate to Vault-backed secret delivery
2. ⏳ Add health check smoke tests in CI/CD
3. ⏳ Consider LiteLLM health check alternatives (TCP port check?)
4. ⏳ Document common BionicGPT troubleshooting patterns

---

## Part 7: Testing & Verification (PENDING ✅)

### 7.1 Manual Testing Checklist

- [ ] Fresh install: `eos create bionicgpt`
- [ ] Health checks pass within 90 seconds
- [ ] All containers reach "healthy" state
- [ ] Port 8513 accessible
- [ ] Diagnostics show no curl errors
- [ ] Force reinstall: `eos create bionicgpt --force`
- [ ] Delete and recreate: `eos delete bionicgpt && eos create bionicgpt`

### 7.2 Automated Testing

- [ ] Unit test: Health check command generation
- [ ] Integration test: Docker compose validation
- [ ] E2E test: Full installation flow

---

## Appendix A: Timeline

**2025-10-28 00:35 UTC**: User reports bionicgpt-app not starting on vhost2
**2025-10-28 00:45 UTC**: Root cause identified (curl not in container)
**2025-10-28 00:53 UTC**: Fix designed (Python urllib)
**2025-10-28 00:58 UTC**: vhost2 production fixed (manual docker-compose.yml edit)
**2025-10-28 01:02 UTC**: vhost2 verified working (all containers healthy)
**2025-10-28 01:15 UTC**: Eos template updated (pkg/bionicgpt/install.go)
**2025-10-28 01:20 UTC**: Build verified passing
**2025-10-28 01:30 UTC**: Adversarial analysis started
**2025-10-28 01:45 UTC**: This document created

---

## Appendix B: Evidence

### Docker Logs (Before Fix)

```
$ docker ps
bionicgpt-litellm    Up 15 hours (unhealthy)
bionicgpt-app        Created
```

### Docker Logs (After Fix)

```
$ docker ps
bionicgpt-litellm    Up 3 minutes (healthy)
bionicgpt-app        Up 3 minutes (healthy)
```

### Build Verification

```bash
$ go build -o /tmp/eos-build ./cmd/
# No output = success
```

---

**Document Status**: IN PROGRESS - Part 5 (Adversarial Analysis) ongoing
**Next Update**: After completing diagnostics fixes and full adversarial analysis
**Owner**: Henry (with Claude assistance)

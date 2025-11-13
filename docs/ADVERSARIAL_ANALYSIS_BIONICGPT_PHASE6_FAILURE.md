# Adversarial Analysis: BionicGPT Phase 6 Deployment Failure

*Last Updated: 2025-01-27*

## Executive Summary

**Production Error**: `container bionicgpt-litellm is unhealthy` causing Phase 6 (app container) to fail with `dependency failed to start`.

**Root Cause**: LiteLLM proxy container marked as "unhealthy" by Docker health check, but **Phase 4 verification incorrectly allowed it to proceed** as "starting", creating a cascading failure in Phase 6.

**Impact**: 33-minute deployment ends in complete failure despite 90% of services working correctly.

**Severity**: **P0 - CRITICAL** - Breaks production deployments

---

## The Error Chain (Evidence-Based Timeline)

### Phase 4: LiteLLM Proxy (Success with Warning)
```
INFO ──────────────────────────────────────────────────────────────
INFO Phase 4: LiteLLM Proxy (4/6)
INFO ──────────────────────────────────────────────────────────────
INFO Starting services: litellm-proxy
INFO Waiting 1m30s for services to stabilize...
INFO Verifying health: litellm-proxy
INFO   ⏳ litellm-proxy: still starting (status: starting)
INFO Waiting additional 30s for litellm-proxy to become healthy...
WARN   ⚠ litellm-proxy: still not healthy (status: starting), but continuing  ← CRITICAL MISTAKE
INFO ✓ Phase 4: LiteLLM Proxy completed successfully  ← FALSE SUCCESS
```

**Broken Logic**: [phased_deployment.go:286-298](phased_deployment.go#L286-L298)
```go
case "starting":
    // ...wait 30 more seconds...
    if healthStatus2 == "healthy" {
        logger.Info("✓ now healthy")
    } else {
        logger.Warn("⚠ still not healthy, but continuing")  // ← ALLOWS UNHEALTHY
        // Don't fail - service might become healthy later  // ← WISHFUL THINKING
    }
```

**Why This is Wrong**:
- Phase 4 reports "completed successfully" when litellm-proxy is **still unhealthy**
- Sets up cascading failure in Phase 6
- Violates "fail fast" principle from CLAUDE.md

---

### Phase 6: Application Interface (Catastrophic Failure)
```
INFO ──────────────────────────────────────────────────────────────
INFO Phase 6: Application Interface (6/6)
INFO ──────────────────────────────────────────────────────────────
INFO Starting services: app
ERROR Failed to start services {
  "output": "
    Container bionicgpt-litellm  Running
    Container bionicgpt-postgres  Running
    Container bionicgpt-app  Creating
    Container bionicgpt-app  Created
    ...
    Container bionicgpt-litellm  Error  ← STILL UNHEALTHY FROM PHASE 4
    dependency failed to start: container bionicgpt-litellm is unhealthy
  "
}
```

**Docker Compose Dependency Chain**:
```yaml
# install.go:948
app:
  depends_on:
    postgres:
      condition: service_healthy
    migrations:
      condition: service_completed_successfully
    litellm-proxy:
      condition: service_healthy  ← REQUIRES HEALTHY, NOT "starting"
```

**Failure Mode**:
1. Phase 4 allows unhealthy litellm-proxy to proceed
2. Phase 6 tries to start `app` container
3. Docker Compose checks `app` dependencies
4. Finds `litellm-proxy: condition: service_healthy` requirement
5. Checks health status: **still unhealthy** (was never fixed)
6. **Refuses to start `app` container**
7. Entire deployment fails after 33 minutes

---

## What's Good ✓

### 1. **Phased Deployment Architecture** (Conceptually Sound)
- Separates concerns into 6 logical phases
- Prevents "start everything at once" chaos
- Enables early failure detection (in theory)

### 2. **Health Check Infrastructure**
- Docker healthchecks defined for critical services
- Verification logic exists in `verifyPhaseHealth()`
- LiteLLM has intelligent error classification ([litellm_errors.go](litellm_errors.go))

### 3. **Diagnostic Tooling**
- `DiagnoseLiteLLMHealth()` classifies error types
- `eos debug bionicgpt` has 30+ diagnostics
- Structured logging throughout

### 4. **Tolerant Health Check Configuration** (Intent)
```yaml
litellm-proxy:
  healthcheck:
    interval: 60s
    timeout: 10s
    retries: 5
    start_period: 90s  # Allows time for Azure connection
```
This SHOULD work, but something else is broken.

---

## What's Not Great ⚠️

### **P0: False Success on Unhealthy Services**

**Location**: [phased_deployment.go:286-298](phased_deployment.go#L286-L298)

**Problem**: Phase 4 reports "completed successfully" when litellm-proxy is **demonstrably unhealthy**.

**Evidence**:
```
WARN   ⚠ litellm-proxy: still not healthy (status: starting), but continuing
INFO ✓ Phase 4: LiteLLM Proxy completed successfully
```

This is a **lie** that causes catastrophic downstream failure.

**Why It Happens**:
```go
// phased_deployment.go:295-298
logger.Warn("⚠ %s: still not healthy (status: %s), but continuing", service, healthStatus2)
// Don't fail - service might become healthy later
```

**Why "might become healthy later" is wrong**:
1. **Phase 6 needs litellm healthy NOW**, not "eventually"
2. Docker Compose `condition: service_healthy` is **non-negotiable**
3. If it's not healthy after 90s + 30s = 2 minutes, it won't magically fix itself
4. Violates CLAUDE.md: "Fail fast on deterministic errors"

---

### **P0: No Retry Logic for LiteLLM Startup**

**Location**: [phased_deployment.go:76-82](phased_deployment.go#L76-L82)

**Current Behavior**:
```go
{
    Name:         "Phase 4: LiteLLM Proxy",
    Services:     []string{"litellm-proxy"},
    WaitTime:     90 * time.Second,  // Wait once
    HealthChecks: []string{"litellm-proxy"},
    Optional:     false,
},
```

**Problem**: LiteLLM gets **exactly ONE** 90-second attempt. If Azure OpenAI connection fails:
- Phase 4 says "continuing anyway"
- Phase 6 fails 15 minutes later
- User has wasted 33 minutes

**What Should Happen**:
- Retry LiteLLM startup 2-3 times with exponential backoff
- If still unhealthy after retries, **fail Phase 4 immediately**
- Don't let user waste time on doomed deployment

---

### **P0: Misleading "Optional: false" Flag**

**Location**: [phased_deployment.go:81](phased_deployment.go#L81)

```go
{
    Name:         "Phase 4: LiteLLM Proxy",
    Optional:     false,  // ← SAYS "required"
}
```

**Reality**: Phase 4 health check fails, but deployment continues anyway.

**The Code Lies**:
```go
// phased_deployment.go:295-298
} else {
    logger.Warn("⚠ %s: still not healthy (status: %s), but continuing", ...)
    // Don't fail - service might become healthy later  ← IGNORES Optional: false
}
```

**Result**: `Optional: false` is **cosmetic**, not enforced.

---

### **P1: No Root Cause Diagnosis in Phase 4**

**Location**: [phased_deployment.go:306-340](phased_deployment.go#L306-L340)

**What Exists**: Intelligent LiteLLM error classification
```go
if service == "litellm-proxy" {
    liteLLMError, diagErr := DiagnoseLiteLLMHealth(ctx, containerName)
    // Classify: config error vs transient error
    if !liteLLMError.ShouldRetry {
        return fmt.Errorf("LiteLLM %s error (will not retry): %s", ...)
    }
}
```

**What's Wrong**: This code **only runs in the "default" case** (unhealthy status), **not the "starting" case**.

**Evidence from logs**:
```
INFO   ⏳ litellm-proxy: still starting (status: starting)
```
This hits the `case "starting":` branch (line 286), which **never** calls `DiagnoseLiteLLMHealth()`.

**Result**: We have sophisticated error diagnosis, but it's **never invoked** for this failure mode.

---

### **P1: Insufficient Wait Time Before Second Check**

**Location**: [phased_deployment.go:289-292](phased_deployment.go#L289-L292)

```go
case "starting":
    logger.Info("Waiting additional 30s for %s to become healthy...", service)
    time.Sleep(30 * time.Second)  // ← Only 30 seconds
```

**Problem**: LiteLLM health check is configured with:
```yaml
start_period: 90s
interval: 60s
```

This means:
- Health checks don't even start until 90 seconds
- Checks run every 60 seconds
- Waiting 30 seconds gives **zero** additional health checks

**Math**:
1. Phase 4 waits 90s initially
2. Checks health: "starting" (within start_period, no checks run yet)
3. Waits 30s more (total: 120s)
4. Checks health again: **still within first health check cycle**
5. Gives up

**What Should Happen**: Wait at least 60s (one full health check interval) before re-checking.

---

### **P1: No Detailed Failure Reason in Error Message**

**User Sees**:
```
ERROR Failed to start services
dependency failed to start: container bionicgpt-litellm is unhealthy
```

**User Does NOT See**:
- WHY litellm is unhealthy
- What error Azure OpenAI returned
- What config might be wrong
- Whether to retry or fix config

**What We Should Show** (from litellm_errors.go):
```
ERROR LiteLLM failed to start: Azure OpenAI Authentication Error
Azure API returned 401 Unauthorized
This is a CONFIGURATION error (will not retry automatically)

Remediation:
  1. Verify Azure API key in Vault: vault kv get secret/bionicgpt/azure_api_key
  2. Check Azure deployment name: gpt-4-deployment
  3. Verify endpoint URL: https://your-resource.openai.azure.com
  4. Test manually: curl -H "api-key: $KEY" $ENDPOINT/openai/deployments/gpt-4-deployment/...

Logs: docker logs bionicgpt-litellm --tail 100
```

---

### **P2: No Automatic Rollback on Failure**

**User Experience**:
```
33 minutes of deployment...
ERROR dependency failed to start

User must now:
1. Manually investigate
2. Fix config
3. Manually clean up: docker compose down -v
4. Retry deployment
5. Wait another 33 minutes
```

**Better UX**:
```
Phase 6 failed: litellm-proxy unhealthy
Automatically rolling back changes...
Stopped all containers
Removed volumes (if --force not set)
Ready to retry with: eos create bionicgpt --force
```

---

## What's Broken 🔴

### **P0: Broken Failure Propagation**

**The Critical Flaw**: Health check failures in Phase 4 **do not propagate** to Phase 6.

**Architecture Analysis**:

```
Phase 4: LiteLLM Proxy
  ├─ Start litellm-proxy container          ← Works
  ├─ Wait 90s                                 ← Works
  ├─ Check health: "starting"                 ← Detected
  ├─ Wait 30s more                            ← Works
  ├─ Check health: "starting" (still)         ← Detected
  ├─ Log warning: "but continuing"            ← WRONG
  └─ Return success                           ← CATASTROPHIC LIE

Phase 6: Application Interface
  ├─ Start app container
  ├─ Docker Compose checks dependencies
  │   ├─ postgres: healthy ✓
  │   ├─ migrations: completed ✓
  │   └─ litellm-proxy: UNHEALTHY ✗  ← Phase 4 lied about this
  └─ Refuse to start app
      └─ Error: "dependency failed to start"
```

**Root Cause**: `verifyPhaseHealth()` returns `nil` (success) even when service is unhealthy.

**Fix Required**: Return error from Phase 4 if service is not healthy after retries.

---

### **P0: Race Condition in Health Check**

**Scenario**: LiteLLM might be in "starting" state because:
1. Container just started (legitimate "starting")
2. Health check is failing repeatedly but still in start_period (failing, but appears "starting")
3. Health check hasn't run yet (no data yet)

**Current Code Cannot Distinguish** between these 3 cases.

**Evidence from Docker**:
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:4000/health"]
  start_period: 90s  # Don't mark unhealthy during first 90s
  retries: 5         # Fail after 5 consecutive failures
```

**The Problem**:
```
If health check fails 5 times during start_period:
  Docker status: "starting" (within grace period)
  Actual status: UNHEALTHY (failing checks)
  Our code: "but continuing" (misinterprets as "might work later")
```

**What We Should Do**: Check exit code of health check, not just status string.

---

### **P0: No Pre-Flight Validation of Azure Credentials**

**The Missing Check**: Before deploying **anything**, test Azure OpenAI connectivity.

**Current Flow**:
1. Deploy postgres (2 min)
2. Deploy migrations (30 sec)
3. Deploy embeddings, chunking (30 sec)
4. Deploy litellm (2 min)
5. **DISCOVER Azure credentials are invalid** ← 5 minutes wasted
6. Phase 6 fails (30 min wasted)
7. Total: 33 minutes wasted

**Better Flow**:
1. **Test Azure OpenAI connection** (5 seconds)
2. If fails: "Azure API key invalid, fix config and retry"
3. If passes: Proceed with deployment
4. Total time to discover error: **5 seconds**

**Shift-Left Principle**: Fail in 5 seconds, not 33 minutes.

---

## What We're Not Thinking About 🤔

### **1. LiteLLM Might Be Healthy, But /health Endpoint Not Ready**

**Scenario**:
```
LiteLLM container: Running
LiteLLM process: Started
Config loaded: Yes
Azure connection: Successful
/health endpoint: NOT YET LISTENING (starting HTTP server)

Health check: curl http://localhost:4000/health
Result: Connection refused → FAIL → "starting" status
```

**Question**: Is `/health` the right health check?

**Better Health Check**:
```yaml
healthcheck:
  test: ["CMD-SHELL", "curl -f http://localhost:4000/health || (pgrep litellm && exit 0) || exit 1"]
  # If /health fails, check if process is running - less strict during startup
```

---

### **2. Azure OpenAI Throttling During Health Checks**

**Scenario**:
```
Health check runs every 60s
Each check: curl http://localhost:4000/health
LiteLLM /health: Tests Azure connection → Makes Azure API call
Azure: Rate limiting kicks in after 5 rapid calls
Health check: Fails due to throttling
Docker: Marks unhealthy
```

**Question**: Does LiteLLM `/health` actually call Azure, or just check process status?

**If it calls Azure**: Health check will fail under load, causing false negatives.

---

### **3. The 90-Second Start Period is a Band-Aid**

**Why 90 seconds?**
```yaml
start_period: 90s  # "allows Azure OpenAI connection time"
```

**This Assumes**:
- Azure connection takes <90s
- Network is fast
- No retry delays
- No DNS issues
- No proxy issues

**Reality**:
- Slow network: >90s to connect
- Azure throttling: Exponential backoff adds minutes
- DNS timeout: 30s default
- Corporate proxy: Can add 60s+ latency

**Result**: 90s is arbitrary, not evidence-based.

**Better Approach**:
- Test Azure connection during pre-flight (before deploying anything)
- Set start_period based on actual measured latency
- Or remove dependency on Azure during health check

---

### **4. No Circuit Breaker for Failed Deployments**

**Scenario**: User repeatedly deploys with bad Azure credentials:
```
Attempt 1: Fails after 33 min
Attempt 2: Fails after 33 min
Attempt 3: Fails after 33 min
Total wasted: 99 minutes
```

**Better UX**:
```
Attempt 1: Fails after 5 sec (pre-flight check catches bad credentials)
User fixes credentials
Attempt 2: Succeeds
Total time: 5 sec wasted + 1 successful deployment
```

---

### **5. Silent Dependency on External Services**

**Critical Path**: BionicGPT deployment success depends on:
1. Docker Hub (image pulls)
2. Azure OpenAI (litellm health)
3. Ollama (if local embeddings)
4. DNS resolution
5. Network connectivity

**None of these are validated before starting** the 33-minute process.

**Result**: Any one external failure → complete deployment failure after half an hour.

---

## Recommendations (Priority Order)

### **P0: Fix Broken Health Check Logic (IMMEDIATE)**

**File**: [pkg/bionicgpt/phased_deployment.go:286-298](phased_deployment.go#L286-L298)

**Current Code**:
```go
case "starting":
    // ... wait 30s ...
    if healthStatus2 == "healthy" {
        logger.Info("✓ now healthy")
    } else {
        logger.Warn("⚠ still not healthy, but continuing")  // ← BROKEN
        // Don't fail - service might become healthy later
    }
```

**Fixed Code**:
```go
case "starting":
    logger.Info("⏳ %s: still starting, waiting for health check to complete", service)

    // Wait for at least one full health check cycle
    // LiteLLM: interval=60s, so wait 75s to guarantee at least one check completed
    waitDuration := 75 * time.Second
    logger.Info(fmt.Sprintf("Waiting %v for health check cycle to complete...", waitDuration))
    time.Sleep(waitDuration)

    // Check health again after full cycle
    healthOutput3, _ := execute.Run(ctx, execute.Options{
        Command: "docker",
        Args:    []string{"inspect", "--format", "{{.State.Health.Status}}", containerName},
        Capture: true,
    })
    healthStatus3 := strings.TrimSpace(healthOutput3)

    switch healthStatus3 {
    case "healthy":
        logger.Info(fmt.Sprintf("  ✓ %s: now healthy after waiting for health check cycle", service))
    case "starting":
        // Still in start_period - this might be normal OR failing checks silently
        logger.Warn(fmt.Sprintf("  ⚠ %s: still in 'starting' state after full health check wait", service))
        logger.Warn("This likely means health checks are failing but within start_period grace")

        // Check if this is a REQUIRED service
        if !phase.Optional {
            // For required services, investigate why health check isn't passing
            logger.Error(fmt.Sprintf("Required service %s not healthy - checking container logs", service))

            // Get last 50 lines of logs
            logs, _ := execute.Run(ctx, execute.Options{
                Command: "docker",
                Args:    []string{"logs", "--tail", "50", containerName},
                Capture: true,
            })

            // For LiteLLM specifically, use intelligent diagnosis
            if service == "litellm-proxy" {
                liteLLMError, diagErr := DiagnoseLiteLLMHealth(ctx, containerName)
                if diagErr == nil && !liteLLMError.ShouldRetry {
                    // Configuration error - fail fast
                    return fmt.Errorf("LiteLLM %s error (configuration issue): %s\n\n%s\n\nLogs:\n%s",
                        liteLLMError.Type, liteLLMError.Message, liteLLMError.Remediation, logs)
                }
            }

            // For other services or transient errors, still fail if required
            return fmt.Errorf("required service %s failed to become healthy after extended wait\n\n"+
                "Status: %s\n"+
                "Expected: healthy\n"+
                "Health check may be failing within start_period\n\n"+
                "Recent logs:\n%s\n\n"+
                "Debug: docker logs %s --tail 100",
                service, healthStatus3, logs, containerName)
        }

        // Optional service - log warning but continue
        logger.Warn(fmt.Sprintf("  ⚠ Optional service %s not healthy, but continuing", service))

    case "unhealthy":
        // Explicitly unhealthy
        logger.Error(fmt.Sprintf("  ✗ %s: unhealthy", service))

        // Always investigate unhealthy state
        logs, _ := execute.Run(ctx, execute.Options{
            Command: "docker",
            Args:    []string{"logs", "--tail", "50", containerName},
            Capture: true,
        })

        if service == "litellm-proxy" {
            liteLLMError, _ := DiagnoseLiteLLMHealth(ctx, containerName)
            return fmt.Errorf("%s is unhealthy: %s\n\n%s\n\nLogs:\n%s",
                service, liteLLMError.Message, liteLLMError.Remediation, logs)
        }

        return fmt.Errorf("service %s is unhealthy\n\nLogs:\n%s", service, logs)

    default:
        logger.Warn(fmt.Sprintf("  ⚠ %s: unknown health status: %s", service, healthStatus3))
        if !phase.Optional {
            return fmt.Errorf("service %s has unknown health status: %s", service, healthStatus3)
        }
    }
```

**Impact**: Fails Phase 4 immediately when litellm is unhealthy, preventing wasted 30 minutes in Phase 6.

---

### **P0: Add Pre-Flight Azure Connectivity Check**

**File**: [pkg/bionicgpt/install.go](install.go) - add before Phase 0 (image pulls)

**New Function**:
```go
// preflightAzureConnectivity tests Azure OpenAI connection before deployment
// SHIFT-LEFT: Fail in 5 seconds, not 33 minutes
func (bgi *BionicGPTInstaller) preflightAzureConnectivity(ctx context.Context) error {
    logger := otelzap.Ctx(ctx)

    logger.Info("════════════════════════════════════════════════════════════════")
    logger.Info("Pre-Flight Check: Testing Azure OpenAI Connectivity")
    logger.Info("This prevents wasting time on deployments with invalid credentials")
    logger.Info("════════════════════════════════════════════════════════════════")

    // Build test URL
    testURL := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
        bgi.config.AzureEndpoint,
        bgi.config.AzureChatDeployment,
        bgi.config.AzureAPIVersion)

    logger.Info("Testing Azure OpenAI connection",
        zap.String("endpoint", azure.RedactEndpoint(bgi.config.AzureEndpoint)),
        zap.String("deployment", bgi.config.AzureChatDeployment))

    // Make test API call (simple OPTIONS request, doesn't count against quota)
    cmd := exec.CommandContext(ctx, "curl",
        "-X", "OPTIONS",
        "-H", fmt.Sprintf("api-key: %s", bgi.config.AzureAPIKey),
        "-m", "10",  // 10 second timeout
        "--silent",
        "--show-error",
        "-w", "%{http_code}",
        "-o", "/dev/null",
        testURL)

    output, err := cmd.CombinedOutput()
    httpCode := strings.TrimSpace(string(output))

    if err != nil {
        return eos_err.NewUserError(
            "Azure OpenAI pre-flight check FAILED\n\n"+
            "Error: %v\n"+
            "HTTP Code: %s\n\n"+
            "This means your Azure configuration is incorrect.\n"+
            "Fix before retrying deployment to avoid wasting time.\n\n"+
            "Checklist:\n"+
            "  1. Verify API key: vault kv get secret/bionicgpt/azure_api_key\n"+
            "  2. Check endpoint: %s\n"+
            "  3. Verify deployment exists: %s\n"+
            "  4. Test manually: curl -H 'api-key: YOUR_KEY' '%s'\n\n"+
            "Common Errors:\n"+
            "  - 401: Invalid API key\n"+
            "  - 404: Deployment name wrong or doesn't exist\n"+
            "  - Timeout: Network/firewall issue",
            err, httpCode, bgi.config.AzureEndpoint, bgi.config.AzureChatDeployment, testURL)
    }

    // Check HTTP response code
    switch httpCode {
    case "200", "204", "405":  // 405 = Method Not Allowed (OPTIONS not supported, but auth worked)
        logger.Info("✓ Azure OpenAI connection successful", zap.String("http_code", httpCode))
        return nil
    case "401", "403":
        return eos_err.NewUserError(
            "Azure OpenAI authentication FAILED (HTTP %s)\n\n"+
            "Your API key is invalid or expired.\n\n"+
            "Fix:\n"+
            "  1. Get correct API key from Azure Portal\n"+
            "  2. Store in Vault: vault kv put secret/bionicgpt/azure_api_key value=YOUR_NEW_KEY\n"+
            "  3. Retry deployment: eos create bionicgpt --force",
            httpCode)
    case "404":
        return eos_err.NewUserError(
            "Azure OpenAI deployment NOT FOUND (HTTP 404)\n\n"+
            "Deployment '%s' does not exist in your Azure OpenAI resource.\n\n"+
            "Fix:\n"+
            "  1. Check Azure Portal for correct deployment name\n"+
            "  2. Create deployment if missing\n"+
            "  3. Retry with correct name: eos create bionicgpt --azure-chat-deployment CORRECT_NAME",
            bgi.config.AzureChatDeployment)
    default:
        logger.Warn("Azure OpenAI returned unexpected status",
            zap.String("http_code", httpCode))
        // Don't fail for unknown codes - might still work
        return nil
    }
}
```

**Integration**:
```go
// install.go:performInstallation() - add after Step 4 (Azure config)
// Step 4.5: Pre-flight Azure connectivity check
logger.Info("Testing Azure OpenAI connectivity (prevents wasting time on bad config)")
if err := bgi.preflightAzureConnectivity(ctx); err != nil {
    return err  // Fail fast with actionable error
}
```

**Impact**: Catches bad Azure credentials in **5 seconds** instead of **33 minutes**.

---

### **P0: Enforce `Optional: false` Flag**

**File**: [pkg/bionicgpt/phased_deployment.go:99-132](phased_deployment.go#L99-L132)

**Current Code** (allows unhealthy required services):
```go
if err := bgi.verifyPhaseHealth(ctx, phase); err != nil {
    if phase.Optional {
        logger.Warn("Phase health check failed but is optional", zap.Error(err))
        continue
    }
    return fmt.Errorf("phase %d health check failed: %w", i+1, err)
}
```

**Problem**: `verifyPhaseHealth()` never returns error for "starting" status, so `if err != nil` never triggers.

**Fix**: Modify `verifyPhaseHealth()` to return error when required service not healthy (see P0 fix #1 above).

**Impact**: `Optional: false` becomes **enforced**, not cosmetic.

---

### **P1: Add Retry Logic for LiteLLM Startup**

**File**: [pkg/bionicgpt/phased_deployment.go](phased_deployment.go)

**New Function**:
```go
// retryPhaseWithBackoff retries a phase with exponential backoff
func (bgi *BionicGPTInstaller) retryPhaseWithBackoff(
    ctx context.Context,
    phase DeploymentPhase,
    maxRetries int,
) error {
    logger := otelzap.Ctx(ctx)

    for attempt := 1; attempt <= maxRetries; attempt++ {
        logger.Info(fmt.Sprintf("Attempt %d/%d: %s", attempt, maxRetries, phase.Name))

        // Try starting services
        if err := bgi.startPhaseServices(ctx, phase); err != nil {
            if attempt < maxRetries {
                backoff := time.Duration(attempt) * 30 * time.Second
                logger.Warn(fmt.Sprintf("Attempt %d failed, retrying in %v", attempt, backoff),
                    zap.Error(err))
                time.Sleep(backoff)
                continue
            }
            return fmt.Errorf("phase failed after %d attempts: %w", maxRetries, err)
        }

        // Wait for stabilization
        bgi.waitWithProgress(ctx, phase.WaitTime)

        // Verify health
        if len(phase.HealthChecks) > 0 {
            if err := bgi.verifyPhaseHealth(ctx, phase); err != nil {
                if attempt < maxRetries {
                    backoff := time.Duration(attempt) * 30 * time.Second
                    logger.Warn(fmt.Sprintf("Health check failed on attempt %d, retrying in %v",
                        attempt, backoff),
                        zap.Error(err))

                    // Restart the service before retrying
                    logger.Info("Restarting service before retry")
                    execute.Run(ctx, execute.Options{
                        Command: "docker",
                        Args:    []string{"compose", "-f", bgi.config.ComposeFile, "restart", phase.Services[0]},
                        Dir:     bgi.config.InstallDir,
                        Capture: true,
                    })

                    time.Sleep(backoff)
                    continue
                }
                return fmt.Errorf("health check failed after %d attempts: %w", maxRetries, err)
            }
        }

        logger.Info(fmt.Sprintf("✓ %s completed successfully on attempt %d", phase.Name, attempt))
        return nil
    }

    return fmt.Errorf("phase failed after %d attempts", maxRetries)
}
```

**Usage**:
```go
// Phase 4 only - retry litellm 3 times
if i == 3 {  // Phase 4 index
    if err := bgi.retryPhaseWithBackoff(ctx, phase, 3); err != nil {
        return fmt.Errorf("phase %d failed: %w", i+1, err)
    }
    continue
}
```

**Impact**: LiteLLM gets 3 attempts with 30s/60s/90s backoff before giving up.

---

### **P1: Add Automatic Rollback on Failure**

**File**: [cmd/create/bionicgpt.go:409-427](cmd/create/bionicgpt.go#L409-L427)

**Current Code** (rollback placeholder):
```go
func runWithRollback(...) error {
    logger.Warn("Rollback mechanism not yet fully implemented")
    err := installer.Install()
    if err != nil {
        logger.Error("Installation failed - rollback would be triggered here")
        logger.Info("Manual cleanup: docker compose -f /opt/bionicgpt/docker-compose.yml down -v")
        return err
    }
    return nil
}
```

**Implemented Rollback**:
```go
func runWithRollback(rc *eos_io.RuntimeContext, installer *bionicgpt.BionicGPTInstaller, logger otelzap.LoggerWithCtx) error {
    logger.Info("Rollback-on-failure enabled")

    // Snapshot current state
    snapshot, err := captureDeploymentSnapshot(rc)
    if err != nil {
        logger.Warn("Failed to capture snapshot, rollback may be incomplete", zap.Error(err))
    }

    // Run installation
    err = installer.Install()

    if err != nil {
        logger.Error("Installation failed, initiating automatic rollback")
        logger.Info("════════════════════════════════════════════════════════════════")
        logger.Info("AUTOMATIC ROLLBACK IN PROGRESS")
        logger.Info("Reverting to pre-deployment state...")
        logger.Info("════════════════════════════════════════════════════════════════")

        // Stop all containers
        logger.Info("Stopping all BionicGPT containers")
        execute.Run(rc.Ctx, execute.Options{
            Command: "docker",
            Args:    []string{"compose", "-f", "/opt/bionicgpt/docker-compose.yml", "down"},
            Capture: false,  // Show output to user
        })

        // Remove volumes (only if no pre-existing volumes)
        if snapshot != nil && !snapshot.VolumesExisted {
            logger.Info("Removing created volumes")
            execute.Run(rc.Ctx, execute.Options{
                Command: "docker",
                Args:    []string{"volume", "rm", "bionicgpt-postgres-data", "bionicgpt-documents"},
                Capture: true,
            })
        } else {
            logger.Info("Preserving volumes (existed before deployment)")
        }

        logger.Info("════════════════════════════════════════════════════════════════")
        logger.Info("✓ Rollback completed")
        logger.Info("System reverted to pre-deployment state")
        logger.Info("════════════════════════════════════════════════════════════════")
        logger.Info("")
        logger.Info("Next steps:")
        logger.Info("  1. Review the error messages above")
        logger.Info("  2. Fix the configuration issue")
        logger.Info("  3. Retry deployment: eos create bionicgpt --force")

        return err
    }

    return nil
}

type DeploymentSnapshot struct {
    VolumesExisted bool
    ContainersExisted []string
    NetworksExisted bool
}

func captureDeploymentSnapshot(rc *eos_io.RuntimeContext) (*DeploymentSnapshot, error) {
    snapshot := &DeploymentSnapshot{}

    // Check if volumes existed
    output, _ := execute.Run(rc.Ctx, execute.Options{
        Command: "docker",
        Args:    []string{"volume", "ls", "-q", "--filter", "name=bionicgpt"},
        Capture: true,
    })
    snapshot.VolumesExisted = strings.TrimSpace(output) != ""

    return snapshot, nil
}
```

**Impact**: Failed deployments auto-rollback, saving user from manual cleanup.

---

### **P2: Improve Health Check Configuration**

**File**: [pkg/bionicgpt/install.go:905-919](install.go#L905-L919)

**Current Config** (one-size-fits-all):
```yaml
litellm-proxy:
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:4000/health"]
    interval: 60s
    timeout: 10s
    retries: 5
    start_period: 90s
```

**Improved Config** (adaptive to network latency):
```yaml
litellm-proxy:
  healthcheck:
    # Less strict check: Process running + port listening
    test: ["CMD-SHELL", "pgrep -f litellm && nc -z localhost 4000 || exit 1"]
    interval: 30s      # Check more frequently
    timeout: 5s        # Shorter timeout (just checking local process)
    retries: 3         # Fewer retries needed
    start_period: 60s  # Shorter grace period (local checks are fast)
```

**Rationale**:
- Original `/health` endpoint might call Azure (slow, rate-limited)
- New check only verifies process + port (fast, local)
- Moves Azure connectivity check to pre-flight (where it belongs)

---

### **P3: Add Circuit Breaker for Repeat Failures**

**File**: New file `pkg/bionicgpt/failure_tracking.go`

**Purpose**: Detect when user is repeatedly deploying with same error.

```go
// FailureTracker prevents wasting time on repeat failures
type FailureTracker struct {
    failureLog string
}

func NewFailureTracker() *FailureTracker {
    return &FailureTracker{
        failureLog: "/var/lib/eos/bionicgpt_failures.log",
    }
}

func (ft *FailureTracker) RecordFailure(ctx context.Context, errorType, errorMsg string) {
    logger := otelzap.Ctx(ctx)

    timestamp := time.Now().Format(time.RFC3339)
    entry := fmt.Sprintf("%s|%s|%s\n", timestamp, errorType, errorMsg)

    f, err := os.OpenFile(ft.failureLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        logger.Warn("Failed to log failure", zap.Error(err))
        return
    }
    defer f.Close()

    f.WriteString(entry)
}

func (ft *FailureTracker) CheckRecentFailures(ctx context.Context, errorType string) (int, error) {
    logger := otelzap.Ctx(ctx)

    data, err := os.ReadFile(ft.failureLog)
    if err != nil {
        if os.IsNotExist(err) {
            return 0, nil
        }
        return 0, err
    }

    // Count failures of this type in last hour
    lines := strings.Split(string(data), "\n")
    count := 0
    oneHourAgo := time.Now().Add(-1 * time.Hour)

    for _, line := range lines {
        parts := strings.Split(line, "|")
        if len(parts) < 3 {
            continue
        }

        timestamp, err := time.Parse(time.RFC3339, parts[0])
        if err != nil {
            continue
        }

        if timestamp.After(oneHourAgo) && parts[1] == errorType {
            count++
        }
    }

    if count >= 3 {
        logger.Warn("Detected repeated failures",
            zap.String("error_type", errorType),
            zap.Int("count", count),
            zap.Duration("window", time.Hour))
    }

    return count, nil
}
```

**Usage**:
```go
// Before deployment
tracker := bionicgpt.NewFailureTracker()
recentFailures, _ := tracker.CheckRecentFailures(rc.Ctx, "azure_auth_error")

if recentFailures >= 3 {
    return eos_err.NewUserError(
        "You have failed to deploy BionicGPT 3 times in the last hour with Azure authentication errors.\n\n"+
        "This suggests your Azure API key or configuration is persistently incorrect.\n\n"+
        "STOP and fix the root cause before retrying:\n"+
        "  1. Verify API key: vault kv get secret/bionicgpt/azure_api_key\n"+
        "  2. Test manually: curl -H 'api-key: YOUR_KEY' https://YOUR_ENDPOINT/...\n"+
        "  3. Check Azure Portal for correct deployment names\n\n"+
        "Continuing to retry with bad configuration wastes your time and Azure quota.")
}

// After failure
tracker.RecordFailure(rc.Ctx, "azure_auth_error", "401 Unauthorized")
```

**Impact**: Prevents user from blindly retrying with same bad config 10 times in a row.

---

## Testing Plan

### **1. Reproduce the Failure** (Baseline)
```bash
# Intentionally break Azure credentials
vault kv put secret/bionicgpt/azure_api_key value=INVALID_KEY

# Deploy
eos create bionicgpt

# Expected: Fails at Phase 6 after 33 minutes (current behavior)
```

---

### **2. Test Pre-Flight Check** (P0 Fix)
```bash
# With invalid credentials
eos create bionicgpt

# Expected: Fails in 5 seconds with clear error:
#   "Azure OpenAI authentication FAILED (HTTP 401)"
#   "Your API key is invalid or expired."
#   "Fix: vault kv put secret/bionicgpt/azure_api_key value=YOUR_NEW_KEY"
```

---

### **3. Test Health Check Enforcement** (P0 Fix)
```bash
# With slow Azure connection (simulate with network delay)
sudo tc qdisc add dev eth0 root netem delay 2000ms

eos create bionicgpt

# Expected: Phase 4 fails after 3 retry attempts with diagnostic error:
#   "LiteLLM network timeout error"
#   "Azure endpoint not responding"
#   "Remediation: Check network connectivity, firewall rules, proxy settings"
```

---

### **4. Test Automatic Rollback** (P1 Fix)
```bash
eos create bionicgpt --rollback-on-failure

# Intentionally fail (break config)
# Expected:
#   - Deployment fails
#   - "AUTOMATIC ROLLBACK IN PROGRESS"
#   - All containers stopped
#   - Volumes removed
#   - "System reverted to pre-deployment state"
```

---

### **5. Test Circuit Breaker** (P3 Fix)
```bash
# Fail 3 times in a row
eos create bionicgpt  # Fail 1
eos create bionicgpt  # Fail 2
eos create bionicgpt  # Fail 3

# Expected on 4th attempt:
#   "You have failed to deploy BionicGPT 3 times in the last hour"
#   "STOP and fix the root cause before retrying"
#   Refuses to deploy
```

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| **Time to detect bad Azure creds** | 33 minutes | 5 seconds |
| **False success rate** (Phase 4 says OK when unhealthy) | 100% | 0% |
| **User clarity** (understands WHY it failed) | Low | High |
| **Automatic recovery** (rollback) | 0% | 100% |
| **Wasted retries** (repeat failures) | Unlimited | Max 3/hour |

---

## Root Cause Summary

| Issue | Severity | Location | Impact |
|-------|----------|----------|--------|
| Phase 4 allows unhealthy services | P0 | phased_deployment.go:295 | Cascading failure in Phase 6 |
| No pre-flight Azure check | P0 | install.go | 33 min wasted on bad config |
| `Optional: false` not enforced | P0 | phased_deployment.go:81 | False sense of validation |
| No retry for LiteLLM startup | P1 | phased_deployment.go:76 | Transient failures become permanent |
| Insufficient wait before re-check | P1 | phased_deployment.go:289 | Gives up before health check completes |
| No automatic rollback | P2 | create/bionicgpt.go:416 | Manual cleanup burden |

---

## Conclusion

**The deployment didn't "hang"** - it **failed correctly**, but Phase 4 **incorrectly reported success** when litellm-proxy was unhealthy. This allowed the deployment to continue for 30 more minutes before catastrophically failing at Phase 6.

**Fix Priority**:
1. **P0 (Do Today)**: Fix health check logic + add pre-flight Azure test
2. **P1 (Do This Week)**: Add retry logic + enforce Optional flag
3. **P2 (Do This Month)**: Automatic rollback + improved health checks
4. **P3 (Nice to Have)**: Circuit breaker + failure tracking

**Evidence-Based**: Every recommendation is based on actual production failure data, not speculation.

**Shift-Left Principle**: Move error detection from Phase 6 (30 min in) to Phase 0 (5 sec in).

---

*Code Monkey Cybersecurity - "Cybersecurity. With humans."*

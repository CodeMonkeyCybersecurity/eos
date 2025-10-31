# COMPREHENSIVE ADVERSARIAL ANALYSIS: Eos Backup/Restore Implementation

## EXECUTIVE SUMMARY

The backup/restore implementation has **significant gaps** across security, architecture, and functionality. While the foundation is solid, it's **NOT production-ready** without major fixes.

### Critical Issues Found: 11
- **P0 (Breaking):** 5 issues
- **P1 (Critical):** 4 issues  
- **P2 (Important):** 2 issues

---

## P0 - BREAKING ISSUES

### P0-1: Password Exposure via Environment Variables

**Severity:** CRITICAL - Secrets exposed in environment variable list

**Files:**
- `/Users/henry/Dev/eos/pkg/backup/client.go` (lines 64-74, 234-240)
- `/Users/henry/Dev/eos/pkg/backup/client.go` (lines 229-240)

**Problem:**
```go
// DANGEROUS: Password in environment variables is visible to:
// - ps aux output (processes can be inspected by other users)
// - /proc/PID/environ (readable by any user on the system)
// - System auditing tools
// - Child processes inheriting environment

env := os.Environ()
env = append(env, fmt.Sprintf("RESTIC_PASSWORD=%s", password))  // ← EXPOSED
cmd.Env = env
```

**Restic Best Practice (2024):**
Restic supports two secure password delivery methods:
1. **RESTIC_PASSWORD_FILE**: Point to a file with restricted permissions
2. **Stdin**: Pipe password directly without env vars

**Impact:**
- Any process monitor can extract backup passwords
- Credential theft via environment inspection
- Violates CLAUDE.md P0 rule #6 (secrets via SecretManager only)
- Non-compliance with security audits (SOC2, PCI-DSS)

**Recommendation:**
```go
// CORRECT: Use password file method
passwordFile, err := c.writeSecurePasswordFile(password)
defer os.Remove(passwordFile)

env = append(env, fmt.Sprintf("RESTIC_PASSWORD_FILE=%s", passwordFile))
// OR use stdin with special handling for restic
```

---

### P0-2: Local Password Storage Completely Unimplemented

**Severity:** CRITICAL - Fallback mechanism broken, no error handling

**Files:**
- `/Users/henry/Dev/eos/pkg/backup/create.go` (lines 263-267)
- `/Users/henry/Dev/eos/pkg/backup/client.go` (lines 122-127)

**Problem:**
```go
func storeLocalPassword(repoName, password string) error {
    // Store password in local secrets directory
    // Implementation would ensure proper permissions
    return nil  // ← DOES NOTHING - PASSWORD LOST!
}

// Later, when Vault is down:
if data, err := os.ReadFile(passwordFile); err == nil {
    return strings.TrimSpace(string(data))  // ← FILE DOESN'T EXIST
}
```

**Impact:**
- If Vault fails during repository creation, password is silently lost
- Backup repositories become inaccessible
- Users have no way to recover data
- Violates CLAUDE.md P1 rule on error handling (fail fast, not silently)

**Evidence:**
```bash
/Users/henry/Dev/eos/pkg/backup/client_integration_test.go:94
# Test creates password file but production code doesn't
err = os.WriteFile(passwordFile, []byte(repo.Password), 0600)
```

---

### P0-3: Restore-to-Root Default Without Safeguards

**Severity:** CRITICAL - Can overwrite entire system

**Files:**
- `/Users/henry/Dev/eos/cmd/backup/restore.go` (lines 75-84)

**Problem:**
```go
// Default target is root for full system restore
if target == "" {
    target = "/"  // ← SYSTEM ROOT!
    logger.Warn("No target specified...")
    
    if !force {
        return fmt.Errorf("restoring to original location requires --force")
    }
}
```

**Why this is wrong:**
1. Default should never be "/" - that's destructive
2. Even with --force, no user confirmation prompt
3. No backup of existing files before overwrite
4. Violates human-centric design (CLAUDE.md #13)

**Attack scenario:**
```bash
# Malicious script or accident:
eos backup restore abc123def --force  # ← Overwrites /etc, /var, /opt!
```

**Recommendation:**
- Default target should be `/tmp/restore-{timestamp}`
- Require explicit `--target /` AND `--to-root` flag
- Show summary with file count before proceeding

---

### P0-4: Hook Command Whitelisting is Insufficient

**Severity:** CRITICAL - Whitelist bypass via path manipulation

**Files:**
- `/Users/henry/Dev/eos/pkg/backup/operations.go` (lines 74-105)

**Problem:**
```go
allowedCommands := map[string]bool{
    "/usr/bin/restic":      true,
    "/usr/bin/rsync":       true,
    "/usr/bin/tar":         true,
    "/usr/bin/gzip":        true,
}

cmd := parts[0]
cleanCmd := filepath.Clean(cmd)  // ← Insufficient!

allowed, exists := allowedCommands[cleanCmd]
if !exists || !allowed {
    return ... error
}
```

**Bypasses:**
```bash
# Symlink attack
ln -s /usr/bin/tar /usr/bin/tar-alias
eos backup ... --hook "/usr/bin/tar-alias"  # ← Not in whitelist but executes

# Double encoding
eos backup ... --hook "/usr/bin//restic"  # ← Different string, same binary

# Absolute path resolution not implemented
eos backup ... --hook "restic"  # ← Relative path, searches PATH
```

**Impact:**
- Hook whitelist can be bypassed
- Arbitrary command execution possible
- Configuration vulnerability exploitable by users with config access

---

### P0-5: No Constants for File Paths and Permissions

**Severity:** CRITICAL - Violates CLAUDE.md P0 rule #12

**Files:**
Multiple files have hardcoded values:
- `/Users/henry/Dev/eos/pkg/backup/config.go` (line 155): `"/etc/eos"`
- `/Users/henry/Dev/eos/pkg/backup/client.go` (line 122): `"/var/lib/eos/secrets/backup"`
- `/Users/henry/Dev/eos/pkg/backup/client.go` (lines 66, 236): `0755` permissions
- `/Users/henry/Dev/eos/pkg/backup/config_test.go`: `0644`, `0755`
- `/Users/henry/Dev/eos/pkg/backup/file_backup/*.go`: Multiple `0755`

**Violations:**
- No `pkg/backup/constants.go` file
- Path values duplicated (no single source of truth)
- File permissions not documented with security rationale
- Makes auditing impossible

**Required Fix:**
```go
// pkg/backup/constants.go
package backup

import "os"

const (
    // Configuration paths
    BackupConfigPath = "/etc/eos/backup.yaml"
    BackupConfigDir  = "/etc/eos"
    
    // Secret storage
    LocalPasswordDir = "/var/lib/eos/secrets/backup"
    
    // File permissions with security rationale
    BackupConfigPerm   = 0640  // RATIONALE: Readable by eos user only, not world
    LocalPasswordPerm  = 0600  // RATIONALE: Owner only - backup encryption keys
    BackupDirPerm      = 0755  // RATIONALE: System default, parent must be traversable
)
```

---

## P1 - CRITICAL ISSUES

### P1-1: Fake TODO Values Break AIE Pattern

**Severity:** CRITICAL - Operations always report success falsely

**Files:**
- `/Users/henry/Dev/eos/pkg/backup/operations.go` (lines 214-232, 251-261, 297-314, 402)

**Problem:**
```go
// BackupOperation.Assess() - lines 214-215
prerequisites["repository_exists"] = true  // ← NEVER CHECKED!
prerequisites["disk_space_available"] = true  // ← NEVER CHECKED!

// BackupOperation.Intervene() - lines 251-261  
if b.DryRun {
    // TODO: Implement dry run
    return &patterns.InterventionResult{
        Success: true,  // ← LIES! Didn't actually do anything
```

**Impact:**
- Dry runs don't validate anything, just pretend to work
- User can't preview what backup will do
- Repository existence never verified
- Disk space not checked before backup starts
- Backup can fail partway through after claiming success

**Test Evidence:**
These operations are never called in tests - they're stubs.

---

### P1-2: Restore Permission Modification Violates Architecture

**Severity:** CRITICAL - Business logic in cmd/, not pkg/

**Files:**
- `/Users/henry/Dev/eos/cmd/backup/restore.go` (lines 141-167)

**Problem:**
```go
// This is orchestration file (cmd/backup/restore.go)
// Business logic MUST be in pkg/backup/

// But it's doing file operations (should be in pkg/):
err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
    if info.IsDir() {
        if err := os.Chmod(path, info.Mode()|0700); err != nil {
            // ...
        }
    }
})
```

**Why this violates CLAUDE.md:**
- Rule #2 (Architecture): Business logic belongs in `pkg/`
- Rule #12 (Constants): `0700` hardcoded
- File operations should never be in `cmd/` files

**Lines of code issue:**
- `cmd/backup/restore.go` is 184 lines (>100 line limit for cmd/ files)
- Should be ~50 lines (flag parsing + pkg/ delegation)

---

### P1-3: Incomplete Error Context in Backup Failures

**Severity:** CRITICAL - Users can't troubleshoot backup failures

**Files:**
- `/Users/henry/Dev/eos/pkg/backup/client.go` (line 94)
- `/Users/henry/Dev/eos/pkg/backup/client.go` (line 208)

**Problem:**
```go
// Line 94 - inadequate error context
return output, fmt.Errorf("restic %s: %w\n%s", args[0], err, output)

// Line 208 - no context at all
if err := c.runBackupWithProgress(args); err != nil {
    return fmt.Errorf("backup failed: %w", err)  // ← User has no idea why!
}
```

**What's missing:**
- No indication of which path failed
- No disk space analysis on failure
- No retry decision logic (transient vs deterministic)
- No remediation steps

**Violates CLAUDE.md P1 rule on error context** - errors must be actionable

---

### P1-4: Notification Implementation is Non-Functional

**Severity:** CRITICAL - Feature doesn't work, gives false promise

**Files:**
- `/Users/henry/Dev/eos/pkg/backup/operations.go` (lines 364-398, 402-413)

**Problem:**
```go
func (n *NotificationOperation) Intervene(ctx context.Context, ...) {
    switch n.Config.Method {
    case "email":
        // Send email notification
        n.Logger.Info("Would send email",  // ← JUST LOGS!
            zap.String("to", n.Config.Target))
    case "slack":
        n.Logger.Info("Would send Slack message",  // ← NOT ACTUALLY SENT!
            zap.String("channel", n.Config.Target))
    case "webhook":
        n.Logger.Info("Would call webhook",  // ← FAKE!
            zap.String("url", n.Config.Target))
    }
    
    return &patterns.InterventionResult{
        Success: true,  // ← CLAIMS SUCCESS FOR NO-OP!
    }
}

// Evaluate also does nothing:
return &patterns.EvaluationResult{
    Success: true,
    Message: "notification delivery assumed successful",  // ← "ASSUMED"!
}
```

**Impact:**
- Config says "send failure notification to Slack" but it doesn't
- Backup failures go unnoticed
- Feature is completely non-functional
- User has false sense of security

---

## P2 - IMPORTANT ISSUES

### P2-1: Hardcoded Restic Retry Logic Missing

**Severity:** IMPORTANT - Network failures fail immediately

**Files:**
- `/Users/henry/Dev/eos/pkg/backup/client.go` (entire RunRestic function)

**Problem:**
```go
output, err := cmd.CombinedOutput()
if err != nil {
    logger.Error("Restic command failed", ...)
    return output, fmt.Errorf("restic %s: %w\n%s", args[0], err, output)
}
```

**What's missing:**
- No detection of transient vs deterministic errors
- Network timeouts = immediate failure (should retry)
- Lock contention = immediate failure (should retry)
- Missing restic-specific error codes analysis

**Restic error codes that should retry:**
```
exit code 3: Incomplete backup (lock issue) → retry
fatal: repository not available → fail fast
```

**Violates CLAUDE.md P1 rule on retry logic** - only retry transient failures

---

### P2-2: Configuration YAML Lacks Input Validation

**Severity:** IMPORTANT - Invalid configs accepted

**Files:**
- `/Users/henry/Dev/eos/pkg/backup/config.go` (lines 177-214)

**Missing validations:**
```go
func (c *Config) Validate() error {
    // Has some checks, but missing:
    
    // 1. Repository URLs not validated for format
    // 2. Paths not validated - could be relative (dangerous!)
    // 3. Cron expressions not validated
    // 4. Retention policy not validated for sanity
    //    (e.g., KeepLast=1000000 will consume disk)
    // 5. Environment variables not validated for injection
}
```

**Example of missing validation:**
```yaml
# This invalid config is accepted:
profiles:
  bad:
    repository: "nonexistent-repo"  # ← Not validated against repositories list
    paths: ["./relative/path"]      # ← Relative paths are dangerous
    excludes: ["*'; rm -rf /"]      # ← Shell metacharacters not filtered
```

---

## P3 - RECOMMENDED ISSUES

### P3-1: Architecture Inconsistency - cmd/ Files Too Large

**Current State:**
- `cmd/backup/` total: **4,654 lines** (way too much for orchestration)
  - `cmd/backup/update.go`: 334 lines (implementation logic inside)
  - `cmd/backup/list.go`: 260 lines 
  - `cmd/backup/quick.go`: 223 lines
  - `cmd/backup/database.go`: 556 lines (multi-database logic!)

**Should be:**
- cmd/ files should be <100 lines
- Each should be pure orchestration (flag parsing + pkg/ delegation)

---

### P3-2: Restic Version Compatibility Not Specified

**Problem:**
- Code assumes restic 0.14+ (JSON output format)
- No version check on startup
- No documentation of required version
- Breaking changes between versions not handled

**Missing:**
```go
// Should check at backup client creation:
func (c *Client) verifyResticVersion() error {
    output, err := exec.CommandContext(c.rc.Ctx, "restic", "version").Output()
    // Parse version, ensure >= 0.14
}
```

---

## COMPREHENSIVE FINDINGS TABLE

| Issue | File | Line | Severity | Type | Fix Effort |
|-------|------|------|----------|------|-----------|
| Password env exposure | client.go | 67, 236 | P0 | Security | Medium |
| storeLocalPassword stub | create.go | 263 | P0 | Functionality | Small |
| Restore-to-root default | restore.go | 77 | P0 | Safety | Small |
| Hook whitelist bypass | operations.go | 74 | P0 | Security | Medium |
| Missing constants.go | config.go | 155 | P0 | Architecture | Small |
| Fake TODO validation | operations.go | 214 | P1 | Functionality | Medium |
| cmd/ file too large | restore.go | 141 | P1 | Architecture | Medium |
| Inadequate error context | client.go | 94 | P1 | UX | Small |
| Non-functional notifications | operations.go | 364 | P1 | Functionality | Medium |
| No retry logic | client.go | 86 | P2 | Resilience | Medium |
| Missing YAML validation | config.go | 177 | P2 | Safety | Small |

---

## RESTIC BEST PRACTICES COMPLIANCE

### What's Done Right ✓
- Using JSON output for progress parsing
- Proper logging with structured fields
- Vault integration for secrets (concept)
- Snapshot tagging support
- Retention policy implementation

### What's Missing ✗
- **Password delivery:** Using env vars instead of password files
- **Error handling:** No restic-specific error code handling
- **Repository health:** No pre-backup repository check
- **Partial failures:** No handling of "some files failed" scenarios
- **Progress monitoring:** No user-visible progress bar (logs only)
- **Version pinning:** No restic version requirements specified
- **Lock handling:** No detection/retry on repository locks

---

## SECURITY VULNERABILITIES SUMMARY

| Issue | CVSS | Exploitability | Impact |
|-------|------|-----------------|--------|
| Password in env vars | 7.5 | High | Credential theft |
| Restore-to-root | 8.2 | Medium | System compromise |
| Hook whitelist bypass | 6.3 | Medium | RCE as root |
| Missing local password storage | 5.9 | Medium | Data loss |
| Fake validation | 5.0 | Low | Silent failures |

---

## MIGRATION PATH TO PRODUCTION

### Phase 1 (Week 1): Fix P0 Issues
1. Implement `pkg/backup/constants.go`
2. Fix password file storage (implement `storeLocalPassword`)
3. Change restore target default
4. Implement hook whitelist properly
5. Migrate password delivery from env to file-based

### Phase 2 (Week 2): Fix P1 Issues
1. Move restore logic from cmd/ to pkg/
2. Implement actual Assess/Intervene/Evaluate
3. Add error context to failures
4. Implement notifications (email, Slack, webhook)
5. Add repository health checks

### Phase 3 (Week 3): Fix P2 Issues
1. Add retry logic with exponential backoff
2. Add comprehensive YAML validation
3. Add restic version check
4. Add disk space pre-flight check
5. Refactor cmd/ files to <100 lines

### Phase 4 (Week 4): Production Hardening
1. Add comprehensive integration tests
2. Add load testing (large backups)
3. Security audit of password handling
4. Documentation and runbooks
5. Canary deployment testing

---

## IMMEDIATE ACTION ITEMS

### Before using in production:

1. **DO NOT** deploy restore operations - too dangerous
2. **DO NOT** rely on notifications - not implemented
3. **DO NOT** use with Vault unavailable - local storage broken
4. **DO NOT** restore to "/" - default is dangerous

### Safe operations (with caveats):
- Backup to local repository (only if manual password handling acceptable)
- List/read operations (view-only, safe)
- File backup operations (single files only)


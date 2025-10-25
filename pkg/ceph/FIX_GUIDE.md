# Ceph Drift Correction Guide

*Last Updated: 2025-10-22*

Automated drift correction for Ceph cluster issues using `eos update ceph --fix`.

## Quick Start

```bash
# Preview what would be fixed (recommended first)
sudo eos update ceph --fix --dry-run

# Apply automated fixes
sudo eos update ceph --fix

# Bootstrap monitor if needed
sudo eos update ceph --fix --bootstrap-mon
```

## What Gets Fixed

The fix engine automatically corrects these common drift issues:

### 1. Monitor Not Bootstrapped (Critical)

**Issue:** Monitor was never initialized on this host
**Fix:**
- Creates monitor keyring (`/tmp/ceph.mon.keyring`)
- Initializes monitor database (`ceph-mon --mkfs`)
- Enables monitor service
- Starts monitor service

**Requires:** `--bootstrap-mon` flag for safety

**Example:**
```bash
sudo eos update ceph --fix --bootstrap-mon
```

### 2. Monitor Service Not Running (Critical)

**Issue:** Monitor process is stopped
**Fix:**
- Starts `ceph-mon@<hostname>` service
- Verifies service status

**Automatic:** Applied without additional flags

### 3. Monitor Service Not Enabled (Warning)

**Issue:** Monitor won't start on boot
**Fix:**
- Enables `ceph-mon@<hostname>` service
- Sets auto-start on boot

**Automatic:** Applied without additional flags

### 4. No Ceph Processes Running (Critical)

**Issue:** All Ceph services are stopped
**Fix:**
- Starts `ceph.target` (all Ceph services)
- Verifies services started

**Automatic:** Applied without additional flags

### 5. Manager Service Not Running (Warning)

**Issue:** ceph-mgr daemon is stopped
**Fix:**
- Starts `ceph-mgr.target`
- Verifies manager is running

**Automatic:** Applied without additional flags

### 6. Systemd Services Not Enabled (Warning)

**Issue:** Ceph services won't start on boot
**Fix:**
- Enables `ceph.target`
- Ensures auto-start persistence

**Automatic:** Applied without additional flags

## Command Options

### Core Flags

```bash
--fix                  # Apply automated drift corrections
--dry-run             # Preview fixes without applying
--bootstrap-mon       # Bootstrap monitor if never initialized
--permissions-only    # Only fix permissions, not services
```

### Example Workflows

#### 1. Safe Assessment (Recommended First)

```bash
# Step 1: See what's wrong
sudo eos debug ceph

# Step 2: Preview what would be fixed
sudo eos update ceph --fix --dry-run

# Step 3: Apply fixes
sudo eos update ceph --fix
```

#### 2. Monitor Bootstrap Scenario

Your monitor was never initialized:

```bash
# Include monitor bootstrap
sudo eos update ceph --fix --bootstrap-mon
```

#### 3. Service-Only Fixes

You want to fix services but not touch permissions:

```bash
sudo eos update ceph --fix
```

#### 4. Permissions-Only Fixes

You only want permission corrections:

```bash
sudo eos update ceph --fix --permissions-only
```

## How It Works

### 1. Diagnosis Phase

```
Step 1: Running diagnostics to identify issues...
Found 3 critical issue(s) and 1 warning(s)
```

The fix engine:
- Runs full Ceph diagnostics
- Extracts critical issues and warnings
- Categorizes by component (mon, mgr, systemd, etc.)

### 2. Fix Application Phase

```
Step 2: Fixing critical issues...
  [1/3] ceph-mon: Monitor was never bootstrapped
  Creating monitor keyring...
  Initializing monitor database...
  Enabling monitor service...
  Starting monitor service...
  ✓ Successfully bootstrapped and started monitor on vhost5
```

For each issue:
- Applies appropriate fix based on component and description
- Logs every command executed
- Tracks success/failure
- Shows detailed progress

### 3. Verification Phase

```
Step 4: Verifying fixes...
Re-running diagnostics to verify fixes...
✓ Verification passed: No critical issues remaining
```

After fixing:
- Re-runs diagnostics
- Counts remaining critical issues
- Reports success or remaining problems

### 4. Summary

```
Fix Summary
✓ Successfully applied: 3 fix(es)
⊙ Skipped: 0 fix(es)
✗ Failed: 0 fix(es)
```

Shows:
- Successfully applied fixes
- Skipped fixes (not applicable)
- Failed fixes (requires manual intervention)

## Fix Logic Flow

```
┌─────────────────────────────────────────────┐
│  eos update ceph --fix                      │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  1. Run Diagnostics (identify issues)       │
│     - Critical issues                       │
│     - Warnings                              │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  2. Route Issue to Fix Handler              │
│     - ceph-mon → fixMonitor()               │
│     - ceph-mgr → fixManager()               │
│     - ceph → fixGeneral()                   │
│     - systemd → fixSystemd()                │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  3. Apply Fix (ASSESS → INTERVENE)          │
│     - Check current state                   │
│     - Execute commands                      │
│     - Track results                         │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│  4. Verify (EVALUATE)                       │
│     - Re-run diagnostics                    │
│     - Count remaining issues                │
│     - Report status                         │
└─────────────────────────────────────────────┘
```

## Safety Features

### 1. Dry-Run Mode

Preview all fixes before applying:

```bash
sudo eos update ceph --fix --dry-run
```

Output shows:
- Exact commands that would be run
- Which fixes would be applied
- No actual changes made

### 2. Bootstrap Protection

Monitor bootstrap requires explicit flag:

```bash
# This will NOT bootstrap (safe)
sudo eos update ceph --fix

# This WILL bootstrap (explicit)
sudo eos update ceph --fix --bootstrap-mon
```

**Rationale:** Bootstrapping creates a new monitor, which could be destructive if the monitor exists elsewhere.

### 3. Command Logging

Every command executed is logged:

```
DEBUG: Ran: ceph-authtool --create-keyring /tmp/ceph.mon.keyring --gen-key -n mon.
DEBUG: Ran: ceph-mon --mkfs -i vhost5 --keyring /tmp/ceph.mon.keyring
DEBUG: Ran: systemctl enable ceph-mon@vhost5
DEBUG: Ran: systemctl start ceph-mon@vhost5
```

### 4. Post-Fix Verification

After applying fixes, diagnostics re-run automatically to verify success.

## Troubleshooting

### Fix Shows "Skipped"

```
⊙ Bootstrap Ceph Monitor
  → Skipped (use --bootstrap-mon to enable automatic bootstrap)
```

**Solution:** Add the required flag:
```bash
sudo eos update ceph --fix --bootstrap-mon
```

### Fix Failed

```
✗ Start Monitor Service
  Error: failed to start service: Unit not found
```

**Solution:** Check diagnostic details:
```bash
sudo eos debug ceph
```

Then apply manual remediation from diagnostics output.

### Verification Still Shows Issues

```
  Verification: 1 critical issue(s) still remain
  → Some issues may require manual intervention
```

**Common causes:**
- Network configuration issues (check /etc/ceph/ceph.conf)
- Missing Ceph configuration files
- Filesystem permission issues on /var/lib/ceph

**Solution:** Run diagnostics to see remaining issues:
```bash
sudo eos debug ceph
```

### Monitor Bootstrap Fails

**Error:** "Failed to initialize monitor: permission denied"

**Solution:**
```bash
# Check ownership
sudo ls -la /var/lib/ceph/mon/

# Fix if needed
sudo chown -R ceph:ceph /var/lib/ceph/
sudo chmod 750 /var/lib/ceph/mon/
```

## Integration with Diagnostics

The fix engine uses the same diagnostic output as `eos debug ceph`:

| Diagnostic Output | Fix Action |
|------------------|------------|
| "Monitor was never bootstrapped" | Bootstrap monitor (if --bootstrap-mon) |
| "Monitor service is not running" | Start ceph-mon@hostname |
| "Monitor service is not enabled" | Enable ceph-mon@hostname |
| "No Ceph processes running" | Start ceph.target |
| "No manager processes found" | Start ceph-mgr.target |

**See also:** [pkg/ceph/diagnostics.go](diagnostics.go) for issue definitions

## Advanced Usage

### Selective Fixing

Fix only specific types of issues:

```bash
# Only fix permissions (no service changes)
sudo eos update ceph --fix --permissions-only

# Fix services but preview first
sudo eos update ceph --fix --dry-run
```

### Combining with Other Commands

```bash
# 1. Debug to identify issues
sudo eos debug ceph

# 2. Fix critical issues
sudo eos update ceph --fix --bootstrap-mon

# 3. Verify cluster health
sudo ceph status
sudo ceph health detail
```

### CI/CD Integration

For automated deployments:

```bash
#!/bin/bash
# Auto-fix Ceph drift in deployment

# Preview first
if ! sudo eos update ceph --fix --dry-run; then
    echo "ERROR: Dry-run detected issues that can't be fixed"
    exit 1
fi

# Apply fixes
if ! sudo eos update ceph --fix --bootstrap-mon; then
    echo "ERROR: Failed to fix Ceph drift"
    exit 1
fi

# Verify
if ! sudo eos debug ceph | grep -q "No critical issues"; then
    echo "ERROR: Critical issues remain after fixes"
    exit 1
fi

echo "SUCCESS: Ceph drift corrected"
```

## Reference

### Files

- [pkg/ceph/fix.go](fix.go) - Fix engine implementation
- [cmd/update/ceph.go](../../cmd/update/ceph.go) - CLI integration
- [pkg/ceph/diagnostics.go](diagnostics.go) - Issue detection

### Related Commands

- `eos debug ceph` - Detailed diagnostics
- `eos create ceph` - Initial Ceph deployment
- `eos read ceph` - Read Ceph status

### External Documentation

- [Ceph Monitor Bootstrap](https://docs.ceph.com/en/latest/install/manual-deployment/#monitor-bootstrapping)
- [Ceph Services](https://docs.ceph.com/en/latest/rados/operations/)
- [systemd Integration](https://docs.ceph.com/en/latest/cephadm/services/)

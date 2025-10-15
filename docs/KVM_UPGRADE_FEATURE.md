# KVM VM Upgrade Feature

*Last Updated: 2025-10-15*

## Overview

The `eos update kvm-upgrade` command automates the process of upgrading packages inside KVM virtual machines and rebooting them to resolve QEMU version drift.

## The Problem

When you run `sudo apt upgrade` on your Ubuntu hypervisor, you'll often see messages like:

```
VM guests are running outdated hypervisor (qemu) binaries on this host:
 'centos-stream9' with pid 8718
 'eos-kvm-vm-20251003-1604' with pid 2096110
 'eos-kvm-vm-20251003-1613' with pid 2151651
```

This happens because:
1. The host system upgraded QEMU to a newer version
2. Running VMs are still using the old QEMU binaries they were started with
3. VMs need to be restarted to pick up the new QEMU version from the host

## The Solution

`eos update kvm-upgrade` automates the complete upgrade cycle:

1. **Create snapshot** (optional, default: enabled)
2. **Upgrade packages** inside the VM (`apt update && apt upgrade`)
3. **Gracefully reboot** the VM
4. **Verify** QEMU drift is resolved
5. **Cleanup** snapshot (optional)

## Architecture

### New Files Created

```
pkg/kvm/
├── guest_exec.go           # Execute commands via QEMU guest agent
├── package_upgrade.go      # Apt update/upgrade operations
└── upgrade_and_reboot.go   # Full orchestration

cmd/update/
└── kvm.go                  # CLI command (extended)
```

### Component Breakdown

#### 1. `pkg/kvm/guest_exec.go`

Executes commands inside VMs via QEMU guest agent's `guest-exec` API.

**Key Functions:**
- `GuestExecCommand()` - Execute arbitrary command with args
- `GuestExecScript()` - Execute shell script
- Follows **Assess → Intervene → Evaluate** pattern
- Polls for completion with configurable timeout
- Captures stdout/stderr (base64 decoded)
- Detects if guest-exec is disabled

**Safety Features:**
- Checks VM is running
- Verifies guest agent is responsive
- Detects if guest-exec is disabled (with remediation message)
- Timeout protection (default 30min)
- Detailed logging

#### 2. `pkg/kvm/package_upgrade.go`

Manages package upgrades inside VMs.

**Key Functions:**
- `UpgradeVMPackages()` - Full upgrade cycle
- Follows **Assess → Intervene → Evaluate** pattern
- Handles dpkg/apt locks with retry logic
- Parses apt output for package counts
- Detects reboot requirement

**Features:**
- `--dry-run` support
- `--security-only` for Ubuntu security updates
- Auto-remove obsolete packages
- Auto-clean package cache
- Lock detection and retry (with backoff)
- Reboot requirement detection

**Safety Features:**
- Checks dpkg/apt locks before starting
- Retries on transient lock errors (configurable)
- Non-interactive mode (DEBIAN_FRONTEND=noninteractive)
- Rich error context

#### 3. `pkg/kvm/upgrade_and_reboot.go`

Orchestrates the complete upgrade cycle.

**Key Functions:**
- `UpgradeAndRebootVM()` - Single VM full cycle
- `UpgradeAndRebootMultiple()` - Batch processing
- `UpgradeAndRebootVMsWithDrift()` - Auto-detect and upgrade VMs with drift

**Safety Features:**
- Snapshot creation before upgrade (default: enabled)
- Rollback capability via snapshots
- Sequential processing (limits blast radius)
- Rolling upgrades with configurable batch size
- Continue-on-error option
- Comprehensive result tracking

## Usage Examples

### Basic Usage

```bash
# Upgrade and reboot a single VM
sudo eos update kvm-upgrade centos-stream9

# Dry-run to see what would happen
sudo eos update kvm-upgrade centos-stream9 --dry-run
```

### Auto-Detect VMs with Drift

```bash
# Upgrade all VMs with QEMU drift (sequential)
sudo eos update kvm-upgrade --all-drift

# Rolling upgrade (batch size 2, wait 60s between batches)
sudo eos update kvm-upgrade --all-drift --rolling --batch-size=2 --wait-between=60
```

### Advanced Options

```bash
# Just upgrade packages (no reboot)
sudo eos update kvm-upgrade centos-stream9 --skip-reboot

# Just reboot (no package upgrade) - use kvm-restart instead
sudo eos update kvm-restart centos-stream9

# Security updates only
sudo eos update kvm-upgrade --all-drift --security-only

# Skip snapshot (dangerous!)
sudo eos update kvm-upgrade centos-stream9 --no-snapshot

# Delete snapshot after success
sudo eos update kvm-upgrade centos-stream9 --delete-snapshot

# Continue with other VMs if one fails
sudo eos update kvm-upgrade vm1 vm2 vm3 --continue-on-error
```

## Prerequisites

### On Each VM

1. **QEMU Guest Agent** must be installed and running:
   ```bash
   # Ubuntu/Debian
   sudo apt install qemu-guest-agent
   sudo systemctl enable --now qemu-guest-agent

   # CentOS/RHEL
   sudo yum install qemu-guest-agent
   sudo systemctl enable --now qemu-guest-agent
   ```

2. **Guest-exec must be enabled**:
   ```bash
   # Check status
   sudo eos list kvm

   # Enable if disabled
   sudo eos update kvm <vm-name> --enable-guest-exec

   # Enable for all VMs with DISABLED status
   sudo eos update kvm --enable-guest-exec --all-disabled
   ```

## Safety Mechanisms

### Snapshots (Default: Enabled)

Before any upgrade, Eos creates a VM snapshot:

```
Snapshot name: pre-upgrade-20251015-143022
Description:   Automatic snapshot before package upgrade
Type:          Live snapshot (VM stays running)
```

If upgrade fails, the snapshot remains for manual rollback:

```bash
virsh snapshot-revert <vm-name> pre-upgrade-20251015-143022
```

### Lock Detection and Retry

If dpkg/apt is locked (e.g., unattended-upgrades running):

```
Attempt 1/3: dpkg locked, retrying in 30s...
Attempt 2/3: dpkg locked, retrying in 30s...
Attempt 3/3: Success!
```

Configurable via:
- `RetryOnLock` (default: true)
- `LockRetries` (default: 3)
- `LockRetryDelay` (default: 30s)

### Graceful Shutdown

Uses ACPI shutdown with timeout:
1. Send ACPI power button signal
2. Wait up to 5 minutes for graceful shutdown
3. Force shutdown only if timeout exceeded
4. Log all state transitions

### Error Classification

Eos distinguishes between:
- **Transient errors** (retry): network timeouts, locks
- **Deterministic errors** (fail fast): config errors, missing dependencies

### Blast Radius Limitation

Sequential processing by default:
- Process one VM at a time
- Wait for completion before next VM
- Use `--rolling` for controlled batch processing

## Configuration

All operations use sensible defaults with full configurability:

```go
type UpgradeAndRebootConfig struct {
    // Package upgrade
    PackageConfig *PackageUpgradeConfig

    // VM restart
    RestartConfig *RestartConfig

    // Safety
    CreateSnapshot   bool  // default: true
    DeleteSnapshot   bool  // default: false
    KeepSnapshotDays int   // default: 7

    // Control
    DryRun          bool  // default: false
    SkipUpgrade     bool  // default: false
    SkipReboot      bool  // default: false
    ContinueOnError bool  // default: false
}
```

## Output

### Single VM

```
═══════════════════════════════════════
UPGRADE SUMMARY: 1 VM(s) processed
═══════════════════════════════════════
✓ centos-stream9
  Packages upgraded: 23
  Restarted: yes
  QEMU drift: resolved
  Snapshot: pre-upgrade-20251015-143022
  Duration: 5m32s

═══════════════════════════════════════
Success: 1  Failed: 0  Drift Resolved: 1
═══════════════════════════════════════
```

### Multiple VMs

```
═══════════════════════════════��═══════
UPGRADE SUMMARY: 5 VM(s) processed
═══════════════════════════════════════
✓ centos-stream9
  Packages upgraded: 23
  Restarted: yes
  QEMU drift: resolved
  Snapshot: pre-upgrade-20251015-143022
  Duration: 5m32s

✓ eos-kvm-vm-20251003-1604
  Packages upgraded: 15
  Restarted: yes
  QEMU drift: resolved
  Snapshot: pre-upgrade-20251015-143128
  Duration: 4m18s

✗ eos-kvm-vm-20251003-1613
  Error: guest agent not responsive
  Duration: 12s

✓ eos-kvm-vm-20251001-1236
  Packages upgraded: 8
  Restarted: yes
  QEMU drift: resolved
  Snapshot: pre-upgrade-20251015-143402
  Duration: 3m45s

✓ eos-kvm-vm-20251001-1255
  Packages upgraded: 12
  Restarted: yes
  QEMU drift: resolved
  Snapshot: pre-upgrade-20251015-143645
  Duration: 4m02s

═══════════════════════════════════════
Success: 4  Failed: 1  Drift Resolved: 4
═══════════════════════════════════════
```

## Logging

All operations are fully logged with structured logging (zap):

```json
{
  "level": "info",
  "ts": "2025-10-15T14:30:22Z",
  "msg": "Starting upgrade and reboot cycle",
  "vm": "centos-stream9",
  "dry_run": false,
  "create_snapshot": true
}

{
  "level": "info",
  "ts": "2025-10-15T14:30:25Z",
  "msg": "Upgrading packages",
  "vm": "centos-stream9"
}

{
  "level": "info",
  "ts": "2025-10-15T14:35:18Z",
  "msg": "Package upgrade completed",
  "vm": "centos-stream9",
  "packages_upgraded": 23
}

{
  "level": "info",
  "ts": "2025-10-15T14:35:54Z",
  "msg": "Upgrade and reboot cycle completed",
  "vm": "centos-stream9",
  "drift_resolved": true,
  "duration": "5m32s"
}
```

## Error Handling

### Common Errors and Remediation

#### 1. Guest Agent Not Responsive

```
Error: guest agent not responsive - ensure qemu-guest-agent is installed and running

Remediation:
1. SSH into VM
2. Install: sudo apt install qemu-guest-agent
3. Enable: sudo systemctl enable --now qemu-guest-agent
```

#### 2. Guest-exec Disabled

```
Error: guest-exec is disabled - run 'eos update kvm centos-stream9 --enable-guest-exec' first

Remediation:
sudo eos update kvm centos-stream9 --enable-guest-exec
```

#### 3. dpkg/apt Locked

```
Error: dpkg/apt is locked by another process

Remediation (automatic with retry):
Attempt 1/3: dpkg locked, retrying in 30s...
```

#### 4. Package Upgrade Failed

```
Error: apt upgrade failed with exit code 100:
E: Could not get lock /var/lib/dpkg/lock-frontend

Remediation:
- Snapshot remains for rollback
- Check VM logs: virsh console <vm-name>
- Manual rollback: virsh snapshot-revert <vm-name> pre-upgrade-XXX
```

## Implementation Notes

### Assess → Intervene → Evaluate Pattern

All operations follow Eos's AIE pattern:

```go
// Assess: Pre-flight checks
if err := assessUpgradeAndReboot(rc, vmName, cfg); err != nil {
    return nil, err
}

// Intervene: Execute operations
if err := interveneUpgradeAndReboot(rc, vmName, cfg, result); err != nil {
    return nil, err
}

// Evaluate: Verify success
if err := evaluateUpgradeAndReboot(rc, vmName, cfg, result); err != nil {
    return nil, err
}
```

### Idempotency

Operations are designed to be idempotent:
- Snapshots use timestamped names (no conflicts)
- Package upgrades: `apt upgrade` is idempotent
- VM restart: Already restarted = no error

### QEMU Guest Agent Communication

Uses libvirt's QEMU Agent Command API:

```go
cmd := `{"execute":"guest-exec","arguments":{"path":"/bin/bash","arg":["-c","apt update"],"capture-output":true}}`

response, err := domain.QemuAgentCommand(cmd, timeout, 0)
// Parse response, extract PID
// Poll for completion
// Decode base64-encoded stdout/stderr
```

### Base64 Encoding

Guest-exec returns stdout/stderr as base64:

```go
stdout, err := base64.StdEncoding.DecodeString(outData)
stderr, err := base64.StdEncoding.DecodeString(errData)
```

## Testing

### Manual Testing Checklist

On a Linux system with KVM:

1. **Build Eos:**
   ```bash
   go build -o /tmp/eos ./cmd/
   ```

2. **Create test VM** (if needed):
   ```bash
   sudo /tmp/eos create kvm-tenant
   ```

3. **Enable guest-exec:**
   ```bash
   sudo /tmp/eos update kvm <vm-name> --enable-guest-exec
   ```

4. **Dry-run upgrade:**
   ```bash
   sudo /tmp/eos update kvm-upgrade <vm-name> --dry-run
   ```

5. **Real upgrade:**
   ```bash
   sudo /tmp/eos update kvm-upgrade <vm-name>
   ```

6. **Verify drift resolved:**
   ```bash
   sudo /tmp/eos list kvm | grep -i drift
   ```

7. **Batch upgrade:**
   ```bash
   sudo /tmp/eos update kvm-upgrade --all-drift --rolling --batch-size=2
   ```

### Test Scenarios

- [ ] Single VM upgrade (Ubuntu)
- [ ] Single VM upgrade (CentOS)
- [ ] Multiple VMs upgrade
- [ ] Rolling upgrade with batches
- [ ] Dry-run mode
- [ ] Skip upgrade (reboot only)
- [ ] Skip reboot (upgrade only)
- [ ] Security updates only
- [ ] Snapshot creation/deletion
- [ ] Error handling (guest agent down)
- [ ] Error handling (dpkg locked)
- [ ] Continue on error

## Future Enhancements

### Phase 2 (Possible)

1. **Critical Service Detection**
   - Auto-detect Consul, Vault, Nomad, etc.
   - Warn before restarting critical VMs
   - Graceful service handoff

2. **Parallel Upgrades**
   - Safe parallel processing
   - Dependency-aware ordering
   - Resource contention avoidance

3. **Smart Snapshot Cleanup**
   - Auto-delete snapshots after N days
   - Keep only latest N snapshots
   - Snapshot size monitoring

4. **Health Checks**
   - Post-reboot health verification
   - Service status checks
   - Automatic rollback on failure

5. **Schedule Support**
   - Cron-based scheduling
   - Maintenance windows
   - Email notifications

## Relation to Existing Commands

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `eos update kvm` | Rescue mode (virt-rescue shell) | Manual troubleshooting |
| `eos update kvm --enable-guest-exec` | Enable guest-exec | One-time prerequisite |
| `eos update kvm-restart` | Just reboot VMs | No package upgrade needed |
| `eos update kvm-upgrade` | **Full upgrade cycle** | Resolve QEMU drift |
| `eos list kvm` | Show VM status | Check for drift |

## References

- Eos Architecture: [CLAUDE.md](./CLAUDE.md)
- Pattern Documentation: [docs/PATTERNS.md](./docs/PATTERNS.md)
- QEMU Guest Agent: https://wiki.qemu.org/Features/GuestAgent
- Libvirt Go Bindings: https://libvirt.org/go/libvirt.html

---

*"Solve problems once, encode in Eos, never solve again."*

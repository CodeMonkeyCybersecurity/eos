# KVM Feature Testing Guide

** CRITICAL: DO NOT TEST ON PRODUCTION VMs WITHOUT BACKUPS**

## Pre-Testing Requirements

### 1. Test Environment Setup
```bash
# Create a disposable test VM first
eos create ubuntu-vm --name test-kvm-features --memory 2048 --vcpus 2

# Verify it works
ssh test-kvm-features
```

### 2. Verify Libvirt Installation
```bash
# Check libvirt is installed
pkg-config --exists libvirt && echo "OK" || echo "MISSING"

# Check version
pkg-config --modversion libvirt

# Verify connection
virsh list --all
```

### 3. Build with Libvirt Support
```bash
# On Linux with libvirt-dev installed:
CGO_ENABLED=1 go build -tags libvirt -o eos .

# Verify build includes libvirt
./eos list kvm 2>&1 | grep -q "libvirt support" || echo "Libvirt enabled"
```

## Testing Checklist

### Phase 1: Read-Only Operations (Low Risk)

- [ ] **List VMs**
  ```bash
  eos list kvm
  eos list kvm --format=json
  eos list kvm --show-drift
  eos list kvm --state=running
  ```
  Expected: No errors, matches `virsh list --all`

- [ ] **Drift Detection**
  ```bash
  eos list kvm --show-drift
  ```
  Expected: Correctly identifies VM vs host QEMU versions

- [ ] **IP Detection**
  ```bash
  eos list kvm --detailed
  ```
  Expected: Shows VM IP addresses (may take 3s retry)

### Phase 2: Non-Destructive State Changes (Medium Risk)

- [ ] **VM State Query**
  ```bash
  # Should work without errors
  for vm in $(virsh list --name); do
    echo "Checking $vm..."
    eos list kvm --state=running | grep -q "$vm"
  done
  ```

### Phase 3: Snapshot Operations (CRITICAL - Test First!)

** SNAPSHOT ROLLBACK IS UNTESTED - VERIFY BEFORE PRODUCTION**

- [ ] **Create Snapshot Manually**
  ```bash
  # Test snapshot creation
  virsh snapshot-create-as test-kvm-features test-snapshot-1 "Test snapshot"
  virsh snapshot-list test-kvm-features
  ```

- [ ] **Test Rollback Path**
  ```bash
  # Shutdown the test VM
  virsh shutdown test-kvm-features

  # Wait for shutdown
  while virsh list --state-running | grep -q test-kvm-features; do
    sleep 1
  done

  # Revert to snapshot
  virsh snapshot-revert test-kvm-features test-snapshot-1

  # Verify VM state
  virsh domstate test-kvm-features
  ```

- [ ] **Test Eos Snapshot Creation**
  ```bash
  # Create test file in VM first
  ssh test-kvm-features "echo 'test data' > /tmp/testfile"

  # Restart with snapshot (DO NOT USE --no-safe)
  eos restart kvm-restart test-kvm-features --snapshot --timeout=300

  # Verify snapshot was created
  virsh snapshot-list test-kvm-features | grep "pre-restart-"
  ```

### Phase 4: VM Restart Operations (HIGH RISK)

** ONLY ON TEST VMs - NOT PRODUCTION**

- [ ] **Single VM Restart**
  ```bash
  # Restart test VM with all safety checks
  eos restart kvm-restart test-kvm-features --snapshot --timeout=300

  # Verify:
  # 1. VM shut down gracefully (check logs)
  # 2. VM started successfully
  # 3. Network connectivity restored
  # 4. Snapshot created
  ```

- [ ] **Restart Failure Handling**
  ```bash
  # Test what happens if restart fails
  # Manually break something (e.g., remove VM disk temporarily)
  mv /var/lib/libvirt/images/test-kvm-features.qcow2 /tmp/

  # Try restart with snapshot
  eos restart kvm-restart test-kvm-features --snapshot --timeout=60

  # Should rollback to snapshot
  # Restore disk and verify VM is in snapshot state
  mv /tmp/test-kvm-features.qcow2 /var/lib/libvirt/images/
  virsh start test-kvm-features
  ```

### Phase 5: Bulk Operations (VERY HIGH RISK)

** NEVER RUN ON PRODUCTION WITHOUT TESTING ON DISPOSABLE VMs FIRST**

- [ ] **Multiple VM Restart**
  ```bash
  # Create 3 test VMs
  for i in 1 2 3; do
    eos create ubuntu-vm --name test-multi-$i --memory 1024 --vcpus 1
  done

  # Test rolling restart
  eos restart kvm-restart test-multi-1 test-multi-2 test-multi-3 \
    --rolling --batch-size=1 --wait-between=10 --snapshot

  # Verify all VMs restarted successfully
  for i in 1 2 3; do
    virsh domstate test-multi-$i
  done
  ```

- [ ] **Drift-Based Restart**
  ```bash
  # Only test if you have VMs with actual drift
  eos restart kvm-restart --all-drift --rolling --batch-size=2
  ```

## Known Issues to Watch For

### 1. IP Detection
- May show "N/A" for up to 3 seconds after VM start
- Requires ARP cache or DHCP lease - may fail if neither available
- Only shows primary interface IP

### 2. Guest Agent
- Always reports "NO" (conservative)
- Cannot detect guest agent reliably without platform-specific APIs
- Verify manually: `virsh qemu-agent-command <vm> '{"execute":"guest-ping"}'`

### 3. Snapshot Rollback
- **UNTESTED IN PRODUCTION**
- May not work correctly on first try
- Always verify snapshot exists before relying on rollback
- Manual verification: `virsh snapshot-list <vm>`

### 4. State Race Conditions
- VM state can change between check and action
- Errors like "domain is already running" are handled gracefully
- May need retry logic for concurrent operations

## Failure Scenarios to Test

### Scenario 1: Network Timeout During Shutdown
```bash
# Set very short timeout
eos restart kvm-restart test-kvm-features --timeout=5

# If VM takes longer to shut down:
# - Should force shutdown after timeout
# - Should log warning
# - Should still attempt to start VM
```

### Scenario 2: Missing libvirt Connection
```bash
# Stop libvirtd
sudo systemctl stop libvirtd

# Try Eos command
eos list kvm

# Should show clear error, not crash
```

### Scenario 3: Corrupted VM State
```bash
# Manually corrupt VM XML
virsh dumpxml test-kvm-features > /tmp/backup.xml
virsh edit test-kvm-features # Add invalid XML

# Try Eos operations
eos list kvm
eos restart kvm-restart test-kvm-features

# Restore
virsh define /tmp/backup.xml
```

## Performance Benchmarks

Expected timing for various operations:

| Operation | Expected Time | Timeout |
|-----------|--------------|---------|
| List all VMs | <2s | N/A |
| Get VM state | <1s | N/A |
| VM shutdown (ACPI) | 10-30s | 5min default |
| VM start | 5-15s | 5min default |
| IP detection | 0-3s | 3s (3 retries) |
| Snapshot creation | 1-5s | N/A |
| Snapshot rollback | 2-10s | N/A |

## Before Production Deployment

- [ ] All Phase 1-3 tests pass
- [ ] Phase 4 tested on multiple disposable VMs
- [ ] Snapshot rollback verified to work
- [ ] IP detection reliable for your network setup
- [ ] Timing appropriate for your VM sizes
- [ ] Tested with actual production VM configuration (but not prod VMs!)
- [ ] Backups of all production VMs
- [ ] Maintenance window scheduled
- [ ] Rollback plan documented

## Emergency Rollback

If something goes wrong during production use:

```bash
# 1. Stop all Eos operations (Ctrl+C)

# 2. Check VM states
virsh list --all

# 3. Manually start critical VMs
for vm in critical-vm-1 critical-vm-2; do
  virsh start $vm
done

# 4. If snapshot exists, revert
virsh snapshot-list <vm>
virsh snapshot-revert <vm> <snapshot-name>

# 5. Report issue with full logs
eos list kvm --detailed > /tmp/eos-state.log
virsh list --all >> /tmp/eos-state.log
journalctl -u libvirtd -n 100 >> /tmp/eos-state.log
```

## Contact for Issues

- GitHub Issues: https://github.com/CodeMonkeyCybersecurity/eos/issues
- Include full error output and system info
- Attach `/tmp/eos-state.log` if available

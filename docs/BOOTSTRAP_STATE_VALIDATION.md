# Bootstrap State Validation Architecture

*Last Updated: 2025-01-27*

## Overview

The Eos bootstrap system now uses **state-based validation** instead of arbitrary marker files. This ensures the bootstrap is truly complete by verifying actual system state rather than relying on the presence of checkpoint files.

## Key Improvements

### 1. **State-Based Validation**
Instead of checking for marker files like `/opt/eos/.bootstrapped`, the system now validates:
- Salt is installed and running (`salt-minion` service active)
- Salt API is configured and responding (`eos-salt-api` service active)
- API health endpoint responds correctly
- File roots are properly configured
- All required services are operational

### 2. **Adaptive Bootstrap**
The bootstrap process now:
- Detects what's actually missing
- Skips phases that are already complete
- Only performs necessary operations
- Validates success through system state

### 3. **Intelligent Phase Completion**
Each phase has a validator that checks actual system state:

```go
PhaseValidators = map[string]PhaseValidator{
    "salt":     validateSaltPhase,      // Checks Salt services
    "salt-api": validateSaltAPIPhase,   // Checks API service & endpoints
    "storage":  validateStoragePhase,   // Checks storage setup
    // ... etc
}
```

### 4. **No More False Positives**
The system cannot be in a state where:
- Marker files exist but services aren't running
- Bootstrap appears complete but components are missing
- Manual intervention is required to fix incomplete states

## How It Works

### Phase Validation Example: Salt API
```go
func validateSaltAPIPhase(rc *eos_io.RuntimeContext) (bool, error) {
    // Check if API service is running
    status, err := CheckService(rc, "eos-salt-api")
    if err != nil || status != ServiceStatusActive {
        return false, nil
    }
    
    // Check if API responds to health check
    if !checkSaltAPIConfigured(rc) {
        return false, nil
    }
    
    return true, nil
}
```

### Bootstrap Flow
1. **Assessment**: Check actual state of each component
2. **Detection**: Identify what's missing or not running
3. **Action**: Only perform necessary operations
4. **Validation**: Verify through system state, not files

## User Experience

### Before (File-Based)
```
$ sudo eos create consul
ERROR: System is not bootstrapped
(Even though Salt was installed, just API was missing)

$ sudo eos bootstrap
System is already bootstrapped
(Because marker file existed)
```

### After (State-Based)
```
$ sudo eos create consul
ERROR: System bootstrap is incomplete!
The following components are missing or not running:
  ✗ Salt API service is not configured or not running

$ sudo eos bootstrap
Bootstrap incomplete - missing components detected: [salt-api]
Continuing bootstrap to complete setup...
Phase 1/2: Installing and configuring SaltStack
Phase already completed, skipping
Phase 2/2: Setting up Salt API service
✓ Completed: Setting up Salt API service
Bootstrap completed successfully
```

## Benefits

1. **Self-Healing**: Incomplete bootstraps are automatically detected and fixed
2. **Accurate Status**: Always reflects actual system state
3. **No Manual Cleanup**: No need to remove marker files or force re-runs
4. **Idempotent**: Safe to run multiple times, only does what's needed
5. **Clear Feedback**: Users know exactly what's missing

## Implementation Details

### Required Phases
Only two phases are mandatory for basic operation:
- `salt`: Configuration management system
- `salt-api`: API for service deployments

### Optional Phases
- `storage`: Storage operations monitoring
- `tailscale`: VPN connectivity
- `osquery`: System monitoring
- `hardening`: Security hardening

### Validation Hierarchy
1. Service running (`systemctl is-active`)
2. Port responding (for network services)
3. API health check (for API services)
4. Functional test (actual operation works)

## Troubleshooting

### If Bootstrap Still Shows Complete But Services Don't Work

1. **Check Service Status**:
   ```bash
   sudo systemctl status salt-minion
   sudo systemctl status eos-salt-api
   ```

2. **Check Validation**:
   ```bash
   # The bootstrap will show exactly what's missing
   sudo eos bootstrap
   ```

3. **Force Complete Re-run**:
   ```bash
   sudo eos bootstrap --force
   ```

### Common Issues Automatically Fixed

- Salt installed but API missing
- Services installed but not running
- Configuration files missing
- Permissions incorrect
- Network ports not accessible

## Future Enhancements

- Add functional tests for each phase
- Implement repair actions for common failures
- Add progress persistence for interrupted bootstraps
- Support partial phase completion tracking
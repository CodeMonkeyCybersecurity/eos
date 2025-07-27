# Bootstrap System Improvements

*Last Updated: 2025-01-27*

## Overview

The Eos bootstrap system has been enhanced to ensure Salt and Salt API are always set up together as part of the default bootstrap process. This addresses the issue where systems could have Salt installed but lack the API component, preventing service deployments.

## Key Improvements

### 1. **Mandatory Salt API Setup**
- Salt API is now marked as `Required: true` in the bootstrap phases
- The API setup is no longer optional - it's an essential component for Eos operations
- Both Salt and Salt API are installed and configured in a single, comprehensive process

### 2. **Comprehensive Salt Bootstrap (`salt_bootstrap.go`)**
The new `BootstrapSaltComplete` function provides:

- **Prerequisites Validation**:
  - Ubuntu version check (minimum 20.04)
  - Root access verification
  - Disk space requirements (minimum 1GB)
  - Network connectivity testing

- **Intelligent Installation**:
  - Detects if Salt is already installed
  - Configures based on deployment type (single-node, master, or minion)
  - Handles both new installations and existing Salt setups

- **Proper Configuration**:
  - Creates all necessary directories
  - Sets up file roots and pillar roots
  - Configures symlinks for Eos states
  - Applies appropriate master/minion configurations

- **Service Management**:
  - Ensures correct services are running (master and/or minion)
  - Uses retry logic for service startup
  - Provides detailed error diagnostics

### 3. **Enhanced Salt API Setup**
The `SetupSaltAPI` function now includes:

- **Idempotency Checks**:
  - Detects if API is already configured and running
  - Skips setup if everything is working
  - Prevents duplicate installations

- **Automatic Script Creation**:
  - Creates a minimal API script if missing
  - Provides health check endpoints
  - Ensures the API can start successfully

- **Comprehensive Verification**:
  - Checks service status
  - Verifies API responds on port 5000
  - Tests actual API endpoints

### 4. **Fixed Bootstrap Checks**
The `checkSaltAPIConfigured` function now:

- Looks for the correct service name (`eos-salt-api`)
- Checks the correct port (5000 instead of 8000)
- Falls back to standard `salt-api` for compatibility
- Removes dependency on API credentials file

## Usage

### Complete Bootstrap (Recommended)
```bash
sudo eos bootstrap
```

This will:
1. Validate system prerequisites
2. Install and configure Salt (if needed)
3. Set up Salt API service
4. Configure file roots and states
5. Verify everything is working
6. Mark system as bootstrapped

### Salt-Only Bootstrap
```bash
sudo eos bootstrap salt
```

This runs just the Salt and Salt API setup phases.

## Safety Features

### Idempotency
- All operations can be run multiple times safely
- Existing configurations are preserved
- Services are only restarted if necessary

### Error Recovery
- Retry logic for transient failures
- Detailed error messages for troubleshooting
- Automatic recovery attempts for known issues

### Validation
- Each phase verifies success before proceeding
- Comprehensive prerequisite checks
- Service availability verification

## Troubleshooting

### If Bootstrap Fails

1. **Check Prerequisites**:
   ```bash
   # Verify Ubuntu version
   lsb_release -rs
   
   # Check disk space
   df -h /
   
   # Test network
   ping -c 1 github.com
   ```

2. **Check Service Status**:
   ```bash
   sudo systemctl status salt-master
   sudo systemctl status salt-minion
   sudo systemctl status eos-salt-api
   ```

3. **View Logs**:
   ```bash
   sudo journalctl -u salt-master -n 50
   sudo journalctl -u salt-minion -n 50
   sudo journalctl -u eos-salt-api -n 50
   ```

4. **Manual API Start**:
   ```bash
   # If API fails to start
   sudo python3 /opt/eos/salt/api/cluster_api.py
   ```

### Common Issues

1. **"Salt API is not configured"**
   - Run `sudo eos bootstrap` to complete setup
   - Check if `eos-salt-api` service exists

2. **"Port 5000 already in use"**
   - Check what's using the port: `sudo lsof -i :5000`
   - Stop conflicting service or change API port

3. **"Python dependencies missing"**
   - The bootstrap will install them automatically
   - Manual install: `sudo apt-get install python3-flask python3-yaml`

## Architecture Notes

The bootstrap system follows Eos architectural principles:

- **Assess → Intervene → Evaluate**: Each phase checks prerequisites, performs actions, and verifies success
- **Modular Design**: Salt and Salt API setup are separate but coordinated phases
- **Comprehensive Logging**: All operations are logged with structured logging
- **Error Handling**: User-friendly errors with actionable messages

## Future Enhancements

- Support for custom Salt configurations
- Automated SSL certificate generation for API
- Integration with external Salt masters
- Support for Salt SSH mode
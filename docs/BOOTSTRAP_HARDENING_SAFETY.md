# Bootstrap Hardening Safety Guide

*Last Updated: 2025-01-25*

## Overview

The `eos bootstrap` command includes Ubuntu security hardening as part of its standard workflow. This document explains the safety mechanisms and best practices.

## Current Implementation

Ubuntu hardening is integrated into Phase 5 of the bootstrap process:

```bash
eos bootstrap              # Includes hardening by default
eos bootstrap --skip-hardening  # Skip hardening if needed
```

## Safety Mechanisms

### 1. User Consent
- Users are prompted before applying FIDO2 hardening
- Clear explanation of what will be disabled
- Option to apply basic hardening without FIDO2

### 2. Non-Breaking Design
- Hardening failures don't fail the entire bootstrap
- Core infrastructure is set up first
- Hardening is one of the last steps

### 3. Clear Warnings
```
IMPORTANT: You must run 'eos-enroll-fido2' to enroll your FIDO2 keys for SSH
WARNING: Do not close your current SSH session until you've enrolled your keys!
```

### 4. Escape Options
- `--skip-hardening` flag for environments where hardening isn't appropriate
- Choice between FIDO2 and non-FIDO2 hardening

## Enhanced Safety Checks (Optional)

If you want additional safety, you can enable pre-hardening checks:

### Integration Code

```go
// In bootstrap_enhanced.go, before hardening section:

// Perform safety checks
if !skipHardening {
    logger.Info("Running pre-hardening safety checks")
    if err := bootstrap.PerformHardeningSafetyChecks(rc); err != nil {
        logger.Error("Safety checks failed", zap.Error(err))
        logger.Info("Skipping hardening due to safety concerns")
        skipHardening = true
    } else {
        // Create backup before hardening
        if err := bootstrap.CreateHardeningBackup(rc); err != nil {
            logger.Warn("Failed to create hardening backup", zap.Error(err))
        }
    }
}
```

### What the Safety Checks Verify

1. **SSH Session Stability**
   - Ensures you're in an interactive SSH session
   - Prevents hardening from non-interactive scripts

2. **Sudo Access**
   - Verifies passwordless sudo is configured
   - Prevents lockout if sudo requires password

3. **Backup Access Methods**
   - Looks for console access
   - Checks for recovery users
   - Detects IPMI/iDRAC

4. **SSH Keys**
   - Verifies authorized_keys exists
   - Counts valid SSH keys
   - Ensures you won't be locked out

5. **Pre-Hardening Backup**
   - Backs up critical files
   - Creates restore script
   - Stored in `/root/eos-hardening-backup-*`

## Recovery Procedures

### If Locked Out After Hardening

1. **Use Console Access**
   ```bash
   # Boot into single-user mode
   # Mount root filesystem read-write
   mount -o remount,rw /
   
   # Restore SSH config
   cp /root/eos-hardening-backup-*/sshd_config /etc/ssh/
   systemctl restart sshd
   ```

2. **Use Recovery Script**
   ```bash
   # If you have console access
   /root/eos-hardening-backup-*/restore.sh
   ```

3. **Emergency SSH Config**
   ```bash
   # Create minimal SSH config
   cat > /etc/ssh/sshd_config.emergency <<EOF
   Port 22
   PermitRootLogin yes
   PasswordAuthentication yes
   PubkeyAuthentication yes
   EOF
   
   # Use emergency config
   sshd -f /etc/ssh/sshd_config.emergency -p 2222
   ```

## Best Practices

### Before Running Bootstrap

1. **Ensure Multiple Access Methods**
   - Have console access (physical or virtual)
   - Configure IPMI/iDRAC if available
   - Have a second SSH session open

2. **Verify SSH Keys**
   ```bash
   # Check your SSH keys are in place
   cat ~/.ssh/authorized_keys
   
   # Test key-based login works
   ssh -o PasswordAuthentication=no localhost
   ```

3. **Configure Passwordless Sudo**
   ```bash
   # Add to sudoers (via visudo)
   username ALL=(ALL) NOPASSWD:ALL
   ```

### During Bootstrap

1. **Keep Current Session Open**
   - Don't close your SSH session
   - Open a second terminal for testing

2. **Test Before Proceeding**
   ```bash
   # After hardening, before closing session
   # In a NEW terminal:
   ssh user@server
   
   # Verify sudo still works
   sudo -n true
   ```

3. **Enroll FIDO2 Keys Immediately**
   ```bash
   # If you chose FIDO2 hardening
   eos-enroll-fido2
   ```

## Hardening Levels

### Basic Hardening (No FIDO2)
- Disables root SSH login
- Enforces key-based authentication
- Password authentication remains enabled
- Suitable for environments without hardware keys

### Full Hardening (With FIDO2)
- All basic hardening features
- Requires FIDO2/YubiKey for SSH
- Disables password authentication completely
- Maximum security for production environments

## Troubleshooting

### "Cannot proceed with hardening: X critical checks failed"
- Review the specific failures
- Fix the issues (add SSH keys, configure sudo, etc.)
- Re-run bootstrap

### "SSH session lost during hardening"
- Use console access
- Run the restore script
- Check `/var/log/auth.log` for issues

### "FIDO2 enrollment failed"
- Ensure your key is plugged in
- Check USB permissions: `ls -la /dev/hidraw*`
- Try: `sudo chmod 666 /dev/hidraw*`

## Summary

The current bootstrap implementation is already quite safe:
- Asks for consent
- Provides clear warnings
- Doesn't break on failure
- Offers skip option

For maximum safety in production:
1. Have console access ready
2. Test in staging first
3. Keep the `--skip-hardening` option for initial setup
4. Apply hardening as a separate step after verification
# Ubuntu Hardening with FIDO2 SSH Authentication

*Last Updated: 2025-01-20*

## Overview

The Eos Ubuntu hardening system has been updated to use FIDO2/YubiKey hardware authentication for SSH access instead of traditional 2FA for sudo operations. This provides stronger security for remote access while simplifying local administrative tasks.

## Key Changes

### Removed Features
- Google Authenticator PAM module for sudo/root access
- TOTP/OTP requirements for sudo operations
- MFA enforcement for local administrative tasks

### Added Features
- FIDO2/YubiKey requirement for SSH authentication
- Hardware-based security key support
- Enrollment tool for FIDO2 keys
- Comprehensive recovery procedures

## Usage

### Basic Hardening Command
```bash
# Apply full Ubuntu hardening with FIDO2 SSH
sudo eos update ubuntu

# Skip FIDO2 configuration (keep existing SSH settings)
sudo eos update ubuntu --skip-fido2
```

### Bootstrap Integration
The hardening is now automatically applied during bootstrap:
```bash
# Bootstrap with hardening (default)
eos bootstrap

# Bootstrap without hardening
eos bootstrap --skip-hardening
```

### FIDO2 Key Enrollment
After hardening is applied, users must enroll their FIDO2 keys:
```bash
# Run as regular user (not root)
eos-enroll-fido2
```

This will:
1. Generate an SSH key pair bound to your FIDO2 device
2. Register the key for PAM authentication
3. Display the public key to add to authorized_keys

## Security Features

### System Hardening (Unchanged)
- Kernel security parameters
- Disabled rare network protocols
- File permission hardening
- Core dump restrictions
- Security monitoring tools (auditd, osquery, AIDE, etc.)

### SSH Security
- Password authentication disabled
- FIDO2 hardware key required
- Public key + hardware token authentication
- Maximum 3 authentication attempts
- Automatic connection timeout

## Recovery Procedures

### Emergency Access Options

1. **Physical Console**: Always available for local access
2. **Emergency Account**: Create with traditional SSH key
3. **Backup FIDO2 Keys**: Register multiple keys for redundancy
4. **Temporary Disable**: Remove `/etc/ssh/sshd_config.d/99-eos-fido2.conf` via console

### Best Practices

1. **Always enroll at least 2 FIDO2 keys**
   - Primary key for daily use
   - Backup key in secure location

2. **Test immediately after setup**
   - Don't close existing SSH session until verified
   - Test from another terminal/machine

3. **Document enrolled keys**
   - Keep record of which keys are enrolled
   - Note serial numbers for inventory

## Troubleshooting

### SSH Connection Issues
```bash
# Check SSH service
sudo systemctl status sshd
sudo journalctl -u sshd -f

# Verify FIDO2 key detection
ssh -vvv user@host

# Check PAM authentication
sudo pamtester sshd username authenticate
```

### Enrollment Problems
```bash
# Verify packages installed
dpkg -l | grep -E 'libpam-u2f|pamu2fcfg|yubikey-manager'

# Check U2F mappings
sudo cat /etc/u2f_mappings

# Test key detection
pamu2fcfg -u $USER
```

## Technical Details

### Configuration Files
- `/etc/ssh/sshd_config.d/99-eos-fido2.conf` - SSH FIDO2 configuration
- `/etc/pam.d/sshd` - PAM configuration for SSH
- `/etc/u2f_mappings` - FIDO2 key mappings
- `/usr/local/bin/eos-enroll-fido2` - Enrollment script
- `/etc/ssh/FIDO2_RECOVERY.md` - Recovery documentation

### Requirements
- OpenSSH 8.2+ (for sk- key support)
- libpam-u2f package
- FIDO2-compatible hardware key

## Migration from Old System

For systems previously using Google Authenticator for sudo:
1. The old MFA configuration is automatically removed
2. Sudo access returns to password-only authentication
3. SSH access now requires FIDO2 keys
4. Users must enroll FIDO2 keys before losing physical access

## Security Rationale

This approach provides:
- **Stronger authentication**: Hardware keys cannot be phished or copied
- **Better UX**: No need to enter OTP codes for every sudo command
- **Focus on perimeter**: Secure the entry point (SSH) rather than every command
- **Compliance**: Meets modern security standards for remote access
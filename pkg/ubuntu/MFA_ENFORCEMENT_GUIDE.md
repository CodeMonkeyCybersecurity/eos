# Ubuntu MFA Enforcement Guide

## Overview

Eos now implements **enforced Multi-Factor Authentication (MFA)** by default for all sudo and root access on Ubuntu systems. This provides safe, high-quality and effective security while maintaining usability through guided setup and graceful enforcement options.

##  Default Behavior

**By default, `eos secure ubuntu` now:**
1. **Guides users through MFA setup interactively**
2. **Enforces MFA for all sudo operations**  
3. **Provides emergency access procedures**
4. **Offers 24-hour grace period for setup**

##  Command Options

### Basic Usage
```bash
# Default: Enforced MFA with interactive setup
sudo eos secure ubuntu

# Full hardening with enforced MFA (explicit)
sudo eos secure ubuntu --enforce-mfa

# Standard MFA (allows password fallback)
sudo eos secure ubuntu --enable-mfa

# Skip MFA entirely (not recommended)
sudo eos secure ubuntu --no-mfa
```

### MFA-Only Operations
```bash
# Configure only enforced MFA (no full hardening)
sudo eos secure ubuntu --enforce-mfa --mfa-only

# Configure only standard MFA
sudo eos secure ubuntu --enable-mfa --mfa-only

# Disable MFA
sudo eos secure ubuntu --disable-mfa --mfa-only
```

##  Interactive Setup Process

When you run `eos secure ubuntu`, you'll be guided through:

### 1. System Hardening
- auditd configuration
- osquery installation  
- AIDE file integrity monitoring
- fail2ban brute force protection
- Automatic security updates
- Kernel hardening

### 2. MFA Configuration Prompt
```
 MANDATORY MFA SETUP REQUIRED
═══════════════════════════════════════════════════════════════════════

  Multi-Factor Authentication (MFA) must be configured for secure
   sudo and root access on this system.

This setup will:
  • Generate a unique secret for your account
  • Display a QR code for your mobile authenticator app
  • Create emergency backup codes
  • Test the configuration

Proceed with MFA setup now? (Y/n):
```

### 3. QR Code Display
- Shows QR code for easy mobile app setup
- Supports Google Authenticator, Authy, Microsoft Authenticator, etc.
- Generates 5 emergency backup codes

### 4. Configuration Test
- Tests MFA setup before enforcement
- Allows reconfiguration if test fails
- Provides troubleshooting guidance

### 5. Enforcement Mode Selection
```
 Enforcement Options:

1. Graceful Mode (recommended): Allow password fallback during transition
2. Strict Mode: Require MFA immediately (no password fallback)

Choose enforcement mode (1/2):
```

##  Available Commands

After setup, these commands are available:

### User Commands
```bash
# Check MFA status for current user
mfa-status

# Configure MFA for current user
setup-mfa

# View comprehensive security report  
security-report
```

### Administrative Commands
```bash
# Enable strict MFA enforcement (removes password fallback)
sudo enforce-mfa-strict

# Emergency MFA disable (admin only)
sudo disable-mfa-emergency
```

##  Enforcement Modes

### Graceful Mode (Default)
- **Password fallback allowed** during transition period
- **24-hour grace period** for user setup
- **Automatic transition** to strict mode (optional)
- **Recommended for gradual deployment**

**PAM Configuration:**
```
auth       sufficient pam_unix.so
auth       sufficient pam_google_authenticator.so nullok
```

### Strict Mode
- **MFA required immediately** for all sudo operations
- **No password fallback** allowed
- **Maximum security** but requires all users to have MFA configured
- **Emergency access** via `disable-mfa-emergency`

**PAM Configuration:**
```
auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
```

##  Supported Authenticator Apps

- **Google Authenticator** (iOS/Android)
- **Microsoft Authenticator** (iOS/Android) 
- **Authy** (iOS/Android/Desktop)
- **1Password** (with TOTP support)
- **Bitwarden** (with TOTP support)
- **LastPass Authenticator**
- **Any RFC 6238 TOTP-compatible app**

## 🆘 Emergency Access

### If MFA fails:
1. **Use backup codes** (generated during setup)
2. **Emergency disable script**: `sudo disable-mfa-emergency` 
3. **Physical access**: Boot to single-user mode
4. **Recovery via root session** (if available)

### Backup Code Usage:
```bash
# When prompted for MFA code, enter a backup code instead
sudo command
Password: [your-password]
Verification code: [backup-code]
```

##  Monitoring and Status

### Check MFA Status
```bash
mfa-status
```

Output example:
```
 MFA Status Report for username
============================================================================
 User MFA Configuration: CONFIGURED
   Secret file: /home/username/.google_authenticator
   Last modified: 2024-01-15 10:30:00

 PAM Configuration Status:
 sudo MFA: ENFORCED (strict mode)
 su MFA: ENFORCED (strict mode)

⚖️ Enforcement Policy:
 MFA Enforcement: ACTIVE
   Enforced on: Mon Jan 15 10:30:00 UTC 2024
   Enforced by: admin
```

### Security Report
```bash
security-report
```

Provides comprehensive security analysis including:
- MFA configuration status
- System hardening status  
- Security tool status
- Recent authentication activity
- Recommendations

##  Migration from Standard MFA

If you have existing standard MFA setup:

### Upgrade to Enforced MFA:
```bash
sudo eos secure ubuntu --enforce-mfa --mfa-only
```

### Downgrade to Standard MFA:
```bash  
sudo eos secure ubuntu --enable-mfa --mfa-only
```

##  Security Best Practices

### For Administrators:
1. **Test MFA setup** in development environment first
2. **Ensure emergency access** procedures are documented
3. **Train users** on MFA setup and backup codes
4. **Monitor failed authentication** attempts
5. **Regular security audits** with `security-report`

### For Users:
1. **Secure backup codes** in password manager or safe location
2. **Test authenticator app** setup before closing setup session
3. **Sync device time** to avoid code synchronization issues  
4. **Have multiple devices** configured if possible
5. **Report issues immediately** to prevent lockouts

##  Troubleshooting

### Common Issues:

#### "Verification code incorrect"
- **Check device time synchronization**
- **Wait for next code** (codes change every 30 seconds)
- **Try backup code** if available
- **Reconfigure MFA** if persistent

#### "Permission denied" 
- **Check PAM configuration**: `cat /etc/pam.d/sudo`
- **Verify MFA package**: `dpkg -l libpam-google-authenticator`
- **Check user MFA file**: `ls -la ~/.google_authenticator`

#### "Emergency access needed"
```bash
# Method 1: Use emergency script
sudo disable-mfa-emergency

# Method 2: Manual PAM restoration  
sudo cp /etc/pam.d/sudo.backup-before-mfa /etc/pam.d/sudo

# Method 3: Single-user mode
# Boot with init=/bin/bash, mount -o remount,rw /, restore PAM
```

### Log Analysis:
```bash
# Check authentication logs
sudo journalctl -u sudo --since "1 hour ago"

# Check system logs for PAM errors
sudo journalctl | grep pam_google_authenticator

# Check MFA enforcement logs
sudo tail -f /var/log/eos-mfa-enforcement.log
```

## 📁 File Locations

### Configuration Files:
- `/etc/pam.d/sudo` - Sudo PAM configuration with MFA
- `/etc/pam.d/su` - Su PAM configuration with MFA  
- `/etc/eos/mfa-enforcement.conf` - MFA enforcement policy
- `~/.google_authenticator` - User MFA secret and settings

### Scripts:
- `/usr/local/bin/setup-mfa` - Interactive MFA setup
- `/usr/local/bin/mfa-status` - MFA status checker
- `/usr/local/bin/enforce-mfa-strict` - Enable strict enforcement
- `/usr/local/bin/disable-mfa-emergency` - Emergency disable
- `/usr/local/bin/security-report` - Comprehensive security report

### Backups:
- `/etc/pam.d/sudo.backup-before-mfa` - Original sudo PAM config
- `/etc/pam.d/su.backup-before-mfa` - Original su PAM config
- `~/.google_authenticator.backup.*` - User MFA backups

### Logs:
- `/var/log/eos-mfa-enforcement.log` - MFA enforcement activity
- `/var/log/auth.log` - System authentication events
- `journalctl -u sudo` - Sudo authentication events

##  Use Cases

### Deployment:
```bash
# Deploy with strict enforcement immediately
sudo eos secure ubuntu --enforce-mfa

# Configure all users before enforcement
for user in $(getent passwd | cut -d: -f1); do
    sudo -u $user setup-mfa
done

# Enable strict mode after all users configured
sudo enforce-mfa-strict
```

### Development Environment:
```bash
# Use graceful mode for development flexibility
sudo eos secure ubuntu --enforce-mfa  # (default graceful mode)

# Or use standard MFA for testing
sudo eos secure ubuntu --enable-mfa
```

### High-Security Environment:
```bash
# Immediate strict enforcement with full hardening
sudo eos secure ubuntu --enforce-mfa
# Then manually switch to strict mode during setup
```

This enhanced MFA enforcement ensures your Ubuntu systems meet security standards while providing a smooth user experience and comprehensive emergency access procedures.
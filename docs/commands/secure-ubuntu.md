# Eos Secure Ubuntu Command

*Last Updated: 2025-01-14*

## Overview

The `eos secure ubuntu` command provides comprehensive security hardening for Ubuntu 24.04 LTS servers, with a focus on implementing Multi-Factor Authentication (MFA) for all privileged access while maintaining system usability and preventing lockouts.

## Command Syntax

```bash
# Default: Enforced MFA with full hardening
sudo eos secure ubuntu

# MFA Options
sudo eos secure ubuntu --enforce-mfa  # Strict MFA (default)
sudo eos secure ubuntu --enable-mfa   # Graceful MFA with password fallback
sudo eos secure ubuntu --disable-mfa  # Disable MFA enforcement
sudo eos secure ubuntu --no-mfa       # Skip MFA entirely (not recommended)
sudo eos secure ubuntu --mfa-only     # Only configure MFA, skip other hardening
```

## What It Does

### 1. Multi-Factor Authentication (MFA)
- Implements Google Authenticator-based TOTP for sudo/su access
- Preserves ALL existing sudoers authorizations exactly
- Handles service accounts and automation gracefully
- Provides multiple emergency recovery methods

### 2. System Hardening
- Disables unnecessary services and protocols
- Configures firewall rules (UFW)
- Hardens SSH configuration
- Sets secure kernel parameters
- Implements audit logging
- Configures automatic security updates

### 3. Security Tools Installation
- Installs and configures fail2ban
- Sets up AIDE for intrusion detection
- Configures auditd for comprehensive logging
- Implements ClamAV for malware scanning (optional)

## Why We Created This

### The Problem
Ubuntu servers often run with default configurations that prioritize compatibility over security. Manual hardening is:
- Time-consuming and error-prone
- Risk of locking yourself out
- Inconsistent across deployments
- Difficult to maintain compliance

### The Solution
A single command that:
- Implements security best practices automatically
- Never locks out administrators
- Preserves existing configurations
- Provides comprehensive rollback options
- Creates detailed audit trails

## How It Works

### Phase 1: Pre-flight Checks
```go
// Validates system state before making changes
- Checks Ubuntu version compatibility
- Verifies running as root
- Validates network connectivity
- Checks for existing MFA setup
- Creates comprehensive backups
```

### Phase 2: Emergency Access Setup
```go
// Creates multiple recovery methods BEFORE implementing MFA
- Emergency bypass group (mfa-emergency)
- Backup admin account with credentials
- Time-limited bypass script
- Console access configuration
- Recovery documentation
```

### Phase 3: MFA Implementation
```go
// Safely implements MFA without breaking access
- Installs libpam-google-authenticator
- Identifies all sudo users from sudoers
- Handles NOPASSWD entries specially
- Configures PAM modules atomically
- Tests configuration before enforcing
```

### Phase 4: System Hardening
```go
// Applies security configurations
- SSH hardening (key-only, no root)
- Firewall rules (default deny)
- Kernel parameter tuning
- Service minimization
- Audit logging setup
```

## When to Use

### Recommended Scenarios
- New Ubuntu 24.04 server deployments
- Compliance requirements (SOC2, HIPAA, PCI)
- Production server hardening
- Post-breach remediation
- Security baseline implementation

### Not Recommended For
- Development environments (use --no-mfa)
- CI/CD runners (use --no-mfa)
- Temporary test servers
- Systems without console access

## Where It Applies Changes

### Configuration Files Modified
```
/etc/pam.d/sudo          # MFA for sudo
/etc/pam.d/su            # MFA for su
/etc/ssh/sshd_config     # SSH hardening
/etc/sysctl.conf         # Kernel parameters
/etc/ufw/*               # Firewall rules
/etc/audit/rules.d/*     # Audit rules
/etc/sudoers.d/*         # Not modified, only parsed
```

### System Changes
```
/usr/local/bin/          # Helper scripts
├── emergency-mfa-bypass # Emergency access
├── setup-mfa           # User MFA setup
├── mfa-status          # Check MFA status
└── enforce-mfa-strict  # Switch to strict mode

/etc/eos/                # Eos configurations
├── mfa-backup-*/       # Automatic backups
└── mfa-enforcement.conf # MFA settings
```

## Implementation Details

### MFA Safety Features

#### 1. Preserves Sudoers Exactly
```go
// Original sudoers
user1 ALL=(ALL:ALL) ALL
%admin ALL=(ALL) NOPASSWD: /usr/bin/apt

// After MFA - Same permissions, just adds authentication layer
user1 ALL=(ALL:ALL) ALL              # Now requires password + MFA
%admin ALL=(ALL) NOPASSWD: /usr/bin/apt # Added to service group, no MFA needed
```

#### 2. Multiple Recovery Methods
```bash
# Method 1: Emergency bypass (60 minutes)
sudo emergency-mfa-bypass enable

# Method 2: Emergency group membership
sudo usermod -a -G mfa-emergency username

# Method 3: Backup admin account
Username: emergency-admin
Password: [stored in /etc/eos/mfa-backup-*/emergency-admin-creds.txt]

# Method 4: Console access (if enabled)
Physical console login bypasses MFA

# Method 5: Manual restore script
sudo /etc/eos/mfa-backup-*/restore.sh
```

#### 3. Atomic Operations
All changes are atomic with automatic rollback on any failure:
```go
defer func() {
    if r := recover(); r != nil {
        m.rollback() // Restore original state
    }
}()
```

### PAM Configuration Strategy

#### Graceful Mode (--enable-mfa)
```pam
# Allows password-only during setup period
auth sufficient pam_unix.so try_first_pass
auth optional pam_google_authenticator.so nullok
```

#### Enforced Mode (--enforce-mfa) [Default]
```pam
# Requires both password AND MFA token
auth required pam_google_authenticator.so forward_pass
auth required pam_unix.so use_first_pass
```

### Service Account Handling
Users with NOPASSWD commands are automatically added to `mfa-service-accounts` group:
```bash
# Original sudoers
jenkins ALL=(ALL) NOPASSWD: /usr/bin/docker

# After MFA implementation
jenkins ALL=(ALL) NOPASSWD: /usr/bin/docker  # Still works
# User 'jenkins' added to mfa-service-accounts group
# PAM configuration bypasses MFA for this group
```

## User Experience

### For Administrators

1. **Initial Setup**
```bash
$ sudo eos secure ubuntu --enable-mfa
 Starting comprehensive MFA implementation
 Phase 1: Pre-flight checks passed
 Phase 2: Emergency access configured
 Phase 3: MFA packages installed
👥 Phase 4: Users identified (3 sudo users)
 Phase 5: PAM configured safely
 Phase 6: Tests passed
 Phase 7: Additional hardening applied
 Phase 8: Configuration finalized

 MFA implementation completed successfully!

Next steps:
1. Run 'sudo setup-mfa' to configure your MFA
2. Test with 'sudo mfa-status'
3. Keep emergency credentials safe
```

2. **User MFA Setup**
```bash
$ sudo setup-mfa
 MFA Setup for john
====================

 Setting up authenticator app...
[QR Code displayed]

Secret key: ABCD EFGH IJKL MNOP
Emergency codes:
  12345678
  23456789
  34567890
  45678901
  56789012

 MFA configured successfully!
Test with: sudo whoami
```

3. **Using Sudo with MFA**
```bash
$ sudo systemctl status nginx
[sudo] password for john: ********
Verification code: 123456
● nginx.service - A high performance web server
   Active: active (running)
```

### For Service Accounts
No change required - automation continues working:
```bash
# Jenkins CI pipeline still works
jenkins@server:~$ sudo docker build .
# No password or MFA required - NOPASSWD preserved
```

## Troubleshooting

### Common Issues

1. **Locked Out After MFA Setup**
```bash
# From console or recovery mode:
sudo emergency-mfa-bypass enable
# OR
sudo -u emergency-admin -i
# OR
Boot to recovery mode → root shell → /etc/eos/mfa-backup-*/restore.sh
```

2. **MFA Token Not Working**
```bash
# Check time sync
timedatectl status
sudo ntpdate -s time.nist.gov

# Verify MFA status
sudo mfa-status
```

3. **Service Account Broken**
```bash
# Add to service group
sudo usermod -a -G mfa-service-accounts serviceuser
```

## Security Considerations

### What's Protected
- All sudo/su privilege escalation
- SSH access (key-only by default)
- Console access (optional MFA)
- System services and APIs

### What's Not Protected
- Direct console access (configurable)
- Recovery mode access
- Service accounts with NOPASSWD
- Emergency bypass methods (by design)

### Compliance Notes
- Meets requirements for MFA on privileged access
- Provides comprehensive audit trail
- Implements defense in depth
- Maintains separation of duties

## Best Practices

1. **Always Test First**
```bash
# Use graceful mode initially
sudo eos secure ubuntu --enable-mfa
# Test thoroughly, then enforce
sudo enforce-mfa-strict
```

2. **Document Everything**
```bash
# Record emergency credentials
# Document custom sudoers rules
# Note service account names
```

3. **Regular Reviews**
```bash
# Check MFA status
sudo mfa-status

# Review sudo logs
sudo journalctl -u sudo --since "1 week ago"

# Audit user list
sudo eos list users --sudo
```

## Integration with Eos

The secure ubuntu command integrates with other Eos features:

```bash
# Backup before hardening
eos backup system --pre-hardening

# Monitor security status
eos read security --status

# Update security policies
eos update policies --security-baseline

# Audit compliance
eos list compliance --framework=cis
```

## Advanced Usage

### Custom Configuration
```bash
# Create custom MFA config
cat > /etc/eos/mfa-custom.yaml <<EOF
emergency_timeout: 120m
console_bypass: false
service_group: "automation-accounts"
backup_admin: "recovery-user"
EOF

# Apply with custom config
sudo eos secure ubuntu --config=/etc/eos/mfa-custom.yaml
```

### Selective Hardening
```bash
# Only configure MFA
sudo eos secure ubuntu --mfa-only

# Skip specific components
sudo eos secure ubuntu --skip=firewall,kernel

# Dry run mode
sudo eos secure ubuntu --dry-run
```

## Rollback Procedures

### Automatic Rollback
Happens automatically on any failure during implementation.

### Manual Rollback
```bash
# Full restore
sudo /etc/eos/mfa-backup-[timestamp]/restore.sh

# Selective restore
sudo cp /etc/eos/mfa-backup-*/etc_pam.d_sudo /etc/pam.d/sudo
```

### Emergency Recovery
See [Emergency Recovery Guide](./emergency-recovery.md) for detailed procedures.

## Development Notes

### Why Go Implementation
- Type safety for security-critical operations
- Comprehensive error handling
- Easy integration with Eos framework
- Cross-compilation support
- Single binary deployment

### Testing
```go
// Comprehensive test coverage
go test ./pkg/ubuntu/... -v
go test -run TestMFAImplementation
go test -run TestEmergencyRecovery
```

### Contributing
See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## References

- [Ubuntu Security Guide](https://ubuntu.com/security/certifications/docs/2204/usg)
- [CIS Ubuntu 24.04 Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [PAM Configuration Guide](https://www.linux.com/training-tutorials/understanding-pam/)
- [Google Authenticator PAM Module](https://github.com/google/google-authenticator-libpam)
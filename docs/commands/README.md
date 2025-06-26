# Eos Command Documentation

## Security Commands

### eos secure ubuntu

Comprehensive security hardening for Ubuntu 24.04 LTS servers with production-ready Multi-Factor Authentication.

**Quick Start:**
```bash
sudo eos secure ubuntu  # Full hardening with enforced MFA
```

**Documentation:**
- [Complete Command Guide](./secure-ubuntu.md) - Full documentation
- [MFA Implementation Guide](../guides/mfa-implementation.md) - Technical details
- [User Setup Guide](../guides/mfa-user-guide.md) - End-user instructions
- [Emergency Recovery](../guides/emergency-recovery.md) - Lockout recovery procedures

## Why We Created These Commands

### The Challenge
Ubuntu servers require extensive manual hardening to meet security standards. The process is:
- Time-consuming (2-4 hours per server)
- Error-prone (easy to misconfigure)
- Inconsistent across deployments
- Risk of administrator lockout
- Difficult compliance documentation

### Our Solution
Single commands that implement security best practices:
- **Never lock out administrators** - Multiple recovery methods
- **Preserve existing configurations** - Sudoers authorizations maintained exactly
- **Handle automation gracefully** - Service accounts continue working
- **Comprehensive audit trail** - Every change logged
- **Atomic operations** - All-or-nothing with automatic rollback

## What We Implemented

### Multi-Factor Authentication (MFA)
```go
// Production-ready MFA with safety features
type MFAManager struct {
    // Preserves ALL existing sudoers exactly
    // Multiple emergency recovery methods
    // Atomic operations with rollback
    // Handles service accounts automatically
}
```

### Security Hardening Components
- **SSH Hardening** - Key-only access, disable root login
- **Firewall Configuration** - UFW with secure defaults
- **Kernel Hardening** - Secure sysctl parameters
- **Audit Logging** - Comprehensive activity monitoring
- **Intrusion Detection** - AIDE file integrity monitoring
- **Vulnerability Scanning** - Lynis security auditing
- **Attack Prevention** - fail2ban for brute force protection

### When to Use Each Mode

#### Production Servers (Default)
```bash
sudo eos secure ubuntu
# - Full security hardening
# - Enforced MFA (password + token required)
# - All security tools installed
# - Emergency recovery configured
```

#### Gradual Implementation
```bash
sudo eos secure ubuntu --enable-mfa
# - Graceful MFA (allows password fallback)
# - Full security hardening
# - Gives users time to set up authenticators
# - Switch to enforced mode later
```

#### Development/Testing
```bash
sudo eos secure ubuntu --no-mfa
# - Full security hardening
# - No MFA requirement
# - Suitable for development environments
# - Can add MFA later
```

#### MFA Only
```bash
sudo eos secure ubuntu --mfa-only
# - Only configure MFA
# - Skip other hardening
# - For servers with existing security
# - Quick MFA implementation
```

## How It Works Safely

### 1. Pre-flight Validation
- Check Ubuntu version compatibility
- Verify root access and network connectivity
- Validate existing system state
- Check for conflicting configurations

### 2. Emergency Access First
```bash
# Created BEFORE implementing MFA:
/usr/local/bin/emergency-mfa-bypass  # 60-minute bypass
groupadd mfa-emergency               # Permanent bypass group  
useradd emergency-admin              # Backup admin account
/etc/eos/mfa-backup-*/restore.sh    # Complete restoration
```

### 3. Atomic Implementation
- All changes in a single transaction
- Comprehensive backups before changes
- Automatic rollback on any failure
- Validation at every step

### 4. Service Account Preservation
```bash
# Before MFA:
jenkins ALL=(ALL) NOPASSWD: /usr/bin/docker

# After MFA:
# - Same sudoers entry (unchanged)
# - User 'jenkins' added to mfa-service-accounts group
# - PAM configuration bypasses MFA for this group
# - Automation continues working exactly as before
```

## Emergency Recovery

### If You're Locked Out
```bash
# Method 1: Emergency bypass (if you have any sudo access)
sudo emergency-mfa-bypass enable

# Method 2: Backup admin account
ssh emergency-admin@server
# (credentials in /etc/eos/mfa-backup-*/emergency-admin-creds.txt)

# Method 3: Console access (if configured without MFA)
# Physical console or VM console login

# Method 4: Recovery mode
# Boot to recovery mode → run restore script

# Method 5: Manual PAM restoration
# Expert-level manual intervention
```

### Never Permanently Locked Out
The system provides **5 independent recovery methods** ensuring administrators can always regain access.

## User Experience

### Administrators
1. Run single command for full hardening
2. System guides through MFA setup
3. Multiple recovery options documented
4. Audit trail of all changes
5. Helper scripts for ongoing management

### End Users
1. Clear instructions for MFA setup: `sudo setup-mfa`
2. Works with any TOTP authenticator app
3. Backup codes for device loss
4. Status checking: `sudo mfa-status`
5. Emergency procedures documented

### Service Accounts
- **Zero changes required** for automation
- NOPASSWD entries automatically detected
- Added to bypass group automatically
- Scripts continue working without modification

## Compliance and Security

### Standards Met
- **CIS Ubuntu 24.04 Benchmark** alignment
- **NIST Cybersecurity Framework** compliance
- **SOC 2 Type II** control requirements
- **HIPAA** technical safeguards
- **PCI DSS** access control requirements

### Audit Trail
- All privileged access logged
- MFA setup and usage tracked
- Emergency access usage monitored
- Configuration changes documented
- Recovery actions audited

## Integration with Eos

```bash
# Part of comprehensive security workflow
eos backup system --pre-hardening    # Backup before changes
eos secure ubuntu                    # Apply hardening
eos read security --status           # Verify implementation
eos list compliance --framework=cis  # Check compliance
eos update policies --security       # Maintain policies
```

## Development Philosophy

### Safety First
- **Never break existing access** - Preserve all sudoers exactly
- **Multiple recovery methods** - Never permanently locked out
- **Atomic operations** - All-or-nothing with rollback
- **Comprehensive testing** - Validate before enforcing

### Production Ready
- **Extensive error handling** - Graceful failure modes
- **Comprehensive logging** - Detailed audit trail
- **Performance optimized** - Minimal impact on operations
- **Well documented** - Clear procedures for all scenarios

### User Focused
- **Clear documentation** - Step-by-step guides
- **Helpful error messages** - Actionable troubleshooting
- **Progressive implementation** - Graceful to enforced modes
- **Emergency procedures** - Always a way to recover

## Getting Started

1. **Read the documentation** - [secure-ubuntu.md](./secure-ubuntu.md)
2. **Plan your implementation** - Choose MFA mode for your environment
3. **Backup your system** - `eos backup system --pre-hardening`
4. **Run the command** - `sudo eos secure ubuntu`
5. **Test thoroughly** - Verify access and functionality
6. **Document credentials** - Store emergency access information securely

Remember: Security hardening is a process, not a destination. Regular reviews and updates maintain security posture.
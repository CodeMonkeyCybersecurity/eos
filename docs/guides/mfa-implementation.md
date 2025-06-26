# MFA Implementation Technical Guide

## Architecture Overview

The Eos MFA implementation for Ubuntu follows a safety-first approach that ensures administrators can never be locked out while implementing strong multi-factor authentication across all privilege escalation paths.

## Core Design Principles

### 1. Never Break Existing Access
- All sudoers authorizations are preserved exactly
- Service accounts continue functioning
- Automation workflows remain intact
- Emergency access is established BEFORE enforcement

### 2. Atomic Operations
- All changes happen in a transaction
- Automatic rollback on any failure
- Comprehensive backup before changes
- Validation at every step

### 3. Defense in Depth
- Multiple independent recovery methods
- Time-based emergency bypasses
- Group-based exclusions
- Console access options

## Implementation Components

### MFAManager Structure
```go
type MFAManager struct {
    rc              *eos_io.RuntimeContext
    logger          otelzap.LoggerWithCtx
    config          MFAConfig
    backupDir       string
    rollbackEnabled bool
    testMode        bool
}

type MFAConfig struct {
    // Safety settings
    EnableRecoveryCodes bool
    RecoveryCodeCount   int
    CreateBackupAdmin   bool
    BackupAdminUser     string
    TestBeforeEnforce   bool
    
    // Emergency access
    EmergencyGroupName string
    ConsoleBypassMFA   bool
    EmergencyTimeout   time.Duration
    
    // Automation handling
    ServiceAccountGroup string
    PreserveNOPASSWD    bool
    
    // Rollback settings
    BackupRetentionDays int
    AutoRollbackOnError bool
}
```

### Implementation Phases

#### Phase 1: Pre-flight Checks
```go
func (m *MFAManager) preFlightChecks() error {
    // 1. Verify Ubuntu 24.04
    // 2. Check root access
    // 3. Validate network connectivity
    // 4. Check existing MFA setup
    // 5. Verify disk space for backups
    // 6. Test sudo functionality
}
```

#### Phase 2: Backup Creation
```go
func (m *MFAManager) createBackups() error {
    // Backup locations:
    // - /etc/pam.d/sudo
    // - /etc/pam.d/su
    // - /etc/pam.d/login
    // - /etc/sudoers
    // - /etc/sudoers.d/*
    // Creates: /etc/eos/mfa-backup-[timestamp]/
}
```

#### Phase 3: Emergency Access
```go
func (m *MFAManager) createEmergencyAccess() error {
    // 1. Create emergency bypass group
    // 2. Create service account group
    // 3. Create backup admin user
    // 4. Install emergency bypass script
    // 5. Generate recovery documentation
}
```

#### Phase 4: User Discovery
```go
func (m *MFAManager) identifyAllSudoUsers() ([]SudoUser, error) {
    // 1. Parse /etc/sudoers
    // 2. Parse /etc/sudoers.d/*
    // 3. Resolve group memberships
    // 4. Identify NOPASSWD entries
    // 5. Check existing MFA status
}
```

#### Phase 5: PAM Configuration
```go
func (m *MFAManager) configurePAMSafely() error {
    // 1. Generate PAM configurations
    // 2. Validate syntax
    // 3. Write to temporary files
    // 4. Atomic replacement
    // 5. Verify functionality
}
```

## Sudoers Parsing Algorithm

### Complete Parsing Logic
```go
func (m *MFAManager) parseSudoersComplete() ([]SudoersEntry, error) {
    entries := []SudoersEntry{}
    
    // 1. Parse main sudoers file
    mainEntries := parseSudoersFile("/etc/sudoers")
    entries = append(entries, mainEntries...)
    
    // 2. Handle @includedir directives
    // 3. Parse each included file
    // 4. Skip backup files (~, .backup, .orig)
    // 5. Handle line continuations (\)
    // 6. Parse user specifications
    
    return entries, nil
}
```

### Entry Types Handled
```sudoers
# User entries
john ALL=(ALL:ALL) ALL

# Group entries
%admin ALL=(ALL) ALL

# NOPASSWD entries
jenkins ALL=(ALL) NOPASSWD: /usr/bin/docker

# Complex entries
%sudo ALL=(ALL:ALL) NOPASSWD: /usr/bin/apt, PASSWD: ALL

# Netgroup entries (identified but skipped)
+netgroup ALL=(ALL) ALL
```

## PAM Configuration Details

### Enforcement Levels

#### 1. Test Mode (Initial Setup)
```pam
# /etc/pam.d/sudo - Test mode
auth sufficient pam_unix.so try_first_pass
auth optional pam_google_authenticator.so nullok
@include common-account
@include common-session-noninteractive
```

#### 2. Graceful Mode (--enable-mfa)
```pam
# /etc/pam.d/sudo - Graceful mode
# Emergency bypass for mfa-emergency group
auth [success=done default=ignore] pam_succeed_if.so user ingroup mfa-emergency
# Service account bypass
auth [success=done default=ignore] pam_succeed_if.so user ingroup mfa-service-accounts
# Time-based emergency bypass
auth [success=done default=ignore] pam_succeed_if.so file /etc/security/.emergency_mfa_bypass
# Standard auth + MFA (with fallback)
@include common-auth
auth required pam_google_authenticator.so nullok
@include common-account
@include common-session-noninteractive
```

#### 3. Enforced Mode (--enforce-mfa) [Default]
```pam
# /etc/pam.d/sudo - Enforced mode
# Emergency bypass for mfa-emergency group
auth [success=done default=ignore] pam_succeed_if.so user ingroup mfa-emergency
# Service account bypass
auth [success=done default=ignore] pam_succeed_if.so user ingroup mfa-service-accounts
# Time-based emergency bypass
auth [success=done default=ignore] pam_succeed_if.so file /etc/security/.emergency_mfa_bypass
# Standard auth first
@include common-auth
# MFA required (no nullok)
auth required pam_google_authenticator.so
@include common-account
@include common-session-noninteractive
```

### PAM Control Flags Explained
- `required`: Must succeed for authentication to continue
- `sufficient`: Success is enough, failure doesn't deny
- `optional`: Result doesn't affect overall outcome
- `[success=done default=ignore]`: If check passes, authentication succeeds immediately

## Emergency Access Methods

### Method 1: Time-Based Bypass
```bash
#!/bin/bash
# /usr/local/bin/emergency-mfa-bypass
# Enables 60-minute MFA bypass window

enable() {
    touch /etc/security/.emergency_mfa_bypass
    echo "$(date)" > /etc/security/.emergency_mfa_bypass
    chmod 600 /etc/security/.emergency_mfa_bypass
    
    # Schedule automatic removal
    echo "rm -f /etc/security/.emergency_mfa_bypass" | at now + 60 minutes
    
    # Add user to emergency group temporarily
    usermod -a -G mfa-emergency $SUDO_USER
}
```

### Method 2: Emergency Group
```bash
# Permanent bypass via group membership
groupadd -f mfa-emergency

# Add user for emergency access
usermod -a -G mfa-emergency username

# PAM checks group membership before MFA
auth [success=done default=ignore] pam_succeed_if.so user ingroup mfa-emergency
```

### Method 3: Backup Admin Account
```go
func createBackupAdmin() error {
    // 1. Generate 32-character secure password
    // 2. Create user: emergency-admin
    // 3. Add to sudo group
    // 4. Add to mfa-emergency group
    // 5. Store credentials in backup directory
    // 6. Set permissions 600 on credential file
}
```

### Method 4: Console Bypass
```pam
# /etc/pam.d/login - Console access
# Optional: Console login doesn't require MFA
# Configured via ConsoleBypassMFA setting
```

### Method 5: Recovery Script
```bash
#!/bin/bash
# /etc/eos/mfa-backup-*/restore.sh
# Complete restoration script

# Restores:
# - Original PAM configurations
# - Removes MFA groups
# - Cleans up emergency access
# - Provides testing instructions
```

## Service Account Handling

### Detection Algorithm
```go
func identifyServiceAccounts(users []SudoUser) []string {
    serviceAccounts := []string{}
    
    for _, user := range users {
        // Check for NOPASSWD commands
        if len(user.NOPASSWDCmds) > 0 {
            serviceAccounts = append(serviceAccounts, user.Username)
        }
        
        // Check for system users (UID < 1000)
        if isSystemUser(user.Username) {
            serviceAccounts = append(serviceAccounts, user.Username)
        }
    }
    
    return serviceAccounts
}
```

### Automatic Bypass Configuration
```bash
# Service accounts added to special group
groupadd -f mfa-service-accounts

# Add identified service accounts
usermod -a -G mfa-service-accounts jenkins
usermod -a -G mfa-service-accounts nagios
usermod -a -G mfa-service-accounts zabbix

# PAM bypasses MFA for this group
auth [success=done default=ignore] pam_succeed_if.so user ingroup mfa-service-accounts
```

## Testing Framework

### Automated Tests
```go
func (m *MFAManager) testConfiguration() error {
    tests := []Test{
        {"PAM Syntax Validation", testPAMSyntax},
        {"Emergency Group Exists", testEmergencyGroup},
        {"Service Group Exists", testServiceGroup},
        {"Backup Admin Access", testBackupAdmin},
        {"Emergency Script Executable", testEmergencyScript},
        {"MFA Packages Installed", testPackages},
        {"Audit Rules Active", testAuditRules},
    }
    
    for _, test := range tests {
        if err := test.Run(); err != nil {
            return rollbackWithError(err)
        }
    }
}
```

### Manual Test Procedures
```bash
# Test 1: Basic sudo functionality
sudo whoami
# Expected: Password prompt, then MFA prompt

# Test 2: Service account bypass
su - jenkins
sudo docker ps
# Expected: No password or MFA required

# Test 3: Emergency bypass
sudo emergency-mfa-bypass enable
sudo whoami
# Expected: Only password required

# Test 4: Console access
# Physical console or VM console
# Expected: Based on ConsoleBypassMFA setting
```

## Rollback Procedures

### Automatic Rollback Triggers
1. PAM syntax validation failure
2. Test user authentication failure
3. Package installation failure
4. File permission errors
5. Panic recovery in any phase

### Rollback Operations
```go
func (m *MFAManager) rollback() error {
    // 1. Restore PAM configurations
    for _, file := range []string{"sudo", "su", "login"} {
        restoreFile(file)
    }
    
    // 2. Remove created groups
    exec("groupdel", m.config.EmergencyGroupName)
    exec("groupdel", m.config.ServiceAccountGroup)
    
    // 3. Create rollback notification
    createRollbackNotification()
    
    // 4. Log rollback completion
    m.logger.Info("Rollback completed")
}
```

## Security Hardening Components

### SSH Hardening
```bash
# Changes to /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
```

### Kernel Parameters
```bash
# /etc/sysctl.d/99-security.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
kernel.randomize_va_space = 2
```

### Firewall Rules
```bash
# UFW configuration
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 443/tcp comment 'HTTPS'
ufw enable
```

### Audit Rules
```bash
# /etc/audit/rules.d/mfa-sudo.rules
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes
-w /etc/pam.d/sudo -p wa -k pam_sudo_changes
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec
```

## Monitoring and Compliance

### Log Locations
```
/var/log/auth.log          # Authentication attempts
/var/log/audit/audit.log   # Audit trail
/var/log/secure            # Security events
/var/log/eos/mfa.log      # MFA-specific logging
```

### Compliance Checks
```bash
# CIS Benchmark alignment
- 5.3.4 Ensure password hashing algorithm is SHA-512
- 5.4.3 Ensure password reuse is limited  
- 5.4.4 Ensure strong password policy
- 6.2.1 Ensure password fields are not empty

# Additional MFA requirements
- All interactive sudo requires MFA
- Service accounts explicitly excluded
- Emergency access documented
- Audit trail maintained
```

## Troubleshooting Guide

### Common Issues

#### 1. MFA Token Rejected
```bash
# Check time synchronization
timedatectl status
chronyc sources

# Verify token generation
google-authenticator -t -d -f ~/.google_authenticator -w 3

# Check PAM configuration
sudo pam-auth-update --status
```

#### 2. Service Account Broken
```bash
# Verify group membership
groups jenkins

# Add to service group if missing
sudo usermod -a -G mfa-service-accounts jenkins

# Check sudoers entry
sudo -l -U jenkins
```

#### 3. Complete Lockout
```bash
# Recovery options in order:
1. Try: sudo emergency-mfa-bypass enable
2. Try: Login as emergency-admin
3. Boot to recovery mode
4. Run: /etc/eos/mfa-backup-*/restore.sh
5. Manual PAM restoration
```

## Integration Points

### With Eos Framework
- Uses RuntimeContext for context propagation
- Structured logging via otelzap
- Error handling via eos_err
- Command execution via execute package

### With Ubuntu System
- PAM module integration
- Systemd service management
- UFW firewall rules
- Audit subsystem integration
- Package management via apt

## Performance Considerations

- Sudoers parsing: O(n) where n = number of entries
- PAM checks: Added ~100ms to sudo operations
- Backup creation: ~1-2 seconds
- Full implementation: ~30-60 seconds

## Future Enhancements

1. **Hardware Token Support**
   - YubiKey integration
   - FIDO2 support
   - Smart card authentication

2. **Centralized Management**
   - LDAP/AD integration
   - Central policy management
   - Distributed key management

3. **Enhanced Monitoring**
   - Real-time alerts
   - Anomaly detection
   - Compliance reporting

## References

- [PAM Configuration Reference](http://www.linux-pam.org/Linux-PAM-html/)
- [Google Authenticator PAM](https://github.com/google/google-authenticator-libpam)
- [Ubuntu Security Guide](https://ubuntu.com/security/certifications/docs/2204/usg)
- [sudoers(5) Manual](https://www.sudo.ws/docs/man/sudoers.man/)
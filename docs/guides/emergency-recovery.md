# Emergency MFA Recovery Guide

## Overview

This guide provides step-by-step procedures for recovering from MFA lockouts. The Eos MFA implementation includes multiple independent recovery methods to ensure administrators are never permanently locked out.

⚠️ **IMPORTANT**: These procedures should only be used in genuine emergencies. All recovery actions are logged and audited.

## Quick Reference

### Emergency Contacts
```
System Administrator: [Your org contact]
Emergency Escalation: [Your org escalation]
Emergency Credentials: /etc/eos/mfa-backup-*/emergency-admin-creds.txt
Recovery Documentation: /usr/local/share/eos/mfa-recovery.md
```

### Recovery Method Priority
1. **Emergency bypass script** (if sudo access available)
2. **Backup admin account** (if credentials available)
3. **Console recovery** (physical/VM console access)
4. **Recovery mode** (boot-level recovery)
5. **Manual restoration** (expert-level)

## Method 1: Emergency Bypass Script

### When to Use
- You have sudo access but lost MFA device
- MFA app is broken/corrupted
- Need temporary access to fix MFA setup

### Requirements
- Current sudo access (with your password)
- Terminal access to the server

### Procedure
```bash
# Step 1: Enable emergency bypass (60-minute window)
sudo emergency-mfa-bypass enable

# Output:
============================================
   EMERGENCY MFA BYPASS ACTIVATION
============================================

This will temporarily disable MFA requirements
for 60 minutes.

Continue? (y/N): y

✓ Emergency MFA bypass enabled for 60 minutes
⚠️  Please establish permanent access within this time!
⚠️  Bypass will auto-disable or run: sudo emergency-mfa-bypass disable

# Step 2: Verify bypass is active
sudo emergency-mfa-bypass status

# Step 3: Fix MFA or extend access
sudo setup-mfa  # Re-configure MFA
# OR
sudo usermod -a -G mfa-emergency yourusername  # Permanent bypass

# Step 4: Disable bypass when done
sudo emergency-mfa-bypass disable
```

### Notes
- Creates audit log entry
- Automatically expires after 60 minutes
- Can be extended by running enable again
- Adds you to mfa-emergency group temporarily

## Method 2: Backup Admin Account

### When to Use
- Primary account locked out
- Emergency bypass script not accessible
- Need clean slate for recovery

### Requirements
- Emergency admin credentials (see credentials location)
- SSH or console access

### Finding Credentials
```bash
# Credentials stored during MFA setup in:
/etc/eos/mfa-backup-[timestamp]/emergency-admin-creds.txt

# Example locations:
/etc/eos/mfa-backup-20241226-130100/emergency-admin-creds.txt
/etc/eos/mfa-backup-20241226-140500/emergency-admin-creds.txt

# View available backups:
ls -la /etc/eos/mfa-backup-*/
```

### Procedure
```bash
# Step 1: Find the latest backup directory
LATEST_BACKUP=$(ls -1t /etc/eos/mfa-backup-* | head -1)
echo "Latest backup: $LATEST_BACKUP"

# Step 2: Get emergency admin credentials
sudo cat $LATEST_BACKUP/emergency-admin-creds.txt

# Output:
Emergency Admin Credentials
==============================

Username: emergency-admin
Password: Xk9mP2vQ8nR5tY7wE3uI9oL6sA4hF1jD
Created:  2024-12-26T13:01:00Z
Purpose:  Emergency access if MFA fails
STORE THESE CREDENTIALS SECURELY!

# Step 3: Login as emergency admin
ssh emergency-admin@yourserver
# OR (if on console)
su - emergency-admin

# Step 4: Fix primary account MFA
sudo setup-mfa-for-user your-primary-username
# OR disable MFA temporarily
sudo usermod -a -G mfa-emergency your-primary-username
```

### Security Notes
- Change emergency admin password after use
- Emergency admin has permanent MFA bypass
- Consider disabling account when not needed

## Method 3: Console Recovery

### When to Use
- No SSH access available
- Cannot login with any account
- Network issues preventing remote access

### Requirements
- Physical console access or VM console
- Knowledge of root password or console may not require MFA

### Procedure

#### Option A: Console Login (if configured without MFA)
```bash
# Step 1: Access physical console or VM console
# Step 2: Login with your account
username: john
password: [your password]
# Note: Console may bypass MFA if configured

# Step 3: Fix MFA setup
sudo setup-mfa
# OR enable emergency bypass
sudo usermod -a -G mfa-emergency john
```

#### Option B: Single User Mode
```bash
# Step 1: Reboot server
# Step 2: At GRUB menu, press 'e' to edit
# Step 3: Find line starting with 'linux'
# Step 4: Add 'single' or 'init=/bin/bash' to end
# Step 5: Press Ctrl+X to boot

# Step 6: Remount filesystem as writable
mount -o remount,rw /

# Step 7: Run recovery script
/etc/eos/mfa-backup-*/restore.sh

# Step 8: Reboot normally
reboot
```

## Method 4: Recovery Mode Boot

### When to Use
- Complete system lockout
- Console login also requires MFA
- Emergency admin account not working

### Requirements
- Physical or virtual console access
- Ubuntu recovery mode knowledge

### Procedure
```bash
# Step 1: Boot to recovery mode
# - Restart server
# - Hold SHIFT during boot (or ESC for UEFI)
# - Select "Advanced options for Ubuntu"
# - Select "Recovery mode"
# - Select "root - Drop to root shell prompt"

# Step 2: Enable network (if needed)
dhclient eth0

# Step 3: Remount filesystem writable
mount -o remount,rw /

# Step 4: Identify backup directory
ls /etc/eos/mfa-backup-*/

# Step 5: Run automatic restore
LATEST_BACKUP=$(ls -1t /etc/eos/mfa-backup-* | head -1)
$LATEST_BACKUP/restore.sh

# Step 6: Alternative - manual restore
cp $LATEST_BACKUP/etc_pam.d_sudo /etc/pam.d/sudo
cp $LATEST_BACKUP/etc_pam.d_su /etc/pam.d/su

# Step 7: Remove MFA groups (optional)
groupdel mfa-emergency
groupdel mfa-service-accounts

# Step 8: Resume normal boot
exit
# Select "resume - Resume normal boot"
```

## Method 5: Manual PAM Restoration

### When to Use
- All automated methods failed
- Backup directory corrupted
- Expert-level manual intervention needed

### Requirements
- Root access via recovery mode
- Understanding of PAM configuration

### Procedure
```bash
# Step 1: Boot to recovery mode or single user mode

# Step 2: Create safe PAM configuration
cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive
EOF

# Step 3: Restore su configuration
cat > /etc/pam.d/su << 'EOF'
#%PAM-1.0

auth       sufficient pam_rootok.so
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_unix.so
EOF

# Step 4: Remove MFA packages (if needed)
apt-get remove --purge libpam-google-authenticator

# Step 5: Clean up groups
groupdel mfa-emergency 2>/dev/null || true
groupdel mfa-service-accounts 2>/dev/null || true

# Step 6: Test configuration
# (after normal boot)
sudo whoami
```

## Recovery Verification

### After Any Recovery Method
```bash
# Step 1: Test basic sudo access
sudo whoami
# Expected: Only password prompt, no MFA

# Step 2: Check PAM configuration
sudo grep -l "google_authenticator" /etc/pam.d/* || echo "MFA disabled"

# Step 3: Verify group cleanup
groups | grep -E "(mfa-emergency|mfa-service-accounts)" || echo "Groups cleaned"

# Step 4: Check system users
sudo mfa-status 2>/dev/null || echo "MFA completely disabled"

# Step 5: Review audit logs
sudo journalctl -u sudo --since "1 hour ago"
```

## Post-Recovery Actions

### Immediate Actions
1. **Change passwords** for any emergency accounts used
2. **Review audit logs** for unauthorized access
3. **Document the incident** with timestamp and cause
4. **Test normal operations** with all user accounts

### Security Review
1. **Identify root cause** - Why did the lockout occur?
2. **Update procedures** - What could prevent this?
3. **Verify backups** - Are emergency procedures up to date?
4. **Training needs** - Do users need additional training?

### Re-implementing MFA
```bash
# If MFA was completely disabled during recovery:

# Step 1: Clean slate implementation
sudo eos secure ubuntu --enable-mfa

# Step 2: Test with non-critical account first
sudo -u testuser setup-mfa

# Step 3: Roll out to all users gradually
# Step 4: Move to enforced mode when ready
sudo enforce-mfa-strict
```

## Prevention Strategies

### For Users
- **Set up MFA on multiple devices** (phone + tablet)
- **Store backup codes securely** (password manager)
- **Enable authenticator app backups** (cloud sync)
- **Test MFA before logging out** of critical sessions
- **Keep emergency contact information** updated

### For Administrators
- **Monitor emergency access usage** via audit logs
- **Regularly test recovery procedures** (quarterly)
- **Keep backup directories secure** but accessible
- **Document custom sudoers configurations** before MFA
- **Maintain emergency contact lists**

### For Organizations
- **Multiple administrators** with emergency access
- **Out-of-band communication** methods for emergencies
- **Regular backup verification** procedures
- **Incident response procedures** for MFA issues
- **Training programs** for emergency procedures

## Escalation Procedures

### Level 1: Self-Service Recovery
- Emergency bypass script
- Backup codes
- Secondary devices

### Level 2: Administrator Assistance
- Emergency admin account
- Console access assistance
- PAM configuration review

### Level 3: Expert Recovery
- Recovery mode procedures
- Manual PAM restoration
- System rebuild if necessary

### Level 4: Vendor Support
- Contact Code Monkey Cybersecurity
- Provide system logs and configuration
- Remote assistance if contracted

## Audit and Logging

### Recovery Actions Logged
```bash
# Emergency bypass usage
sudo journalctl -u audit | grep "emergency-mfa-bypass"

# Emergency account logins
sudo journalctl | grep "emergency-admin"

# PAM configuration changes
sudo journalctl | grep "pam.d"

# Group membership changes
sudo journalctl | grep "usermod.*mfa-"
```

### Required Documentation
- Timestamp of emergency
- Method used for recovery
- Personnel involved
- Root cause analysis
- Preventive measures taken

## Testing Recovery Procedures

### Regular Testing (Quarterly)
```bash
# Test 1: Emergency bypass
sudo emergency-mfa-bypass enable
sudo whoami  # Should work without MFA
sudo emergency-mfa-bypass disable

# Test 2: Backup admin access
# (Test login, don't change anything)

# Test 3: Console access
# (Test on VM console if possible)

# Test 4: Backup restore
# (Test script syntax only)
bash -n /etc/eos/mfa-backup-*/restore.sh
```

### Simulation Exercises
- Practice recovery with test accounts
- Time recovery procedures
- Document lessons learned
- Update procedures based on findings

## Contact Information

### Emergency Contacts
```
Primary Admin: [Name, Phone, Email]
Secondary Admin: [Name, Phone, Email]
On-Call Rotation: [Current contact method]
Escalation Path: [Management chain]
```

### Vendor Support
```
Code Monkey Cybersecurity
Email: support@cybermonkey.net.au
Emergency: [If contracted]
Documentation: https://wiki.cybermonkey.net.au
```

Remember: The goal is never to need these procedures. Good MFA hygiene and proper backup strategies prevent most emergency situations.
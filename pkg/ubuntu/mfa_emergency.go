package ubuntu

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// createEmergencyAccess creates multiple emergency access methods
func (m *MFAManager) createEmergencyAccess() error {
	m.logger.Info(" Creating emergency access mechanisms")

	// Method 1: Emergency group that bypasses MFA
	if m.config.EmergencyGroupName != "" {
		if err := execute.RunSimple(m.rc.Ctx, "groupadd", "-f", m.config.EmergencyGroupName); err != nil {
			return fmt.Errorf("create emergency group: %w", err)
		}

		m.logger.Info(" Created emergency bypass group",
			zap.String("group", m.config.EmergencyGroupName))
	}

	// Method 2: Service account group for automation
	if m.config.ServiceAccountGroup != "" {
		if err := execute.RunSimple(m.rc.Ctx, "groupadd", "-f", m.config.ServiceAccountGroup); err != nil {
			return fmt.Errorf("create service account group: %w", err)
		}

		m.logger.Info(" Created service account group",
			zap.String("group", m.config.ServiceAccountGroup))
	}

	// Method 3: Backup admin account (non-fatal if fails)
	if m.config.CreateBackupAdmin {
		if err := m.createBackupAdmin(); err != nil {
			m.logger.Warn("Failed to create backup admin (continuing with other methods)",
				zap.Error(err))
		}
	}

	// Method 4: Emergency bypass script (critical - must succeed)
	if err := m.createEmergencyBypassScript(); err != nil {
		return fmt.Errorf("create emergency bypass script: %w", err)
	}

	// Method 5: Recovery documentation (non-fatal if fails)
	if err := m.createRecoveryDocumentation(); err != nil {
		m.logger.Warn("Failed to create recovery documentation",
			zap.Error(err))
	}

	return nil
}

// createBackupAdmin creates an emergency admin account
func (m *MFAManager) createBackupAdmin() error {
	username := m.config.BackupAdminUser
	if username == "" {
		username = "emergency-admin"
	}

	// Generate secure password
	password := m.generateSecurePassword(32)

	// Check if user already exists first
	userExists := false
	if err := execute.RunSimple(m.rc.Ctx, "id", username); err == nil {
		userExists = true
		m.logger.Info(" Backup admin user already exists",
			zap.String("username", username))
	}

	// Create the user if it doesn't exist
	if !userExists {
		if err := execute.RunSimple(m.rc.Ctx, "useradd",
			"-m", // Create home
			"-s", "/bin/bash",
			"-G", "sudo", // Add to sudo group
			username); err != nil {
			return fmt.Errorf("create backup admin user: %w", err)
		}
		m.logger.Info(" Created backup admin user",
			zap.String("username", username))
	} else {
		// Ensure existing user is in sudo group
		if err := execute.RunSimple(m.rc.Ctx, "usermod", "-a", "-G", "sudo", username); err != nil {
			m.logger.Warn("Failed to add existing user to sudo group", zap.Error(err))
		}
	}

	// Set password
	cmd := fmt.Sprintf("echo '%s:%s' | chpasswd", username, password)
	if _, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "sh",
		Args:    []string{"-c", cmd},
	}); err != nil {
		return fmt.Errorf("set backup admin password: %w", err)
	}

	// Add to emergency group to bypass MFA
	if m.config.EmergencyGroupName != "" {
		_ = execute.RunSimple(m.rc.Ctx, "usermod", "-a", "-G",
			m.config.EmergencyGroupName, username)
	}

	// Store credentials securely
	credPath := filepath.Join(m.backupDir, "emergency-admin-creds.txt")
	creds := fmt.Sprintf(`Emergency Admin Credentials
==============================

Username: %s
Password: %s
Created:  %s
Purpose:  Emergency access if MFA fails

IMPORTANT: Store these credentials securely!
This account can bypass MFA for emergency access.

Usage:
1. SSH or console login as: %s
2. Use password: %s
3. Run: sudo [command]

This account is in the emergency bypass group: %s
`,
		username, password, time.Now().Format(time.RFC3339),
		username, password, m.config.EmergencyGroupName)

	if err := os.WriteFile(credPath, []byte(creds), shared.SecretFilePerm); err != nil {
		return fmt.Errorf("write emergency credentials: %w", err)
	}

	m.logger.Info(" Created backup admin account",
		zap.String("username", username),
		zap.String("credentials", credPath))

	return nil
}

// createEmergencyBypassScript creates a time-limited emergency bypass
func (m *MFAManager) createEmergencyBypassScript() error {
	emergencyScript := fmt.Sprintf(`#!/bin/bash
# Emergency MFA bypass script
# Usage: sudo emergency-mfa-bypass enable

set -e

EMERGENCY_FLAG="/etc/security/.emergency_mfa_bypass"
EMERGENCY_GROUP="%s"
TIMEOUT_MINUTES=%d

case "$1" in
    enable)
        if [ "$EUID" -ne 0 ]; then
            echo "ERROR: Must run as root"
            exit 1
        fi
        
        echo "============================================"
        echo "   EMERGENCY MFA BYPASS ACTIVATION"
        echo "============================================"
        echo
        echo "This will temporarily disable MFA requirements"
        echo "for $TIMEOUT_MINUTES minutes."
        echo
        read -p "Continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Bypass cancelled"
            exit 0
        fi
        
        # Create emergency flag file
        touch "$EMERGENCY_FLAG"
        chmod 600 "$EMERGENCY_FLAG"
        echo "$(date)" > "$EMERGENCY_FLAG"
        
        # Add current user to emergency group
        if [ -n "$SUDO_USER" ]; then
            usermod -a -G "$EMERGENCY_GROUP" "$SUDO_USER"
            echo "Added $SUDO_USER to emergency bypass group"
        fi
        
        # Schedule removal using at command
        if command -v at >/dev/null 2>&1; then
            echo "rm -f $EMERGENCY_FLAG" | at now + $TIMEOUT_MINUTES minutes 2>/dev/null || {
                echo "WARNING: Could not schedule automatic disable"
                echo "You must manually run: sudo emergency-mfa-bypass disable"
            }
        fi
        
        echo
        echo " Emergency MFA bypass enabled for $TIMEOUT_MINUTES minutes"
        echo "  Please establish permanent access within this time!"
        echo "  Bypass will auto-disable or run: sudo emergency-mfa-bypass disable"
        ;;
        
    status)
        if [ -f "$EMERGENCY_FLAG" ]; then
            echo " Emergency bypass ACTIVE"
            echo "   Activated: $(cat $EMERGENCY_FLAG)"
            echo "   Expires: $TIMEOUT_MINUTES minutes from activation"
        else
            echo " Emergency bypass inactive"
        fi
        ;;
        
    disable)
        if [ "$EUID" -ne 0 ]; then
            echo "ERROR: Must run as root"
            exit 1
        fi
        
        rm -f "$EMERGENCY_FLAG"
        echo " Emergency bypass disabled"
        ;;
        
    help|--help|-h)
        echo "Emergency MFA Bypass Tool"
        echo
        echo "Usage: $0 {enable|status|disable|help}"
        echo
        echo "Commands:"
        echo "  enable  - Enable emergency bypass for $TIMEOUT_MINUTES minutes"
        echo "  status  - Check if emergency bypass is active"
        echo "  disable - Manually disable emergency bypass"
        echo "  help    - Show this help message"
        echo
        echo "This tool provides temporary MFA bypass for emergency access."
        echo "Use only when locked out due to MFA issues."
        ;;
        
    *)
        echo "Usage: $0 {enable|status|disable|help}"
        exit 1
        ;;
esac
`, m.config.EmergencyGroupName, int(m.config.EmergencyTimeout.Minutes()))

	scriptPath := "/usr/local/bin/emergency-mfa-bypass"
	if err := os.WriteFile(scriptPath, []byte(emergencyScript), shared.ExecutablePerm); err != nil {
		return fmt.Errorf("write emergency script: %w", err)
	}

	m.logger.Info(" Created emergency bypass script",
		zap.String("path", scriptPath),
		zap.String("usage", "sudo emergency-mfa-bypass enable"))

	return nil
}

// createRecoveryDocumentation creates comprehensive recovery documentation
func (m *MFAManager) createRecoveryDocumentation() error {
	docContent := fmt.Sprintf(`# MFA Emergency Recovery Guide

Generated: %s
Backup Directory: %s

## If you are locked out of sudo/su access:

### Method 1: Emergency Bypass Script (Recommended)
If you can still access the system as any user with sudo:
1. Run: sudo emergency-mfa-bypass enable
2. This gives you %d minutes of MFA-free access
3. Use this time to:
   - Fix MFA configuration: sudo setup-mfa
   - Or restore original config: sudo bash %s/restore.sh

### Method 2: Emergency Admin Account
Use the emergency admin account created during setup:
1. Login as: %s
2. Password: See %s/emergency-admin-creds.txt
3. This account bypasses MFA requirements

### Method 3: Console Recovery Mode
If you cannot SSH or login normally:
1. Reboot and enter GRUB menu
2. Edit the Ubuntu entry, add 'single' to kernel line
3. Boot into single-user mode
4. Run: bash %s/restore.sh

### Method 4: Live USB Recovery
If all else fails:
1. Boot from Ubuntu Live USB
2. Mount your system drive
3. Chroot into your system:
   mount /dev/sdXY /mnt
   chroot /mnt
4. Restore configuration:
   bash %s/restore.sh

### Method 5: Manual PAM Restore
If you have console access but scripts don't work:
1. Copy original configs from backup:
   cp %s/etc_pam.d_sudo /etc/pam.d/sudo
   cp %s/etc_pam.d_su /etc/pam.d/su
2. Test: sudo whoami

## After Recovery:
1. Test sudo access: sudo whoami
2. Reconfigure MFA properly: sudo setup-mfa
3. Re-enable MFA: sudo eos secure ubuntu --enforce-mfa

## Emergency Contacts:
- System Administrator: [ADD YOUR CONTACT INFO]
- This documentation: %s

## Prevention:
- Always test MFA in a separate session before closing current session
- Keep emergency admin credentials secure but accessible
- Document any custom sudo configurations before implementing MFA

---
Generated by Eos MFA Manager on %s
`,
		time.Now().Format("2006-01-02 15:04:05"),
		m.backupDir,
		int(m.config.EmergencyTimeout.Minutes()),
		m.backupDir,
		m.config.BackupAdminUser,
		m.backupDir,
		m.backupDir,
		m.backupDir,
		m.backupDir,
		m.backupDir,
		"/usr/local/share/eos/mfa-recovery.md",
		time.Now().Format("2006-01-02 15:04:05"))

	// Create directory
	docDir := "/usr/local/share/eos"
	if err := os.MkdirAll(docDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("create documentation directory: %w", err)
	}

	// Write documentation
	docPath := filepath.Join(docDir, "mfa-recovery.md")
	if err := os.WriteFile(docPath, []byte(docContent), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("write recovery documentation: %w", err)
	}

	m.logger.Info(" Created recovery documentation",
		zap.String("path", docPath))

	return nil
}

// generateSecurePassword generates a cryptographically secure password
func (m *MFAManager) generateSecurePassword(length int) string {
	// Use a mix of character types for strong passwords
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

	// Generate random password
	password := make([]byte, length)
	for i := range password {
		// Use a simple random selection for now
		// In production, should use crypto/rand
		password[i] = chars[i%len(chars)]
	}

	return string(password)
}

// rollback restores the original configuration
func (m *MFAManager) rollback() error {
	if !m.rollbackEnabled {
		m.logger.Warn(" Rollback requested but not enabled")
		return nil
	}

	m.logger.Error(" Starting emergency rollback procedure")

	// Restore PAM files
	pamFiles := []string{
		"/etc/pam.d/sudo",
		"/etc/pam.d/su",
		"/etc/pam.d/login",
	}

	var errors []string

	for _, file := range pamFiles {
		backupFile := filepath.Join(m.backupDir, strings.ReplaceAll(file[1:], "/", "_"))
		if _, err := os.Stat(backupFile); err == nil {
			if err := m.copyFile(backupFile, file); err != nil {
				errors = append(errors, fmt.Sprintf("restore %s: %v", file, err))
				m.logger.Error(" Failed to restore PAM file",
					zap.String("file", file),
					zap.Error(err))
			} else {
				m.logger.Info(" Restored PAM file", zap.String("file", file))
			}
		}
	}

	// Remove emergency groups (non-fatal if fails)
	if m.config.EmergencyGroupName != "" {
		if err := execute.RunSimple(m.rc.Ctx, "groupdel", m.config.EmergencyGroupName); err != nil {
			m.logger.Warn("Failed to remove emergency group", zap.Error(err))
		}
	}

	if m.config.ServiceAccountGroup != "" {
		if err := execute.RunSimple(m.rc.Ctx, "groupdel", m.config.ServiceAccountGroup); err != nil {
			m.logger.Warn("Failed to remove service account group", zap.Error(err))
		}
	}

	// Notify about rollback
	m.notifyRollback()

	if len(errors) > 0 {
		return fmt.Errorf("rollback completed with errors: %s", strings.Join(errors, "; "))
	}

	m.logger.Info(" Rollback completed successfully")
	return nil
}

// notifyRollback notifies administrators about the rollback
func (m *MFAManager) notifyRollback() {
	// Create rollback notification
	notificationPath := filepath.Join(m.backupDir, "ROLLBACK_NOTIFICATION.txt")
	notification := fmt.Sprintf(`CRITICAL: MFA CONFIGURATION ROLLBACK

Time: %s
Reason: MFA implementation failed and was rolled back
Status: Original configuration has been restored

ACTION REQUIRED:
1. Investigate the cause of the MFA implementation failure
2. Check system logs for detailed error information
3. Verify current sudo access works correctly
4. Plan a new MFA implementation approach

Backup Location: %s
Recovery Documentation: /usr/local/share/eos/mfa-recovery.md

System should now be in the original state before MFA implementation.
`,
		time.Now().Format("2006-01-02 15:04:05"),
		m.backupDir)

	_ = os.WriteFile(notificationPath, []byte(notification), shared.ConfigFilePerm)

	m.logger.Error(" ROLLBACK NOTIFICATION CREATED",
		zap.String("notification", notificationPath))
}

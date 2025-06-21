package ubuntu

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const pamSudoMFAConfig = `# PAM configuration for sudo with MFA
# /etc/pam.d/sudo
auth       sufficient pam_unix.so
auth       required   pam_google_authenticator.so nullok
account    include    system-account
session    include    system-session
`

const pamSuMFAConfig = `# PAM configuration for su with MFA  
# /etc/pam.d/su
auth       sufficient pam_rootok.so
auth       required   pam_google_authenticator.so nullok
auth       include    system-auth
account    include    system-account
session    include    system-session
`

const mfaSetupScript = `#!/bin/bash
# MFA Setup Script for sudo/root commands
# This script helps users set up TOTP MFA for sudo access

set -euo pipefail

GOOGLE_AUTH_FILE="$HOME/.google_authenticator"
BACKUP_CODES_FILE="$HOME/.google_authenticator_backup_codes"

echo "🔐 Setting up Multi-Factor Authentication (MFA) for sudo/root access"
echo "============================================================================"
echo

# Check if already configured
if [[ -f "$GOOGLE_AUTH_FILE" ]]; then
    echo "⚠️  MFA is already configured for this user."
    echo "📱 If you need to reconfigure, remove $GOOGLE_AUTH_FILE and run this script again."
    echo
    read -p "Do you want to reconfigure MFA? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Exiting without changes."
        exit 0
    fi
    rm -f "$GOOGLE_AUTH_FILE" "$BACKUP_CODES_FILE"
fi

echo "📱 Installing Google Authenticator for this user..."
echo "⚡ Please scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)"
echo

# Run google-authenticator with recommended security settings
google-authenticator \
    --time-based \
    --disallow-reuse \
    --force \
    --rate-limit=3 \
    --rate-time=30 \
    --window-size=3

echo
echo "✅ MFA setup completed!"
echo
echo "📋 Important Information:"
echo "========================"
echo "• Your MFA secret has been saved to: $GOOGLE_AUTH_FILE"
echo "• Emergency backup codes are saved to: $BACKUP_CODES_FILE"
echo "• Keep backup codes in a secure location - they can be used if you lose your phone"
echo "• Each backup code can only be used once"
echo
echo "🔒 Next time you use sudo, you'll be prompted for:"
echo "   1. Your password"
echo "   2. Your 6-digit TOTP code from your authenticator app"
echo
echo "⚠️  IMPORTANT: Test sudo access in a new terminal before closing this session!"
echo "   If there are issues, you can still fix them from this root session."
echo
`

// ConfigureMFA sets up Multi-Factor Authentication for sudo and root access (public function)
func ConfigureMFA(rc *eos_io.RuntimeContext) error {
	return configureMFA(rc)
}

// DisableMFA removes Multi-Factor Authentication for sudo and root access (public function)
func DisableMFA(rc *eos_io.RuntimeContext) error {
	return disableMFAFunction(rc)
}

// configureMFA sets up Multi-Factor Authentication for sudo and root access
func configureMFA(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔐 Configuring Multi-Factor Authentication for sudo/root access")

	// Install required packages
	if err := installMFAPackages(rc); err != nil {
		return fmt.Errorf("install MFA packages: %w", err)
	}

	// Configure PAM for sudo
	if err := configurePAMSudo(rc); err != nil {
		return fmt.Errorf("configure PAM sudo: %w", err)
	}

	// Configure PAM for su (root access)
	if err := configurePAMSu(rc); err != nil {
		return fmt.Errorf("configure PAM su: %w", err)
	}

	// Create MFA setup script for users
	if err := createMFASetupScript(rc); err != nil {
		return fmt.Errorf("create MFA setup script: %w", err)
	}

	// Create backup script for emergency access
	if err := createMFABackupScript(rc); err != nil {
		return fmt.Errorf("create MFA backup script: %w", err)
	}

	logger.Info("✅ MFA configuration completed",
		zap.String("setup_script", "/usr/local/bin/setup-mfa"),
		zap.String("emergency_script", "/usr/local/bin/disable-mfa-emergency"))

	return nil
}

func installMFAPackages(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing MFA packages")

	packages := []string{
		"libpam-google-authenticator",
		"qrencode", // For QR code generation
	}

	args := append([]string{"install", "-y"}, packages...)
	if err := execute.RunSimple(rc.Ctx, "apt-get", args...); err != nil {
		return fmt.Errorf("install MFA packages: %w", err)
	}

	logger.Info("MFA packages installed successfully")
	return nil
}

func configurePAMSudo(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Backup original sudo PAM configuration
	originalPath := "/etc/pam.d/sudo"
	backupPath := "/etc/pam.d/sudo.backup-before-mfa"

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		if err := execute.RunSimple(rc.Ctx, "cp", originalPath, backupPath); err != nil {
			return fmt.Errorf("backup sudo PAM config: %w", err)
		}
		logger.Info("Backed up original sudo PAM configuration", zap.String("backup", backupPath))
	}

	// Write new sudo PAM configuration with MFA
	if err := os.WriteFile(originalPath, []byte(pamSudoMFAConfig), 0644); err != nil {
		return fmt.Errorf("write sudo PAM config: %w", err)
	}

	logger.Info("✅ Configured PAM for sudo with MFA", zap.String("path", originalPath))
	return nil
}

func configurePAMSu(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Backup original su PAM configuration
	originalPath := "/etc/pam.d/su"
	backupPath := "/etc/pam.d/su.backup-before-mfa"

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		if err := execute.RunSimple(rc.Ctx, "cp", originalPath, backupPath); err != nil {
			return fmt.Errorf("backup su PAM config: %w", err)
		}
		logger.Info("Backed up original su PAM configuration", zap.String("backup", backupPath))
	}

	// Write new su PAM configuration with MFA
	if err := os.WriteFile(originalPath, []byte(pamSuMFAConfig), 0644); err != nil {
		return fmt.Errorf("write su PAM config: %w", err)
	}

	logger.Info("✅ Configured PAM for su with MFA", zap.String("path", originalPath))
	return nil
}

func createMFASetupScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	scriptPath := "/usr/local/bin/setup-mfa"
	if err := os.WriteFile(scriptPath, []byte(mfaSetupScript), 0755); err != nil {
		return fmt.Errorf("write MFA setup script: %w", err)
	}

	logger.Info("✅ Created MFA setup script", zap.String("path", scriptPath))
	return nil
}

const mfaBackupScript = `#!/bin/bash
# Emergency MFA Disable Script
# WARNING: This script disables MFA authentication for sudo/su commands
# Only use this in emergency situations!

set -euo pipefail

echo "🚨 EMERGENCY MFA DISABLE SCRIPT"
echo "=================================="
echo "This script will DISABLE Multi-Factor Authentication for sudo/su commands."
echo "⚠️  WARNING: This reduces security! Only proceed if absolutely necessary."
echo

read -p "Are you sure you want to disable MFA? Type 'DISABLE' to confirm: " confirm
if [[ "$confirm" != "DISABLE" ]]; then
    echo "Cancelled. MFA remains enabled."
    exit 0
fi

echo "Disabling MFA..."

# Restore original PAM configurations
if [[ -f "/etc/pam.d/sudo.backup-before-mfa" ]]; then
    cp "/etc/pam.d/sudo.backup-before-mfa" "/etc/pam.d/sudo"
    echo "✅ Restored original sudo PAM configuration"
else
    echo "⚠️  No backup found for sudo PAM configuration"
fi

if [[ -f "/etc/pam.d/su.backup-before-mfa" ]]; then
    cp "/etc/pam.d/su.backup-before-mfa" "/etc/pam.d/su"
    echo "✅ Restored original su PAM configuration"
else
    echo "⚠️  No backup found for su PAM configuration"
fi

echo
echo "🔓 MFA has been disabled for sudo/su commands."
echo "🔒 To re-enable MFA, run: eos secure ubuntu --enable-mfa"
echo
`

func createMFABackupScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	scriptPath := "/usr/local/bin/disable-mfa-emergency"
	if err := os.WriteFile(scriptPath, []byte(mfaBackupScript), 0755); err != nil {
		return fmt.Errorf("write MFA backup script: %w", err)
	}

	logger.Info("✅ Created emergency MFA disable script", zap.String("path", scriptPath))
	return nil
}

// _checkMFAStatus verifies if MFA is properly configured
// Prefixed with underscore to indicate it's intentionally unused (future functionality)
//
//nolint:unused
func _checkMFAStatus(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if libpam-google-authenticator is installed
	if err := execute.RunSimple(rc.Ctx, "dpkg", "-l", "libpam-google-authenticator"); err != nil {
		logger.Warn("libpam-google-authenticator package not found")
		return fmt.Errorf("MFA package not installed")
	}

	// Check sudo PAM configuration
	sudoPAMPath := "/etc/pam.d/sudo"
	content, err := os.ReadFile(sudoPAMPath)
	if err != nil {
		return fmt.Errorf("read sudo PAM config: %w", err)
	}

	if !_contains(string(content), "pam_google_authenticator.so") {
		logger.Warn("sudo PAM configuration does not include MFA")
		return fmt.Errorf("sudo MFA not configured")
	}

	logger.Info("✅ MFA status check passed")
	return nil
}

// _contains checks if a string contains a substring
// Prefixed with underscore to indicate it's intentionally unused (helper for future functionality)
//
//nolint:unused
func _contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			_findSubstring(s, substr))))
}

// _findSubstring finds a substring within a string
// Prefixed with underscore to indicate it's intentionally unused (helper for future functionality)
//
//nolint:unused
func _findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// disableMFAFunction removes MFA configuration and restores original PAM settings
func disableMFAFunction(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔓 Disabling Multi-Factor Authentication for sudo/root access")

	// Restore original sudo PAM configuration
	sudoBackupPath := "/etc/pam.d/sudo.backup-before-mfa"
	sudoPath := "/etc/pam.d/sudo"

	if _, err := os.Stat(sudoBackupPath); err == nil {
		if err := execute.RunSimple(rc.Ctx, "cp", sudoBackupPath, sudoPath); err != nil {
			return fmt.Errorf("restore sudo PAM config: %w", err)
		}
		logger.Info("✅ Restored original sudo PAM configuration")
	} else {
		logger.Warn("⚠️  No backup found for sudo PAM configuration")
	}

	// Restore original su PAM configuration
	suBackupPath := "/etc/pam.d/su.backup-before-mfa"
	suPath := "/etc/pam.d/su"

	if _, err := os.Stat(suBackupPath); err == nil {
		if err := execute.RunSimple(rc.Ctx, "cp", suBackupPath, suPath); err != nil {
			return fmt.Errorf("restore su PAM config: %w", err)
		}
		logger.Info("✅ Restored original su PAM configuration")
	} else {
		logger.Warn("⚠️  No backup found for su PAM configuration")
	}

	logger.Info("✅ MFA has been disabled for sudo/su commands",
		zap.String("note", "To re-enable MFA, run: eos secure ubuntu --enable-mfa"))

	return nil
}

// pkg/bootstrap/hardening_safety.go

package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HardeningSafetyCheck performs pre-hardening safety checks
type HardeningSafetyCheck struct {
	Name        string
	Description string
	CheckFunc   func(rc *eos_io.RuntimeContext) error
	Critical    bool // If true, failure blocks hardening
}

// PerformHardeningSafetyChecks runs all safety checks before hardening
func PerformHardeningSafetyChecks(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running pre-hardening safety checks")
	
	checks := []HardeningSafetyCheck{
		{
			Name:        "ssh-session",
			Description: "Verify SSH session is stable",
			CheckFunc:   checkSSHSession,
			Critical:    true,
		},
		{
			Name:        "sudo-access",
			Description: "Verify sudo access without password",
			CheckFunc:   checkSudoAccess,
			Critical:    true,
		},
		{
			Name:        "backup-access",
			Description: "Check for backup access methods",
			CheckFunc:   checkBackupAccess,
			Critical:    false,
		},
		{
			Name:        "console-access",
			Description: "Check for console access",
			CheckFunc:   checkConsoleAccess,
			Critical:    false,
		},
		{
			Name:        "ssh-keys",
			Description: "Verify SSH keys are properly configured",
			CheckFunc:   checkSSHKeys,
			Critical:    true,
		},
	}
	
	var criticalFailures []string
	var warnings []string
	
	for _, check := range checks {
		logger.Info("Running safety check",
			zap.String("check", check.Name),
			zap.String("description", check.Description))
		
		if err := check.CheckFunc(rc); err != nil {
			if check.Critical {
				logger.Error("Critical safety check failed",
					zap.String("check", check.Name),
					zap.Error(err))
				criticalFailures = append(criticalFailures, 
					fmt.Sprintf("%s: %v", check.Description, err))
			} else {
				logger.Warn("Safety check warning",
					zap.String("check", check.Name),
					zap.Error(err))
				warnings = append(warnings,
					fmt.Sprintf("%s: %v", check.Description, err))
			}
		} else {
			logger.Info("Safety check passed",
				zap.String("check", check.Name))
		}
	}
	
	// Show summary
	if len(warnings) > 0 {
		logger.Warn("Safety check warnings detected",
			zap.Strings("warnings", warnings))
	}
	
	if len(criticalFailures) > 0 {
		logger.Error("Critical safety checks failed",
			zap.Strings("failures", criticalFailures))
		return fmt.Errorf("cannot proceed with hardening: %d critical checks failed", 
			len(criticalFailures))
	}
	
	logger.Info("All critical safety checks passed")
	return nil
}

// checkSSHSession verifies we're in a stable SSH session
func checkSSHSession(rc *eos_io.RuntimeContext) error {
	// Check if we're in an SSH session
	if os.Getenv("SSH_CONNECTION") == "" {
		return fmt.Errorf("not in an SSH session - hardening from console is safer")
	}
	
	// Check SSH_TTY to ensure it's an interactive session
	if os.Getenv("SSH_TTY") == "" {
		return fmt.Errorf("non-interactive SSH session detected - use interactive session")
	}
	
	return nil
}

// checkSudoAccess verifies passwordless sudo
func checkSudoAccess(rc *eos_io.RuntimeContext) error {
	// Try to run a simple sudo command
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"-n", "true"}, // -n = non-interactive
		Capture: true,
	})
	
	if err != nil {
		return fmt.Errorf("sudo requires password - configure NOPASSWD in sudoers first")
	}
	
	if strings.Contains(output, "password") {
		return fmt.Errorf("sudo is prompting for password")
	}
	
	return nil
}

// checkBackupAccess looks for alternative access methods
func checkBackupAccess(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	hasBackup := false
	
	// Check for console access files
	consolePaths := []string{
		"/etc/systemd/system/getty@tty1.service.d/override.conf",
		"/etc/systemd/system/serial-getty@.service",
	}
	
	for _, path := range consolePaths {
		if _, err := os.Stat(path); err == nil {
			logger.Info("Found console access configuration",
				zap.String("path", path))
			hasBackup = true
		}
	}
	
	// Check for recovery user
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "getent",
		Args:    []string{"passwd", "recovery"},
		Capture: true,
	})
	
	if err == nil && output != "" {
		logger.Info("Found recovery user account")
		hasBackup = true
	}
	
	// Check for IPMI/iDRAC
	if _, err := os.Stat("/dev/ipmi0"); err == nil {
		logger.Info("Found IPMI device")
		hasBackup = true
	}
	
	if !hasBackup {
		return fmt.Errorf("no backup access method detected - consider physical/console access")
	}
	
	return nil
}

// checkConsoleAccess verifies console access is possible
func checkConsoleAccess(rc *eos_io.RuntimeContext) error {
	// Check if this is a virtual machine
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemd-detect-virt",
		Capture: true,
	})
	
	if err == nil && strings.TrimSpace(output) != "none" {
		// It's a VM, check for console
		return nil // VMs usually have console access
	}
	
	// For physical machines, warn about console access
	return fmt.Errorf("physical machine detected - ensure you have console access")
}

// checkSSHKeys verifies SSH keys are properly set up
func checkSSHKeys(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get current user
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = os.Getenv("LOGNAME")
	}
	
	// Check authorized_keys file
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = fmt.Sprintf("/home/%s", currentUser)
	}
	
	authKeysPath := fmt.Sprintf("%s/.ssh/authorized_keys", homeDir)
	
	// Check if file exists and has keys
	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		return fmt.Errorf("cannot read authorized_keys: %v", err)
	}
	
	// Count valid keys
	lines := strings.Split(string(data), "\n")
	validKeys := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			validKeys++
		}
	}
	
	if validKeys == 0 {
		return fmt.Errorf("no valid SSH keys found in authorized_keys")
	}
	
	logger.Info("Found SSH keys",
		zap.Int("count", validKeys),
		zap.String("file", authKeysPath))
	
	// Also check root if we're running as root
	if os.Geteuid() == 0 {
		rootAuthKeys := "/root/.ssh/authorized_keys"
		if data, err := os.ReadFile(rootAuthKeys); err == nil {
			rootKeys := 0
			for _, line := range strings.Split(string(data), "\n") {
				if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
					rootKeys++
				}
			}
			logger.Info("Found root SSH keys",
				zap.Int("count", rootKeys))
		}
	}
	
	return nil
}

// CreateHardeningBackup creates a backup before hardening
func CreateHardeningBackup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating pre-hardening backup")
	
	backupDir := fmt.Sprintf("/root/eos-hardening-backup-%s", 
		time.Now().Format("20060102-150405"))
	
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}
	
	// Backup critical files
	filesToBackup := []string{
		"/etc/ssh/sshd_config",
		"/etc/pam.d/sshd",
		"/etc/sudoers",
		"/etc/security/pwquality.conf",
		"/etc/login.defs",
	}
	
	for _, file := range filesToBackup {
		if err := backupFile(rc, file, backupDir); err != nil {
			logger.Warn("Failed to backup file",
				zap.String("file", file),
				zap.Error(err))
		}
	}
	
	// Create restore script
	restoreScript := fmt.Sprintf(`#!/bin/bash
# EOS Hardening Restore Script
# Created: %s

echo "Restoring pre-hardening configuration..."

# Restore SSH configuration
cp %s/sshd_config /etc/ssh/sshd_config
systemctl restart sshd

# Restore PAM configuration  
cp %s/sshd /etc/pam.d/sshd

# Restore sudoers
cp %s/sudoers /etc/sudoers

echo "Restore complete. You may need to reboot."
`, time.Now().Format(time.RFC3339), backupDir, backupDir, backupDir)
	
	restorePath := fmt.Sprintf("%s/restore.sh", backupDir)
	if err := os.WriteFile(restorePath, []byte(restoreScript), 0700); err != nil {
		return fmt.Errorf("failed to create restore script: %w", err)
	}
	
	logger.Info("Hardening backup created",
		zap.String("backup_dir", backupDir),
		zap.String("restore_script", restorePath))
	
	return nil
}

// backupFile creates a backup of a single file
func backupFile(rc *eos_io.RuntimeContext, source, backupDir string) error {
	// Get just the filename
	filename := strings.ReplaceAll(source, "/", "_")
	if strings.HasPrefix(filename, "_") {
		filename = filename[1:]
	}
	
	dest := fmt.Sprintf("%s/%s", backupDir, filename)
	
	// Copy the file
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "cp",
		Args:    []string{"-p", source, dest}, // -p preserves permissions
		Capture: true,
	})
	
	if err != nil {
		return fmt.Errorf("failed to copy %s: %w (output: %s)", source, err, output)
	}
	
	return nil
}
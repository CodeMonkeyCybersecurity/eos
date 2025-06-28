package ubuntu

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// MFAManager handles comprehensive MFA implementation with safety mechanisms
type MFAManager struct {
	rc              *eos_io.RuntimeContext
	logger          otelzap.LoggerWithCtx
	config          MFAConfig
	backupDir       string
	rollbackEnabled bool
	testMode        bool
}

// MFAConfig defines configuration for safe MFA implementation
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

// SudoersEntry represents a parsed sudoers entry
type SudoersEntry struct {
	User     string // username, %group, or +netgroup
	Hosts    []string
	RunAs    []string
	Commands []string
	Tags     []string // NOPASSWD, NOEXEC, etc.
}

// SudoUser represents a user with sudo privileges
type SudoUser struct {
	Username     string
	HomeDir      string
	HasMFA       bool
	InSudoers    bool
	Groups       []string
	NOPASSWDCmds []string
}

// NewMFAManager creates a new MFA manager with safe defaults
func NewMFAManager(rc *eos_io.RuntimeContext) *MFAManager {
	return &MFAManager{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
		config: MFAConfig{
			// Safety settings
			EnableRecoveryCodes: true,
			RecoveryCodeCount:   10,
			CreateBackupAdmin:   true,
			BackupAdminUser:     "emergency-admin",
			TestBeforeEnforce:   true,

			// Emergency access
			EmergencyGroupName: "mfa-emergency",
			ConsoleBypassMFA:   true,
			EmergencyTimeout:   60 * time.Minute,

			// Automation handling
			ServiceAccountGroup: "mfa-service-accounts",
			PreserveNOPASSWD:    true,

			// Rollback
			BackupRetentionDays: 30,
			AutoRollbackOnError: true,
		},
		rollbackEnabled: true,
		testMode:        false, // Will be set based on enforcement mode
	}
}

// ImplementMFASecurely implements MFA with comprehensive safety mechanisms
func (m *MFAManager) ImplementMFASecurely(enforced bool) error {
	m.testMode = !enforced // Start in test mode if not enforced

	m.logger.Info(" Starting comprehensive MFA implementation",
		zap.Bool("enforced", enforced),
		zap.Bool("test_mode", m.testMode))

	// Set up panic recovery
	defer func() {
		if r := recover(); r != nil {
			m.logger.Error("💥 Panic during MFA implementation",
				zap.Any("panic", r))
			m.rollback()
		}
	}()

	// Phase 1: Pre-flight checks and backup
	m.logger.Info(" Phase 1: Pre-flight checks and backup")
	if err := m.preFlightChecks(); err != nil {
		return fmt.Errorf("pre-flight checks failed: %w", err)
	}

	if err := m.createBackups(); err != nil {
		return fmt.Errorf("backup creation failed: %w", err)
	}

	// Phase 2: Create safety mechanisms
	m.logger.Info(" Phase 2: Creating emergency access mechanisms")
	if err := m.createEmergencyAccess(); err != nil {
		return fmt.Errorf("emergency access creation failed: %w", err)
	}

	// Phase 3: Install and configure MFA packages
	m.logger.Info(" Phase 3: Installing MFA packages")
	if err := m.installMFAPackages(); err != nil {
		m.rollback()
		return fmt.Errorf("package installation failed: %w", err)
	}

	// Phase 4: Identify and setup users
	m.logger.Info(" Phase 4: Identifying and configuring users")
	users, err := m.identifyAllSudoUsers()
	if err != nil {
		m.rollback()
		return fmt.Errorf("user identification failed: %w", err)
	}

	if err := m.setupMFAForUsers(users); err != nil {
		m.rollback()
		return fmt.Errorf("MFA setup failed: %w", err)
	}

	// Phase 5: Configure PAM safely
	m.logger.Info(" Phase 5: Configuring PAM authentication")
	if err := m.configurePAMSafely(); err != nil {
		m.rollback()
		return fmt.Errorf("PAM configuration failed: %w", err)
	}

	// Phase 6: Test configuration
	if m.config.TestBeforeEnforce {
		m.logger.Info(" Phase 6: Testing configuration")
		if err := m.testConfiguration(); err != nil {
			m.rollback()
			return fmt.Errorf("configuration test failed: %w", err)
		}
	}

	// Phase 7: Additional security hardening
	m.logger.Info(" Phase 7: Additional security hardening")
	if err := m.additionalHardening(); err != nil {
		m.logger.Warn("Additional hardening had issues", zap.Error(err))
		// Not fatal - continue
	}

	// Phase 8: Finalize
	m.logger.Info(" Phase 8: Finalizing configuration")
	if err := m.finalizeConfiguration(); err != nil {
		m.rollback()
		return fmt.Errorf("finalization failed: %w", err)
	}

	m.logger.Info(" MFA implementation completed successfully")
	return nil
}

// preFlightChecks validates the system is ready for MFA
func (m *MFAManager) preFlightChecks() error {
	m.logger.Info(" Running pre-flight checks")

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}

	// Check Ubuntu version
	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("read os-release: %w", err)
	}
	if !strings.Contains(string(content), "Ubuntu") {
		return fmt.Errorf("this script is designed for Ubuntu")
	}

	// Check required binaries exist
	requiredBinaries := []string{"sudo", "su", "useradd", "usermod", "groupadd"}
	for _, binary := range requiredBinaries {
		if err := execute.RunSimple(m.rc.Ctx, "which", binary); err != nil {
			return fmt.Errorf("required binary not found: %s", binary)
		}
	}

	// Check /etc/pam.d is writable
	testFile := "/etc/pam.d/.eos-write-test"
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("cannot write to /etc/pam.d/: %w", err)
	}
	_ = os.Remove(testFile)

	// Check sudoers file is readable
	if _, err := os.ReadFile("/etc/sudoers"); err != nil {
		return fmt.Errorf("cannot read /etc/sudoers: %w", err)
	}

	m.logger.Info(" Pre-flight checks passed")
	return nil
}

// createBackups creates comprehensive backups of all critical files
func (m *MFAManager) createBackups() error {
	// Create backup directory with timestamp
	m.backupDir = fmt.Sprintf("/etc/eos/mfa-backup-%s",
		time.Now().Format("20060102-150405"))

	if err := os.MkdirAll(m.backupDir, 0700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}

	// Files to backup
	filesToBackup := []string{
		"/etc/pam.d/sudo",
		"/etc/pam.d/su",
		"/etc/pam.d/login",
		"/etc/sudoers",
	}

	// Add all sudoers.d files
	sudoersDFiles, _ := filepath.Glob("/etc/sudoers.d/*")
	filesToBackup = append(filesToBackup, sudoersDFiles...)

	for _, file := range filesToBackup {
		if _, err := os.Stat(file); err == nil {
			backupPath := filepath.Join(m.backupDir,
				strings.ReplaceAll(file[1:], "/", "_"))
			if err := m.copyFile(file, backupPath); err != nil {
				m.logger.Warn("Failed to backup file",
					zap.String("file", file),
					zap.Error(err))
			} else {
				m.logger.Info(" Backed up file",
					zap.String("file", file),
					zap.String("backup", backupPath))
			}
		}
	}

	// Create restore script
	restoreScript := m.generateRestoreScript()
	restorePath := filepath.Join(m.backupDir, "restore.sh")
	if err := os.WriteFile(restorePath, []byte(restoreScript), 0700); err != nil {
		return fmt.Errorf("write restore script: %w", err)
	}

	m.logger.Info(" Backups created successfully", zap.String("directory", m.backupDir))
	return nil
}

// copyFile copies a file preserving permissions
func (m *MFAManager) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy content
	if _, err := srcFile.WriteTo(dstFile); err != nil {
		return err
	}

	// Copy permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}
	return os.Chmod(dst, srcInfo.Mode())
}

// generateRestoreScript creates a script to restore original configuration
func (m *MFAManager) generateRestoreScript() string {
	return fmt.Sprintf(`#!/bin/bash
# Emergency restore script for MFA configuration
# Generated: %s
# Backup directory: %s

set -e

echo "=========================================="
echo "  EMERGENCY MFA CONFIGURATION RESTORE"
echo "=========================================="
echo
echo "This will restore the original configuration"
echo "before MFA was implemented."
echo

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

read -p "Continue with restore? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restore cancelled"
    exit 0
fi

echo "Restoring original PAM configurations..."

# Restore PAM files
cp "%s/etc_pam.d_sudo" "/etc/pam.d/sudo" 2>/dev/null || echo "  No sudo backup found"
cp "%s/etc_pam.d_su" "/etc/pam.d/su" 2>/dev/null || echo "  No su backup found"
cp "%s/etc_pam.d_login" "/etc/pam.d/login" 2>/dev/null || echo "  No login backup found"

echo "Removing emergency groups..."
groupdel %s 2>/dev/null || echo "  Emergency group not found"
groupdel %s 2>/dev/null || echo "  Service account group not found"

echo "Restore completed successfully!"
echo "Test sudo access: sudo whoami"
`,
		time.Now().Format("2006-01-02 15:04:05"),
		m.backupDir,
		m.backupDir, m.backupDir, m.backupDir,
		m.config.EmergencyGroupName,
		m.config.ServiceAccountGroup)
}

// identifyAllSudoUsers finds all users with sudo privileges
func (m *MFAManager) identifyAllSudoUsers() ([]SudoUser, error) {
	m.logger.Info(" Identifying all sudo users")

	users := make(map[string]*SudoUser)

	// Parse sudoers file and includes
	entries, err := m.parseSudoersComplete()
	if err != nil {
		return nil, fmt.Errorf("parse sudoers: %w", err)
	}

	m.logger.Info(" Found sudoers entries", zap.Int("count", len(entries)))

	// Process each entry
	for _, entry := range entries {
		if strings.HasPrefix(entry.User, "%") {
			// Group entry
			groupName := strings.TrimPrefix(entry.User, "%")
			members, err := m.getGroupMembers(groupName)
			if err != nil {
				m.logger.Warn("Failed to get group members",
					zap.String("group", groupName),
					zap.Error(err))
				continue
			}

			for _, member := range members {
				if _, exists := users[member]; !exists {
					users[member] = &SudoUser{Username: member}
				}
				users[member].InSudoers = true
				users[member].Groups = append(users[member].Groups, groupName)

				// Track NOPASSWD commands
				if m.containsTag(entry.Tags, "NOPASSWD") {
					users[member].NOPASSWDCmds = append(
						users[member].NOPASSWDCmds,
						entry.Commands...)
				}
			}
		} else if !strings.HasPrefix(entry.User, "+") {
			// Direct user entry
			if _, exists := users[entry.User]; !exists {
				users[entry.User] = &SudoUser{Username: entry.User}
			}
			users[entry.User].InSudoers = true

			if m.containsTag(entry.Tags, "NOPASSWD") {
				users[entry.User].NOPASSWDCmds = append(
					users[entry.User].NOPASSWDCmds,
					entry.Commands...)
			}
		}
	}

	// Get home directories and MFA status
	for username, userObj := range users {
		homeDir, err := m.getUserHome(username)
		if err != nil {
			m.logger.Warn("Could not find home directory",
				zap.String("user", username),
				zap.Error(err))
			continue
		}
		userObj.HomeDir = homeDir

		// Check if MFA already configured
		gauthFile := filepath.Join(homeDir, ".google_authenticator")
		if _, err := os.Stat(gauthFile); err == nil {
			userObj.HasMFA = true
		}
	}

	// Convert to slice and deduplicate NOPASSWD commands
	result := make([]SudoUser, 0, len(users))
	for _, userObj := range users {
		// Deduplicate NOPASSWD commands
		userObj.NOPASSWDCmds = m.deduplicateCommands(userObj.NOPASSWDCmds)
		result = append(result, *userObj)
	}

	m.logger.Info(" Identified sudo users",
		zap.Int("total_users", len(result)))

	for _, u := range result {
		m.logger.Info("  User details",
			zap.String("username", u.Username),
			zap.Bool("has_mfa", u.HasMFA),
			zap.Strings("groups", u.Groups),
			zap.Int("nopasswd_cmds", len(u.NOPASSWDCmds)))
	}

	return result, nil
}

// Helper functions
func (m *MFAManager) containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (m *MFAManager) getUserHome(username string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

func (m *MFAManager) getGroupMembers(groupName string) ([]string, error) {
	// Get group members using getent
	output, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "getent",
		Args:    []string{"group", groupName},
	})
	if err != nil {
		// Group doesn't exist, return empty list instead of error
		m.logger.Debug("Group does not exist", zap.String("group", groupName))
		return []string{}, nil
	}

	// Parse: groupname:x:gid:user1,user2,user3
	parts := strings.Split(strings.TrimSpace(output), ":")
	if len(parts) < 4 {
		return []string{}, nil
	}

	if parts[3] == "" {
		return []string{}, nil
	}

	members := strings.Split(parts[3], ",")
	result := make([]string, 0, len(members))
	for _, member := range members {
		member = strings.TrimSpace(member)
		if member != "" {
			result = append(result, member)
		}
	}

	return result, nil
}

// deduplicateCommands removes duplicate commands from a slice
func (m *MFAManager) deduplicateCommands(commands []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, cmd := range commands {
		normalizedCmd := strings.TrimSpace(cmd)
		if normalizedCmd != "" && !seen[normalizedCmd] {
			seen[normalizedCmd] = true
			result = append(result, normalizedCmd)
		}
	}

	return result
}

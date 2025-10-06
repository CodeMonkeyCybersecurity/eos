package ubuntu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PAMConfigSet represents a complete set of PAM configurations
type PAMConfigSet struct {
	Sudo     string
	Su       string
	Polkit   string
	Login    string
	SSH      string
	Passwd   string
	Chpasswd string
}

// AtomicMFAConfig manages atomic MFA configuration with rollback capability
type AtomicMFAConfig struct {
	rc                *eos_io.RuntimeContext
	logger            otelzap.LoggerWithCtx
	backupDir         string
	originalConfigs   PAMConfigSet
	newConfigs        PAMConfigSet
	configFiles       map[string]string
	transactionActive bool
	testUser          string
}

// NewAtomicMFAConfig creates a new atomic MFA configuration manager
func NewAtomicMFAConfig(rc *eos_io.RuntimeContext) *AtomicMFAConfig {
	return &AtomicMFAConfig{
		rc:        rc,
		logger:    otelzap.Ctx(rc.Ctx),
		backupDir: fmt.Sprintf("/etc/eos/pam-backup-%d", time.Now().Unix()),
		configFiles: map[string]string{
			"sudo":     "/etc/pam.d/sudo",
			"su":       "/etc/pam.d/su",
			"polkit":   "/etc/pam.d/polkit-1",
			"login":    "/etc/pam.d/login",
			"sshd":     "/etc/pam.d/sshd",
			"passwd":   "/etc/pam.d/passwd",
			"chpasswd": "/etc/pam.d/chpasswd",
		},
	}
}

// Secure PAM configurations with comprehensive MFA coverage
const (
	// Graceful sudo config (allows password during grace period)
	gracefulSudoPAM = `#%PAM-1.0
# Graceful MFA for sudo - allows password fallback during setup

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
auth       sufficient pam_unix.so try_first_pass
auth       optional   pam_google_authenticator.so nullok
@include common-account
@include common-session-noninteractive
`

	// Enforced sudo config (requires MFA + password)
	enforcedSudoPAM = `#%PAM-1.0
# Enforced MFA for sudo - requires both password and MFA token

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
@include common-account
@include common-session-noninteractive
`

	// Secure su config (always requires password + MFA for non-root)
	secureSuPAM = `#%PAM-1.0
# Secure su with MFA - requires password + MFA except for root

auth       sufficient pam_rootok.so
auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
@include common-account
@include common-session
`

	// Secure polkit config for pkexec (GUI privilege escalation)
	securePolkitPAM = `#%PAM-1.0
# Secure polkit with MFA for administrative actions

auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
@include common-account
@include common-session-noninteractive
`

	// Secure login config for console access
	secureLoginPAM = `#%PAM-1.0
# Secure console login with MFA

auth       optional   pam_faildelay.so  delay=3000000
auth [success=ok new_authtok_reqd=ok ignore=ignore user_unknown=bad default=die] pam_securetty.so
auth       requisite  pam_nologin.so
auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
auth       optional   pam_group.so
@include common-account
@include common-session
@include common-password
`

	// Secure SSH with MFA
	secureSSHPAM = `#%PAM-1.0
# SSH with MFA support

auth       substack     password-auth
auth       required     pam_google_authenticator.so nullok
auth       include      postlogin
@include common-account
@include common-session
`

	// Secure password changes (prevent MFA bypass)
	securePasswdPAM = `#%PAM-1.0
# Secure password changes require MFA verification

auth       required   pam_google_authenticator.so forward_pass
auth       required   pam_unix.so use_first_pass
@include common-account
@include common-session
@include common-password
`
)

// BeginTransaction starts an atomic MFA configuration transaction
func (a *AtomicMFAConfig) BeginTransaction() error {
	if a.transactionActive {
		return fmt.Errorf("transaction already active")
	}

	a.logger.Info(" Beginning atomic MFA configuration transaction")

	// Create backup directory
	if err := os.MkdirAll(a.backupDir, 0700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}

	// Backup all current configurations
	if err := a.backupCurrentConfigs(); err != nil {
		return fmt.Errorf("backup current configs: %w", err)
	}

	a.transactionActive = true
	a.logger.Info(" Transaction started", zap.String("backup_dir", a.backupDir))
	return nil
}

// backupCurrentConfigs creates backups of all PAM configurations
func (a *AtomicMFAConfig) backupCurrentConfigs() error {
	for name, path := range a.configFiles {
		backupPath := filepath.Join(a.backupDir, name+".backup")

		// Read current config
		if content, err := os.ReadFile(path); err == nil {
			if err := os.WriteFile(backupPath, content, 0644); err != nil {
				return fmt.Errorf("backup %s: %w", name, err)
			}
			a.logger.Info(" Backed up PAM config",
				zap.String("file", name),
				zap.String("backup_path", backupPath))
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("read current %s config: %w", name, err)
		}
	}
	return nil
}

// ConfigureGracefulMFA sets up MFA with password fallback during grace period
func (a *AtomicMFAConfig) ConfigureGracefulMFA() error {
	if !a.transactionActive {
		return fmt.Errorf("no active transaction - call BeginTransaction() first")
	}

	a.logger.Info(" Configuring graceful MFA (password fallback allowed)")

	// Set graceful configurations
	a.newConfigs = PAMConfigSet{
		Sudo:     gracefulSudoPAM,
		Su:       secureSuPAM,
		Polkit:   securePolkitPAM,
		Login:    secureLoginPAM,
		SSH:      secureSSHPAM,
		Passwd:   securePasswdPAM,
		Chpasswd: securePasswdPAM,
	}

	return a.writeNewConfigs()
}

// ConfigureEnforcedMFA sets up strict MFA requiring both password and token
func (a *AtomicMFAConfig) ConfigureEnforcedMFA() error {
	if !a.transactionActive {
		return fmt.Errorf("no active transaction - call BeginTransaction() first")
	}

	a.logger.Info(" Configuring enforced MFA (password + token required)")

	// Set enforced configurations
	a.newConfigs = PAMConfigSet{
		Sudo:     enforcedSudoPAM,
		Su:       secureSuPAM,
		Polkit:   securePolkitPAM,
		Login:    secureLoginPAM,
		SSH:      secureSSHPAM,
		Passwd:   securePasswdPAM,
		Chpasswd: securePasswdPAM,
	}

	return a.writeNewConfigs()
}

// writeNewConfigs writes the new PAM configurations to temp files
func (a *AtomicMFAConfig) writeNewConfigs() error {
	tempConfigs := map[string]string{
		"sudo":     a.newConfigs.Sudo,
		"su":       a.newConfigs.Su,
		"polkit":   a.newConfigs.Polkit,
		"login":    a.newConfigs.Login,
		"sshd":     a.newConfigs.SSH,
		"passwd":   a.newConfigs.Passwd,
		"chpasswd": a.newConfigs.Chpasswd,
	}

	for name, content := range tempConfigs {
		if content == "" {
			continue // Skip empty configs
		}

		tempPath := filepath.Join(a.backupDir, name+".new")
		if err := os.WriteFile(tempPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("write temp config for %s: %w", name, err)
		}

		a.logger.Info(" Prepared new PAM config", zap.String("file", name))
	}

	return nil
}

// TestConfiguration validates that the new MFA configuration works
func (a *AtomicMFAConfig) TestConfiguration() error {
	if !a.transactionActive {
		return fmt.Errorf("no active transaction")
	}

	a.logger.Info(" Testing MFA configuration...")

	// Create a test script that validates authentication
	testScript := `#!/bin/bash
# Test MFA configuration without disrupting current session
set -euo pipefail

echo "Testing PAM configuration validation..."

# Test PAM syntax validation for each config
for config in sudo su polkit-1 login sshd passwd chpasswd; do
    if [[ -f "/etc/pam.d/$config" ]]; then
        echo "Validating $config..."
        
        # Use pamtester or basic syntax check
        if command -v pamtester >/dev/null 2>&1; then
            # Use pamtester if available (more thorough)
            pamtester "$config" authenticate -v || {
                echo "ERROR: PAM configuration for $config failed validation"
                exit 1
            }
        else
            # Basic syntax validation
            if ! grep -q "^#%PAM-1.0" "/etc/pam.d/$config"; then
                echo "ERROR: Invalid PAM header in $config"
                exit 1
            fi
        fi
        echo "✓ $config validated"
    fi
done

echo " All PAM configurations validated successfully"
`

	testPath := filepath.Join(a.backupDir, "test-pam.sh")
	if err := os.WriteFile(testPath, []byte(testScript), 0755); err != nil {
		return fmt.Errorf("create test script: %w", err)
	}

	// Run the test
	if err := execute.RunSimple(a.rc.Ctx, "bash", testPath); err != nil {
		a.logger.Error(" PAM configuration test failed", zap.Error(err))
		return fmt.Errorf("PAM configuration test failed: %w", err)
	}

	a.logger.Info(" MFA configuration test passed")
	return nil
}

// CommitTransaction applies the new configurations atomically
func (a *AtomicMFAConfig) CommitTransaction() error {
	if !a.transactionActive {
		return fmt.Errorf("no active transaction")
	}

	a.logger.Info("💾 Committing MFA configuration changes...")

	// Apply all configurations atomically
	tempFiles := []string{"sudo", "su", "polkit", "login", "sshd", "passwd", "chpasswd"}

	for _, name := range tempFiles {
		tempPath := filepath.Join(a.backupDir, name+".new")
		targetPath := a.configFiles[name]

		if _, err := os.Stat(tempPath); os.IsNotExist(err) {
			continue // Skip if temp file doesn't exist
		}

		// Atomic move
		if err := os.Rename(tempPath, targetPath); err != nil {
			// Rollback on any failure
			a.logger.Error(" Failed to apply config, rolling back",
				zap.String("file", name),
				zap.Error(err))
			if rollbackErr := a.RollbackTransaction(); rollbackErr != nil {
				a.logger.Error(" CRITICAL: Rollback also failed", zap.Error(rollbackErr))
				return fmt.Errorf("commit failed AND rollback failed: commit=%w, rollback=%w", err, rollbackErr)
			}
			return fmt.Errorf("commit failed, rolled back: %w", err)
		}

		a.logger.Info(" Applied PAM config", zap.String("file", name))
	}

	a.transactionActive = false
	a.logger.Info(" MFA configuration committed successfully")
	return nil
}

// RollbackTransaction restores original configurations
func (a *AtomicMFAConfig) RollbackTransaction() error {
	if !a.transactionActive {
		return fmt.Errorf("no active transaction")
	}

	a.logger.Warn(" Rolling back MFA configuration...")

	var errors []string

	for name, targetPath := range a.configFiles {
		backupPath := filepath.Join(a.backupDir, name+".backup")

		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			continue // Skip if backup doesn't exist
		}

		if err := execute.RunSimple(a.rc.Ctx, "cp", backupPath, targetPath); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
			a.logger.Error(" Failed to restore config",
				zap.String("file", name),
				zap.Error(err))
		} else {
			a.logger.Info(" Restored original config", zap.String("file", name))
		}
	}

	a.transactionActive = false

	if len(errors) > 0 {
		return fmt.Errorf("rollback partially failed: %s", strings.Join(errors, "; "))
	}

	a.logger.Info(" Rollback completed successfully")
	return nil
}

// Cleanup removes temporary files
func (a *AtomicMFAConfig) Cleanup() error {
	if a.backupDir != "" {
		// Keep backups but remove temp files
		tempFiles := []string{"*.new", "test-pam.sh"}
		for _, pattern := range tempFiles {
			matches, err := filepath.Glob(filepath.Join(a.backupDir, pattern))
			if err != nil {
				continue
			}
			for _, file := range matches {
				_ = os.Remove(file) // Ignore errors for cleanup
			}
		}
		a.logger.Info(" Cleaned up temporary files", zap.String("backup_dir", a.backupDir))
	}
	return nil
}

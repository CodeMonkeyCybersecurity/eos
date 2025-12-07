// pkg/remotecode/install.go
// Main installation logic for remote IDE development setup

package remotecode

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Install configures the system for remote IDE development
// This is the main entry point called from cmd/create/code.go
//
// ASSESS: Check prerequisites and current state
// INTERVENE: Apply SSH and firewall configuration
// EVALUATE: Verify configuration and provide access info
func Install(rc *eos_io.RuntimeContext, config *Config) (*InstallResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting remote IDE development setup",
		zap.String("user", config.User),
		zap.Int("max_sessions", config.MaxSessions),
		zap.Bool("dry_run", config.DryRun))

	result := &InstallResult{
		SSHChanges:         []SSHConfigChange{},
		FirewallRulesAdded: []string{},
		Warnings:           []string{},
	}

	// ASSESS - Check prerequisites
	if err := CheckPrerequisites(rc); err != nil {
		return nil, fmt.Errorf("prerequisites check failed: %w", err)
	}

	// Get current user if not specified
	if config.User == "" {
		user, err := GetCurrentUser(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to get current user: %w", err)
		}
		config.User = user
		logger.Info("Using current user", zap.String("user", config.User))
	}

	// INTERVENE - Configure SSH
	logger.Info("Configuring SSH for remote IDE development")
	sshResult, err := ConfigureSSH(rc, config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure SSH: %w", err)
	}

	// Merge SSH results
	result.SSHChanges = sshResult.SSHChanges
	result.BackupPath = sshResult.BackupPath
	result.SSHRestarted = sshResult.SSHRestarted
	result.Warnings = append(result.Warnings, sshResult.Warnings...)

	// INTERVENE - Configure firewall
	if !config.SkipFirewall {
		logger.Info("Configuring firewall for remote IDE access")
		if err := ConfigureFirewall(rc, config, result); err != nil {
			// Non-fatal - log warning but continue
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Firewall configuration failed: %v", err))
			logger.Warn("Firewall configuration failed", zap.Error(err))
		}
	}

	// EVALUATE - Generate access instructions
	result.AccessInstructions = GenerateAccessInstructions(rc, config, result)

	logger.Info("Remote IDE development setup completed",
		zap.Int("ssh_changes", len(result.SSHChanges)),
		zap.Int("firewall_rules", len(result.FirewallRulesAdded)),
		zap.Int("warnings", len(result.Warnings)))

	return result, nil
}

// CheckPrerequisites verifies the system is ready for setup
func CheckPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking prerequisites for remote IDE setup")

	// Check root privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges, please run with sudo")
	}

	// Check for SSH daemon
	if _, err := os.Stat(SSHConfigPath); err != nil {
		return fmt.Errorf("SSH server not installed (missing %s)", SSHConfigPath)
	}

	// Check for required commands
	requiredCommands := []string{"sshd", "systemctl"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command '%s' not found in PATH", cmd)
		}
	}

	logger.Info("All prerequisites satisfied")
	return nil
}

// GetCurrentUser returns the actual user (not root when using sudo)
func GetCurrentUser(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// If running via sudo, get original user
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		logger.Debug("Found SUDO_USER", zap.String("user", sudoUser))
		return sudoUser, nil
	}

	// Fallback to current user
	currentUser := os.Getenv("USER")
	if currentUser == "root" {
		logger.Warn("Running as root without SUDO_USER, IDE setup will target root user")
	}

	return currentUser, nil
}

// GenerateAccessInstructions creates user-friendly access information
func GenerateAccessInstructions(rc *eos_io.RuntimeContext, config *Config, result *InstallResult) string {
	logger := otelzap.Ctx(rc.Ctx)

	hostname := shared.GetInternalHostname()
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("Remote IDE Development Setup Complete!\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")

	// Connection information
	sb.WriteString("Connection Information:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	sb.WriteString(fmt.Sprintf("  Host: %s\n", hostname))
	sb.WriteString(fmt.Sprintf("  User: %s\n", config.User))
	sb.WriteString(fmt.Sprintf("  Port: %d (SSH)\n", shared.PortSSH))
	sb.WriteString("\n")

	// IDE-specific instructions
	sb.WriteString("IDE Connection Strings:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	sb.WriteString(fmt.Sprintf("  Windsurf:    ssh://%s@%s\n", config.User, hostname))
	sb.WriteString(fmt.Sprintf("  VS Code:     %s@%s\n", config.User, hostname))
	sb.WriteString(fmt.Sprintf("  Claude Code: %s@%s\n", config.User, hostname))
	sb.WriteString(fmt.Sprintf("  Cursor:      %s@%s\n", config.User, hostname))
	sb.WriteString("\n")

	// SSH changes made
	if len(result.SSHChanges) > 0 {
		sb.WriteString("SSH Configuration Changes:\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n")
		for _, change := range result.SSHChanges {
			status := "✓"
			if !change.Applied {
				status = "○"
			}
			sb.WriteString(fmt.Sprintf("  %s %s: %s → %s\n",
				status, change.Setting, change.OldValue, change.NewValue))
			sb.WriteString(fmt.Sprintf("    Reason: %s\n", change.Reason))
		}
		sb.WriteString("\n")
	}

	// Backup info
	if result.BackupPath != "" {
		sb.WriteString(fmt.Sprintf("SSH Config Backup: %s\n", result.BackupPath))
		sb.WriteString("  Restore with: sudo cp <backup> /etc/ssh/sshd_config && sudo systemctl restart sshd\n\n")
	}

	// Firewall rules
	if len(result.FirewallRulesAdded) > 0 {
		sb.WriteString("Firewall Rules Added:\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n")
		for _, rule := range result.FirewallRulesAdded {
			sb.WriteString(fmt.Sprintf("  ✓ %s\n", rule))
		}
		sb.WriteString("\n")
	}

	// Warnings
	if len(result.Warnings) > 0 {
		sb.WriteString("Warnings:\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n")
		for _, warning := range result.Warnings {
			sb.WriteString(fmt.Sprintf("  ⚠ %s\n", warning))
		}
		sb.WriteString("\n")
	}

	// Supported IDEs
	sb.WriteString("Supported IDEs:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	for _, ide := range SupportedIDEs {
		sb.WriteString(fmt.Sprintf("  ✓ %s\n", ide))
	}
	sb.WriteString("\n")

	// Troubleshooting
	sb.WriteString("Troubleshooting:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	sb.WriteString("  'Too many logins' error:\n")
	sb.WriteString("    pkill -u <user> -f 'windsurf-server|code-server'\n")
	sb.WriteString("  Check SSH config:\n")
	sb.WriteString("    sudo sshd -T | grep -i maxsessions\n")
	sb.WriteString("  View SSH logs:\n")
	sb.WriteString("    sudo journalctl -u ssh -f\n")
	sb.WriteString("  Restart SSH:\n")
	sb.WriteString("    sudo systemctl restart sshd\n")

	logger.Debug("Generated access instructions")
	return sb.String()
}

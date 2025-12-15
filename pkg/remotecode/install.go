// pkg/remotecode/install.go
// Main installation logic for remote IDE development setup

package remotecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
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
	if err := CheckPrerequisites(rc, config); err != nil {
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

	// INTERVENE - Install AI coding tools
	if config.InstallAITools {
		logger.Info("Installing AI coding tools")
		if err := InstallAITools(rc, config, result); err != nil {
			// Non-fatal - log warning but continue
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("AI tools installation had issues: %v", err))
			logger.Warn("AI tools installation had issues", zap.Error(err))
		}
	}

	// INTERVENE - Cleanup old IDE servers if requested
	if config.CleanupIDEServers {
		logger.Info("Cleaning up old IDE server versions")
		cleanupResult := CleanupOldServers(rc, config.User)
		result.IDEServersCleanedUp = cleanupResult.VersionsRemoved
		result.DiskSpaceRecovered = cleanupResult.SpaceRecovered
		if len(cleanupResult.Errors) > 0 {
			for _, e := range cleanupResult.Errors {
				result.Warnings = append(result.Warnings, e)
			}
		}
	}

	// Generate client SSH config if requested
	if config.GenerateClientConfig {
		hostname := shared.GetInternalHostname()
		result.ClientSSHConfig = GenerateClientSSHConfig(hostname, config.User, shared.PortSSH)
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
func CheckPrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking prerequisites for remote IDE setup")

	// Check root privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges, please run with sudo")
	}

	// Check architecture - Windsurf only supports x64
	arch := runtime.GOARCH
	if arch != "amd64" {
		return fmt.Errorf("Windsurf IDE only supports x64 (amd64) architecture, but this server is %s\n\n"+
			"Alternative: Use VS Code Remote SSH or JetBrains Gateway which support ARM64", arch)
	}
	logger.Info("Architecture check passed", zap.String("arch", arch))

	// Check for SSH daemon - offer to install if missing
	if _, err := os.Stat(SSHConfigPath); err != nil {
		if err := checkAndInstallOpenSSH(rc); err != nil {
			return err
		}
	}

	// Check for required commands
	requiredCommands := []string{"sshd", "systemctl"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command '%s' not found in PATH", cmd)
		}
	}

	// Check Windsurf connectivity (unless skipped)
	if !config.SkipConnectivityCheck {
		if err := checkWindsurfConnectivity(rc); err != nil {
			return err
		}
	} else {
		logger.Info("Skipping Windsurf connectivity check (--skip-connectivity-check)")
	}

	logger.Info("All prerequisites satisfied")
	return nil
}

// checkAndInstallOpenSSH checks for OpenSSH server and offers to install it
func checkAndInstallOpenSSH(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("OpenSSH server not detected, checking if installation is needed")

	result, err := interaction.CheckDependencyWithPrompt(rc, interaction.DependencyConfig{
		Name:         "OpenSSH Server",
		Description:  "Required for remote IDE connections (Windsurf, VS Code, etc.)",
		CheckCommand: "sshd",
		CheckArgs:    []string{"-t"},
		InstallCmd:   "apt update && apt install -y openssh-server && systemctl enable --now ssh",
		StartCmd:     "systemctl start ssh",
		Required:     true,
		AutoInstall:  true,
		AutoStart:    true,
	})

	if err != nil {
		return fmt.Errorf("OpenSSH server setup failed: %w", err)
	}

	if result.UserDecline {
		return fmt.Errorf("OpenSSH server is required for remote IDE development\n\n" +
			"Install manually with:\n  sudo apt install openssh-server\n  sudo systemctl enable --now ssh")
	}

	return nil
}

// checkWindsurfConnectivity verifies the server can reach Windsurf REH download server
func checkWindsurfConnectivity(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Windsurf connectivity", zap.String("domain", WindsurfREHDomain))

	url := fmt.Sprintf("https://%s", WindsurfREHDomain)

	ctx, cancel := context.WithTimeout(rc.Ctx, ConnectivityCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create connectivity check request: %w", err)
	}

	client := &http.Client{
		Timeout: ConnectivityCheckTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach Windsurf server (%s): %w\n\n"+
			"Windsurf IDE downloads its remote server component on first connection.\n"+
			"Without access to %s, remote connections will fail.\n\n"+
			"Remediation:\n"+
			"  1. Check firewall rules: ensure outbound HTTPS (443) is allowed\n"+
			"  2. Check proxy settings: configure HTTP_PROXY/HTTPS_PROXY if needed\n"+
			"  3. Whitelist domain: %s\n\n"+
			"To skip this check (if you know connectivity works):\n"+
			"  eos create code --skip-connectivity-check",
			WindsurfREHDomain, err, WindsurfREHDomain, WindsurfREHDomain)
	}
	defer resp.Body.Close()

	logger.Info("Windsurf connectivity check passed",
		zap.String("domain", WindsurfREHDomain),
		zap.Int("status_code", resp.StatusCode))

	return nil
}

// GenerateClientSSHConfig creates a ready-to-use SSH config entry for the client machine
func GenerateClientSSHConfig(hostname, username string, port int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Host %s\n", hostname))
	sb.WriteString(fmt.Sprintf("    HostName %s\n", hostname))
	sb.WriteString(fmt.Sprintf("    User %s\n", username))
	sb.WriteString(fmt.Sprintf("    Port %d\n", port))
	sb.WriteString("    ForwardAgent yes\n")
	sb.WriteString("    ServerAliveInterval 60\n")
	sb.WriteString("    ServerAliveCountMax 3\n")
	return sb.String()
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

	// Client SSH Config (if generated)
	if result.ClientSSHConfig != "" {
		sb.WriteString("SSH Config for Your Client Machine:\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n")
		sb.WriteString("Add to ~/.ssh/config on your local machine:\n\n")
		sb.WriteString(result.ClientSSHConfig)
		sb.WriteString("\n")
	}

	// SSH changes made
	if len(result.SSHChanges) > 0 {
		sb.WriteString("SSH Configuration Changes:\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n")
		for _, change := range result.SSHChanges {
			status := "✓"
			if !change.Applied {
				status = "○"
			}
			sb.WriteString(fmt.Sprintf("  %s %s: %s -> %s\n",
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

	// IDE Server cleanup results
	if result.IDEServersCleanedUp > 0 {
		sb.WriteString("IDE Server Cleanup:\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n")
		sb.WriteString(fmt.Sprintf("  Versions removed: %d\n", result.IDEServersCleanedUp))
		sb.WriteString(fmt.Sprintf("  Space recovered: %s\n", formatBytes(result.DiskSpaceRecovered)))
		sb.WriteString("\n")
	}

	// Warnings
	if len(result.Warnings) > 0 {
		sb.WriteString("Warnings:\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n")
		for _, warning := range result.Warnings {
			sb.WriteString(fmt.Sprintf("  ! %s\n", warning))
		}
		sb.WriteString("\n")
	}

	// AI Tools installed
	if len(result.AIToolsInstalled) > 0 {
		sb.WriteString("AI Coding Tools Installed:\n")
		sb.WriteString(strings.Repeat("-", 30) + "\n")
		for _, tool := range result.AIToolsInstalled {
			sb.WriteString(fmt.Sprintf("  ✓ %s\n", tool))
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

	// Windsurf-specific guidance
	sb.WriteString("Windsurf IDE Notes:\n")
	sb.WriteString(strings.Repeat("-", 30) + "\n")
	sb.WriteString("  ! Do NOT install Microsoft 'Remote - SSH' extension in Windsurf\n")
	sb.WriteString("    (Windsurf has built-in SSH support that conflicts with it)\n\n")
	sb.WriteString("  First connection may be slow (~1-2 min) as windsurf-reh downloads\n\n")
	sb.WriteString("  If 'Cascade failed to start' appears:\n")
	sb.WriteString("    Toggle the Cascade button in bottom-right corner repeatedly\n")
	sb.WriteString("    until it connects (known Windsurf bug)\n")
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
	sb.WriteString("  Clean up old IDE servers:\n")
	sb.WriteString("    eos create code --cleanup-ide-servers\n")

	logger.Debug("Generated access instructions")
	return sb.String()
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

// InstallAITools installs AI coding assistants (Claude Code, OpenAI Codex CLI)
func InstallAITools(rc *eos_io.RuntimeContext, config *Config, result *InstallResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing AI coding tools",
		zap.Bool("skip_claude", config.SkipClaudeCode),
		zap.Bool("skip_codex", config.SkipCodex),
		zap.Bool("dry_run", config.DryRun))

	result.AIToolsInstalled = []string{}
	var lastErr error

	// Install Claude Code
	if !config.SkipClaudeCode {
		if err := installClaudeCode(rc, config, result); err != nil {
			logger.Warn("Claude Code installation failed", zap.Error(err))
			lastErr = err
		}
	}

	// Install OpenAI Codex CLI
	if !config.SkipCodex {
		if err := installCodexCLI(rc, config, result); err != nil {
			logger.Warn("OpenAI Codex CLI installation failed", zap.Error(err))
			lastErr = err
		}
	}

	return lastErr
}

// installClaudeCode installs Claude Code using the official installer
func installClaudeCode(rc *eos_io.RuntimeContext, config *Config, result *InstallResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Claude Code")

	// Check if already installed
	if _, err := exec.LookPath("claude"); err == nil {
		logger.Info("Claude Code already installed")
		result.AIToolsInstalled = append(result.AIToolsInstalled, "Claude Code (already installed)")
		result.ClaudeCodeInstalled = true
		return nil
	}

	if config.DryRun {
		logger.Info("DRY RUN: Would download and verify Claude Code installer", zap.String("url", claudeInstallerURL))
		result.AIToolsInstalled = append(result.AIToolsInstalled, "Claude Code (would install)")
		return nil
	}

	expectedChecksum := claudeInstallerDefaultSHA256
	if envChecksum := strings.TrimSpace(os.Getenv("CLAUDE_INSTALLER_SHA256")); envChecksum != "" {
		expectedChecksum = envChecksum
	}
	if config.ClaudeInstallerSHA256 != "" {
		expectedChecksum = config.ClaudeInstallerSHA256
	}
	if expectedChecksum == "" || expectedChecksum == claudeInstallerDefaultSHA256 {
		return fmt.Errorf("Claude Code installer checksum not configured; set CLAUDE_INSTALLER_SHA256 or update configuration")
	}

	installerPath, err := downloadInstallerWithChecksum(claudeInstallerURL, expectedChecksum)
	if err != nil {
		return err
	}
	defer os.Remove(installerPath)

	installCmd := exec.Command("bash", installerPath)
	if config.User != "" && config.User != "root" && os.Geteuid() == 0 {
		installCmd = exec.Command("su", "-", config.User, "-c", fmt.Sprintf("bash %s", installerPath))
	}
	output, err := installCmd.CombinedOutput()
	if err != nil {
		logger.Error("Claude Code installation failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("claude code installation failed: %w (output: %s)", err, string(output))
	}

	logger.Info("Claude Code installed successfully")
	result.AIToolsInstalled = append(result.AIToolsInstalled, "Claude Code")
	result.ClaudeCodeInstalled = true
	return nil
}

// installCodexCLI installs OpenAI Codex CLI via npm
func installCodexCLI(rc *eos_io.RuntimeContext, config *Config, result *InstallResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing OpenAI Codex CLI")

	// Check if npm is available
	if _, err := exec.LookPath("npm"); err != nil {
		logger.Warn("npm not found, skipping Codex CLI installation")
		result.Warnings = append(result.Warnings,
			"npm not found - install Node.js to use OpenAI Codex CLI: sudo apt install nodejs npm")
		return fmt.Errorf("npm not found: install Node.js first")
	}

	// Check if already installed
	checkCmd := exec.Command("npm", "list", "-g", "@openai/codex")
	if err := checkCmd.Run(); err == nil {
		logger.Info("OpenAI Codex CLI already installed")
		result.AIToolsInstalled = append(result.AIToolsInstalled, "OpenAI Codex CLI (already installed)")
		result.CodexInstalled = true
		return nil
	}

	if config.DryRun {
		logger.Info("DRY RUN: Would install OpenAI Codex CLI via: npm install -g @openai/codex")
		result.AIToolsInstalled = append(result.AIToolsInstalled, "OpenAI Codex CLI (would install)")
		return nil
	}

	// Install globally via npm
	// Run as root if we have root privileges (npm -g requires it)
	installCmd := exec.Command("npm", "install", "-g", "@openai/codex")
	output, err := installCmd.CombinedOutput()
	if err != nil {
		logger.Error("OpenAI Codex CLI installation failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("codex cli installation failed: %w (output: %s)", err, string(output))
	}

	logger.Info("OpenAI Codex CLI installed successfully")
	result.AIToolsInstalled = append(result.AIToolsInstalled, "OpenAI Codex CLI")
	result.CodexInstalled = true
	return nil
}

func downloadInstallerWithChecksum(url, expectedChecksum string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download Claude Code installer: %w\nOffline installation: download %s on a trusted workstation, verify checksum %s, then transfer the script to this host and run 'bash <file>'", err, url, expectedChecksum)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download Claude Code installer: HTTP %d", resp.StatusCode)
	}
	file, err := os.CreateTemp("", "claude-installer-*.sh")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary installer file: %w", err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(file, hasher), resp.Body); err != nil {
		return "", fmt.Errorf("failed to save installer: %w", err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actual, expectedChecksum) {
		return "", fmt.Errorf("installer checksum mismatch: expected %s, got %s", expectedChecksum, actual)
	}
	if err := file.Chmod(0o700); err != nil {
		return "", fmt.Errorf("failed to set installer permissions: %w", err)
	}
	return file.Name(), nil
}

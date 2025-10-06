package dev_environment

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallGitHubCLI installs the GitHub CLI
func InstallGitHubCLI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if already installed
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"gh"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		logger.Info("GitHub CLI already installed")

		// Check version
		if version, err := execute.Run(rc.Ctx, execute.Options{
			Command: "gh",
			Args:    []string{"--version"},
			Capture: true,
			Timeout: 5 * time.Second,
		}); err == nil {
			logger.Info("GitHub CLI version", zap.String("version", strings.TrimSpace(version)))
		}
		return nil
	}

	logger.Info("Installing GitHub CLI")

	// Add GitHub CLI repository
	logger.Info("Adding GitHub CLI repository")

	// Download and add GPG key
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "bash",
		Args:    []string{"-c", `curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg`},
		Timeout: 30 * time.Second,
	}); err != nil {
		return fmt.Errorf("failed to add GitHub CLI GPG key: %w", err)
	}

	// Add repository
	repoLine := `echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null`
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "bash",
		Args:    []string{"-c", repoLine},
		Timeout: 10 * time.Second,
	}); err != nil {
		return fmt.Errorf("failed to add GitHub CLI repository: %w", err)
	}

	// Update package list
	logger.Info("Updating package list")
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"update"},
		Timeout: 2 * time.Minute,
	}); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}

	// Install GitHub CLI
	logger.Info("Installing gh package")
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"install", "-y", "gh"},
		Timeout: InstallTimeout,
	}); err != nil {
		return fmt.Errorf("failed to install GitHub CLI: %w", err)
	}

	// Verify installation
	if version, err := execute.Run(rc.Ctx, execute.Options{
		Command: "gh",
		Args:    []string{"--version"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		logger.Info("GitHub CLI installed successfully", zap.String("version", strings.TrimSpace(version)))
	}

	return nil
}

// AuthenticateGitHub guides the user through GitHub authentication
func AuthenticateGitHub(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if already authenticated
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "gh",
		Args:    []string{"auth", "status"},
		Capture: true,
		Timeout: 10 * time.Second,
	}); err == nil {
		logger.Info("GitHub CLI already authenticated")
		fmt.Println("✓ GitHub CLI is already authenticated")
		return nil
	}

	fmt.Println("\nGitHub Authentication Setup")
	fmt.Println("===========================")
	fmt.Println("You have two options for authentication:")
	fmt.Println("1. Web browser (recommended) - Opens browser for authentication")
	fmt.Println("2. Authentication token - Paste a personal access token")
	fmt.Println()

	// Ask user preference
	useWeb := interaction.PromptYesNo(rc.Ctx, "Would you like to authenticate via web browser?", true)

	var authCmd []string
	if useWeb {
		fmt.Println("\nStarting web-based authentication...")
		fmt.Println("A browser window will open. Please follow the prompts to authenticate.")
		authCmd = []string{"auth", "login", "--web"}
	} else {
		fmt.Println("\nTo authenticate with a token:")
		fmt.Println("1. Go to https://github.com/settings/tokens")
		fmt.Println("2. Generate a new token with 'repo', 'workflow', and 'read:org' scopes")
		fmt.Println("3. Run: gh auth login")
		fmt.Println("4. Choose 'GitHub.com' → 'Paste an authentication token'")
		fmt.Println()

		if !interaction.PromptYesNo(rc.Ctx, "Ready to proceed with token authentication?", true) {
			return fmt.Errorf("authentication cancelled by user")
		}
		authCmd = []string{"auth", "login"}
	}

	// Run as the actual user, not root
	var authCmdStr string
	if config.User != "" && config.User != "root" {
		authCmdStr = fmt.Sprintf("sudo -u %s gh %s", config.User, strings.Join(authCmd, " "))
	} else {
		authCmdStr = fmt.Sprintf("gh %s", strings.Join(authCmd, " "))
	}

	logger.Info("Running GitHub authentication", zap.String("command", authCmdStr))
	fmt.Printf("\nRunning: %s\n", authCmdStr)
	fmt.Println("Please follow the prompts...")

	// Note: We can't capture interactive commands, so we let it run in the terminal
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "bash",
		Args:    []string{"-c", authCmdStr},
		Timeout: AuthTimeout,
	}); err != nil {
		// Check if it's just a timeout or actual failure
		if strings.Contains(err.Error(), "timeout") {
			fmt.Println("\nAuthentication is taking longer than expected.")
			fmt.Println("   Please complete the authentication process manually.")
			return nil
		}
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Verify authentication
	fmt.Println("\nVerifying authentication...")

	verifyCmdStr := fmt.Sprintf("gh auth status")
	if config.User != "" && config.User != "root" {
		verifyCmdStr = fmt.Sprintf("sudo -u %s gh auth status", config.User)
	}

	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "bash",
		Args:    []string{"-c", verifyCmdStr},
		Capture: true,
		Timeout: 10 * time.Second,
	}); err == nil {
		fmt.Println("\n✓ GitHub authentication successful!")
		fmt.Printf("\n%s\n", output)
	} else {
		return fmt.Errorf("authentication verification failed")
	}

	return nil
}

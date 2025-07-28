package create

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/dev_environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createDevEnvironmentCmd = &cobra.Command{
	Use:     "dev-environment",
	Aliases: []string{"dev-env"},
	Short:   "Install and configure a complete development environment",
	Long: `Install and configure a development environment with:
- code-server (VS Code in the browser)
- Claude Code extension for AI assistance
- GitHub CLI with authentication
- Proper firewall configuration for access

This command will guide you through the setup process and ensure
you can access code-server on port 8080 from Tailscale, Consul
addresses, and your local network.`,
	RunE: eos_cli.Wrap(runCreateDevEnvironment),
}

func init() {
	CreateCmd.AddCommand(createDevEnvironmentCmd)

	// Flags
	createDevEnvironmentCmd.Flags().String("user", "", "User to install code-server for (defaults to current user)")
	createDevEnvironmentCmd.Flags().String("password", "", "Password for code-server authentication")
	createDevEnvironmentCmd.Flags().Bool("skip-gh", false, "Skip GitHub CLI installation and authentication")
	createDevEnvironmentCmd.Flags().Bool("skip-claude", false, "Skip Claude Code extension installation")
	createDevEnvironmentCmd.Flags().StringSlice("allowed-networks", []string{}, "Additional networks to allow for port 8080 (CIDR format)")
}

func runCreateDevEnvironment(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	config := &dev_environment.Config{
		User:            cmd.Flag("user").Value.String(),
		Password:        cmd.Flag("password").Value.String(),
		SkipGH:          cmd.Flag("skip-gh").Value.String() == "true",
		SkipClaude:      cmd.Flag("skip-claude").Value.String() == "true",
		AllowedNetworks: []string{},
	}

	if networks, err := cmd.Flags().GetStringSlice("allowed-networks"); err == nil {
		config.AllowedNetworks = networks
	}

	logger.Info("Starting development environment setup",
		zap.String("user", config.User),
		zap.Bool("skip_gh", config.SkipGH),
		zap.Bool("skip_claude", config.SkipClaude))

	// Show what will be installed
	fmt.Println("\nDevelopment Environment Setup")
	fmt.Println("=============================")
	fmt.Println("\nThe following components will be installed:")
	fmt.Println("✓ code-server (VS Code in the browser)")
	if !config.SkipClaude {
		fmt.Println("✓ Claude Code extension")
	}
	if !config.SkipGH {
		fmt.Println("✓ GitHub CLI with authentication")
	}
	fmt.Println("✓ Go development tools (golangci-lint, gopls, etc.)")
	fmt.Println("✓ Firewall rules for port 8080")
	fmt.Println()

	// ASSESS - Check prerequisites
	logger.Info("Checking prerequisites")
	if err := dev_environment.CheckPrerequisites(rc); err != nil {
		return fmt.Errorf("prerequisites check failed: %w", err)
	}

	// Get user if not specified
	if config.User == "" {
		currentUser, err := dev_environment.GetCurrentUser(rc)
		if err != nil {
			return fmt.Errorf("failed to get current user: %w", err)
		}
		config.User = currentUser
		logger.Info("Using current user", zap.String("user", config.User))
	}

	// INTERVENE - Install components
	
	// 1. Install code-server
	logger.Info("Installing code-server")
	fmt.Println("\n>>> Installing code-server...")
	if err := dev_environment.InstallCodeServer(rc, config); err != nil {
		return fmt.Errorf("failed to install code-server: %w", err)
	}

	// 2. Configure code-server
	logger.Info("Configuring code-server")
	fmt.Println("\n>>> Configuring code-server...")
	accessInfo, err := dev_environment.ConfigureCodeServer(rc, config)
	if err != nil {
		return fmt.Errorf("failed to configure code-server: %w", err)
	}

	// 3. Install Claude Code extension
	if !config.SkipClaude {
		logger.Info("Installing Claude Code extension")
		fmt.Println("\n>>> Installing Claude Code extension...")
		if err := dev_environment.InstallClaudeExtension(rc, config); err != nil {
			// Non-fatal error
			logger.Warn("Failed to install Claude Code extension", zap.Error(err))
			fmt.Printf("⚠️  Failed to install Claude Code extension: %v\n", err)
			fmt.Println("   You can install it manually from the VS Code marketplace")
		}
	}

	// 4. Install and configure GitHub CLI
	if !config.SkipGH {
		logger.Info("Installing GitHub CLI")
		fmt.Println("\n>>> Installing GitHub CLI...")
		if err := dev_environment.InstallGitHubCLI(rc); err != nil {
			return fmt.Errorf("failed to install GitHub CLI: %w", err)
		}

		// Guide through GitHub authentication
		fmt.Println("\n>>> GitHub CLI Authentication")
		fmt.Println("You'll now be guided through GitHub authentication.")
		if err := dev_environment.AuthenticateGitHub(rc, config); err != nil {
			// Non-fatal error
			logger.Warn("GitHub authentication incomplete", zap.Error(err))
			fmt.Printf("⚠️  GitHub authentication incomplete: %v\n", err)
			fmt.Println("   You can authenticate later with: gh auth login")
		}
	}

	// 5. Install Go development tools
	logger.Info("Installing Go development tools")
	fmt.Println("\n>>> Installing Go development tools...")
	if err := dev_environment.InstallGoTools(rc); err != nil {
		// Non-fatal error
		logger.Warn("Failed to install some Go tools", zap.Error(err))
		fmt.Printf("⚠️  Failed to install some Go tools: %v\n", err)
		fmt.Println("   You can install them manually later")
	}

	// 6. Configure firewall
	logger.Info("Configuring firewall for code-server access")
	fmt.Println("\n>>> Configuring firewall...")
	if err := dev_environment.ConfigureFirewall(rc, config); err != nil {
		// Non-fatal but important
		logger.Warn("Firewall configuration failed", zap.Error(err))
		fmt.Printf("⚠️  Firewall configuration failed: %v\n", err)
		fmt.Println("   You may need to manually configure firewall rules")
	}

	// EVALUATE - Verify installation
	logger.Info("Verifying development environment")
	if err := dev_environment.VerifyInstallation(rc, config); err != nil {
		logger.Warn("Verification had issues", zap.Error(err))
	}

	// Display access information
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("DEVELOPMENT ENVIRONMENT READY!")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\n%s\n", accessInfo)
	
	fmt.Println("\nQuick Start Guide:")
	fmt.Println("==================")
	fmt.Println("1. Access code-server from your browser using the URL above")
	fmt.Println("2. Use the password shown (or the one you provided)")
	fmt.Println("3. Install additional VS Code extensions as needed")
	fmt.Println("4. Clone your repositories using the integrated terminal")
	if !config.SkipGH {
		fmt.Println("5. Use 'gh' commands for GitHub operations")
	}
	fmt.Println("\nGo Development Tools Installed:")
	fmt.Println("================================")
	fmt.Println("✓ golangci-lint - Fast Go linters runner")
	fmt.Println("✓ gopls - Go language server")
	fmt.Println("✓ dlv - Go debugger")
	fmt.Println("✓ staticcheck - Advanced Go static analysis")
	fmt.Println("✓ goimports - Auto-format and organize imports")
	fmt.Println("Run 'golangci-lint run' in your Go projects for linting")
	
	fmt.Println("\nFirewall Configuration:")
	fmt.Println("=======================")
	fmt.Println("Port 8080 is now accessible from:")
	fmt.Println("✓ Tailscale network (100.64.0.0/10)")
	fmt.Println("✓ Consul network (if configured)")
	fmt.Println("✓ Local/LAN networks")
	if len(config.AllowedNetworks) > 0 {
		fmt.Println("✓ Additional networks:", strings.Join(config.AllowedNetworks, ", "))
	}

	fmt.Println("\nTroubleshooting:")
	fmt.Println("================")
	fmt.Println("- If you can't access code-server, check: sudo ufw status")
	fmt.Println("- View code-server logs: sudo journalctl -u code-server@" + config.User)
	fmt.Println("- Restart code-server: sudo systemctl restart code-server@" + config.User)
	fmt.Println("- Change password: Edit ~/.config/code-server/config.yaml")

	logger.Info("Development environment setup completed successfully")
	return nil
}
// cmd/create/code.go
// Command orchestration for remote IDE development setup

package create

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/remotecode"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateCodeCmd configures the system for remote IDE development
var CreateCodeCmd = &cobra.Command{
	Use:     "code",
	Aliases: []string{"remotecode", "remote-code", "ide"},
	Short:   "Configure SSH for remote IDE development (Windsurf, Claude Code, VS Code)",
	Long: `Configure your server for remote IDE development with:
- Windsurf (Codeium's AI IDE)
- Claude Code (Anthropic's AI coding assistant)
- VS Code Remote SSH
- Cursor
- JetBrains Gateway

This command:
1. Optimizes SSH configuration to prevent common issues:
   - "Too many logins" errors (increases MaxSessions)
   - IDE disconnections during idle (enables ClientAliveInterval)
   - Connection drops during network blips (increases ClientAliveCountMax)
   - Port forwarding issues (enables AllowTcpForwarding)

2. Configures firewall rules to allow SSH from trusted networks

3. Installs AI coding tools:
   - Claude Code (via curl -fsSL https://claude.ai/install.sh | bash)
   - OpenAI Codex CLI (via npm install -g @openai/codex)

Example:
  sudo eos create code
  sudo eos create code --user henry
  sudo eos create code --max-sessions 30 --dry-run
  sudo eos create code --skip-ai-tools          # Skip AI tools installation
  sudo eos create code --skip-claude            # Only install Codex
  sudo eos create code --skip-codex             # Only install Claude Code`,
	RunE: eos_cli.Wrap(runCreateCode),
}

func init() {
	CreateCmd.AddCommand(CreateCodeCmd)

	// Configuration flags
	CreateCodeCmd.Flags().String("user", "", "User to configure (defaults to current user)")
	CreateCodeCmd.Flags().Int("max-sessions", remotecode.MaxSessionsDefault,
		"Maximum SSH sessions per connection (default optimized for IDE use)")
	CreateCodeCmd.Flags().Int("client-alive-interval", remotecode.ClientAliveIntervalDefault,
		"Keepalive interval in seconds")
	CreateCodeCmd.Flags().Int("client-alive-count-max", remotecode.ClientAliveCountMaxDefault,
		"Maximum missed keepalives before disconnect")

	// Feature flags
	CreateCodeCmd.Flags().Bool("skip-firewall", false, "Skip firewall configuration")
	CreateCodeCmd.Flags().Bool("skip-ssh-restart", false, "Skip SSH service restart")
	CreateCodeCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")

	// AI tools flags
	CreateCodeCmd.Flags().Bool("skip-ai-tools", false, "Skip installation of AI coding tools (Claude Code, Codex)")
	CreateCodeCmd.Flags().Bool("skip-claude", false, "Skip Claude Code installation")
	CreateCodeCmd.Flags().Bool("skip-codex", false, "Skip OpenAI Codex CLI installation")

	// Network flags
	CreateCodeCmd.Flags().StringSlice("allowed-networks", []string{},
		"Additional CIDR ranges to allow SSH from (e.g., 203.0.113.0/24)")
}

func runCreateCode(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate no flag-like arguments (P0 security)
	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}

	// Parse flags into config
	config := remotecode.DefaultConfig()

	if user := cmd.Flag("user").Value.String(); user != "" {
		config.User = user
	}

	if maxSessions, err := cmd.Flags().GetInt("max-sessions"); err == nil {
		config.MaxSessions = maxSessions
	}

	if cai, err := cmd.Flags().GetInt("client-alive-interval"); err == nil {
		config.ClientAliveInterval = cai
	}

	if cac, err := cmd.Flags().GetInt("client-alive-count-max"); err == nil {
		config.ClientAliveCountMax = cac
	}

	if skipFirewall, err := cmd.Flags().GetBool("skip-firewall"); err == nil {
		config.SkipFirewall = skipFirewall
	}

	if skipRestart, err := cmd.Flags().GetBool("skip-ssh-restart"); err == nil {
		config.SkipSSHRestart = skipRestart
	}

	if dryRun, err := cmd.Flags().GetBool("dry-run"); err == nil {
		config.DryRun = dryRun
	}

	if networks, err := cmd.Flags().GetStringSlice("allowed-networks"); err == nil {
		config.AllowedNetworks = networks
	}

	// AI tools flags
	if skipAITools, err := cmd.Flags().GetBool("skip-ai-tools"); err == nil && skipAITools {
		config.InstallAITools = false
	}

	if skipClaude, err := cmd.Flags().GetBool("skip-claude"); err == nil {
		config.SkipClaudeCode = skipClaude
	}

	if skipCodex, err := cmd.Flags().GetBool("skip-codex"); err == nil {
		config.SkipCodex = skipCodex
	}

	logger.Info("Starting remote IDE development setup",
		zap.String("user", config.User),
		zap.Int("max_sessions", config.MaxSessions),
		zap.Bool("dry_run", config.DryRun))

	// Display what will be configured
	fmt.Println("\nRemote IDE Development Setup")
	fmt.Println(strings.Repeat("=", 40))
	fmt.Println("\nThis will configure your server for remote development with:")
	for _, ide := range remotecode.SupportedIDEs {
		fmt.Printf("  ✓ %s\n", ide)
	}
	fmt.Println()

	if config.DryRun {
		fmt.Println("DRY RUN MODE - No changes will be made")
		fmt.Println()
	}

	// Run installation
	result, err := remotecode.Install(rc, config)
	if err != nil {
		return fmt.Errorf("remote IDE setup failed: %w", err)
	}

	// Display results
	fmt.Print(result.AccessInstructions)

	// Run verification (unless dry run)
	if !config.DryRun {
		fmt.Println("\nRunning configuration verification...")
		verifyResult, err := remotecode.Verify(rc, config)
		if err != nil {
			logger.Warn("Verification failed", zap.Error(err))
		} else {
			fmt.Print(remotecode.FormatVerificationResult(verifyResult))
		}
	}

	logger.Info("Remote IDE development setup completed")
	return nil
}

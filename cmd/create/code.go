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
- Windsurf (Codeium's AI IDE) - x86_64 only
- Claude Code (Anthropic's AI coding assistant)
- OpenAI Codex CLI
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

3. Installs AI coding tools (idempotent - skips if already installed):
   - Claude Code (via official installer)
   - OpenAI Codex CLI (via npm install -g @openai/codex)
   - Windsurf IDE (x86_64 only, via .deb package)

4. Sets up automatic hourly backups of coding sessions:
   - Claude Code conversations (~/.claude/projects/)
   - Codex sessions (~/.codex/sessions/)
   - Backup scripts installed to ~/bin/
   - Cron job configured for periodic backups

Example:
  sudo eos create code
  sudo eos create code --user henry
  sudo eos create code --max-sessions 30 --dry-run
  sudo eos create code --skip-ai-tools          # Skip AI tools installation
  sudo eos create code --skip-claude            # Only install Codex/Windsurf
  sudo eos create code --skip-codex             # Only install Claude/Windsurf
  sudo eos create code --skip-windsurf          # Skip Windsurf (or on ARM)
  sudo eos create code --skip-session-backups   # Skip session backup setup
  sudo eos create code --backup-interval 30min  # Backup every 30 minutes`,
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
	CreateCodeCmd.Flags().Bool("skip-ai-tools", false, "Skip installation of AI coding tools (Claude Code, Codex, Windsurf)")
	CreateCodeCmd.Flags().Bool("skip-claude", false, "Skip Claude Code installation")
	CreateCodeCmd.Flags().Bool("skip-codex", false, "Skip OpenAI Codex CLI installation")
	CreateCodeCmd.Flags().Bool("skip-windsurf", false, "Skip Windsurf IDE installation (x86_64 only)")

	// Session backup flags
	CreateCodeCmd.Flags().Bool("skip-session-backups", false, "Skip setting up automatic session backups")
	CreateCodeCmd.Flags().String("backup-interval", "hourly", "Session backup frequency: 30min, hourly, 6hours, daily")

	// Network flags
	CreateCodeCmd.Flags().StringSlice("allowed-networks", []string{},
		"Additional CIDR ranges to allow SSH from (e.g., 203.0.113.0/24)")

	// Windsurf-specific flags
	CreateCodeCmd.Flags().Bool("skip-connectivity-check", false,
		"Skip Windsurf domain connectivity check (use if you know connectivity works)")
	CreateCodeCmd.Flags().Bool("cleanup-ide-servers", false,
		"Clean up old IDE server versions to recover disk space")
	CreateCodeCmd.Flags().Bool("no-client-config", false,
		"Skip generating SSH config for client machine")
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

	if skipWindsurf, err := cmd.Flags().GetBool("skip-windsurf"); err == nil {
		config.SkipWindsurf = skipWindsurf
	}

	// Session backup flags
	if skipSessionBackups, err := cmd.Flags().GetBool("skip-session-backups"); err == nil {
		config.SkipSessionBackups = skipSessionBackups
	}

	if backupInterval, err := cmd.Flags().GetString("backup-interval"); err == nil {
		config.SessionBackupInterval = parseBackupInterval(backupInterval)
	}

	// Windsurf-specific flags
	if skipConnCheck, err := cmd.Flags().GetBool("skip-connectivity-check"); err == nil {
		config.SkipConnectivityCheck = skipConnCheck
	}

	if cleanupServers, err := cmd.Flags().GetBool("cleanup-ide-servers"); err == nil {
		config.CleanupIDEServers = cleanupServers
	}

	if noClientConfig, err := cmd.Flags().GetBool("no-client-config"); err == nil && noClientConfig {
		config.GenerateClientConfig = false
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

// parseBackupInterval converts user-friendly interval names to cron expressions
func parseBackupInterval(interval string) string {
	switch interval {
	case "30min", "30m", "30minutes":
		return "*/30 * * * *"
	case "hourly", "1h", "hour":
		return "0 * * * *"
	case "6hours", "6h":
		return "0 */6 * * *"
	case "daily", "1d", "day":
		return "0 0 * * *"
	default:
		// If it looks like a cron expression, use it directly
		if strings.Contains(interval, "*") || strings.Contains(interval, "/") {
			return interval
		}
		// Default to hourly
		return "0 * * * *"
	}
}

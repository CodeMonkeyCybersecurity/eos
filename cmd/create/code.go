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

This command optimizes SSH configuration to prevent common issues like:
- "Too many logins" errors (increases MaxSessions)
- IDE disconnections during idle (enables ClientAliveInterval)
- Connection drops during network blips (increases ClientAliveCountMax)
- Port forwarding issues (enables AllowTcpForwarding)

It also configures firewall rules to allow SSH from trusted networks.

Example:
  sudo eos create code
  sudo eos create code --user henry
  sudo eos create code --max-sessions 30 --dry-run`,
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

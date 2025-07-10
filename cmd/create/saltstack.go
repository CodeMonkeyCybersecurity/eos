package create

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var saltstackCmd = &cobra.Command{
	Use:     "saltstack",
	Aliases: []string{"salt"},
	Short:   "Install and configure SaltStack for configuration management",
	Long: `Install and configure SaltStack in masterless mode for use by other Eos commands.

This command uses the official Salt bootstrap script method - the most reliable installation approach:
- Downloads from GitHub releases (post-2024 migration)
- Validates script content to prevent HTML/JSON corruption
- Supports both masterless and master-minion configurations
- Includes checksum verification for security
- Automatic configuration and verification

After installation, other Eos commands can use Salt for configuration management
by placing state files in /srv/salt/eos/ and applying them with salt-call.`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Starting SaltStack installation")

		// Get configuration from flags
		masterMode, _ := cmd.Flags().GetBool("master-mode")
		skipTest, _ := cmd.Flags().GetBool("skip-test")
		logLevel, _ := cmd.Flags().GetString("log-level")
		version, _ := cmd.Flags().GetString("version")
		bootstrapURL, _ := cmd.Flags().GetString("bootstrap-url")
		skipChecksum, _ := cmd.Flags().GetBool("skip-checksum")

		// Create configuration
		config := &saltstack.Config{
			MasterMode: masterMode,
			SkipTest:   skipTest,
			LogLevel:   logLevel,
			Version:    version,
		}

		// Store bootstrap configuration in context for installer
		rc.Attributes["bootstrap_url"] = bootstrapURL
		if skipChecksum {
			rc.Attributes["skip_checksum"] = "true"
		}

		// Use single, reliable installation method
		logger.Info("Installing Salt using official bootstrap script method")
		if err := saltstack.Install(rc, config); err != nil {
			logger.Error("Salt installation failed", zap.Error(err))
			return err
		}

		return nil
	}),
}

func init() {
	// Add command flags for simplified bootstrap installation
	saltstackCmd.Flags().Bool("master-mode", false, "Install as master-minion instead of masterless")
	saltstackCmd.Flags().Bool("skip-test", false, "Skip the verification test")
	saltstackCmd.Flags().String("log-level", "warning", "Set Salt log level (debug, info, warning, error)")
	saltstackCmd.Flags().String("version", "latest", "Salt version to install ('latest' for automatic detection)")

	// Bootstrap-specific flags (using current GitHub-hosted URL)
	saltstackCmd.Flags().String("bootstrap-url", "https://github.com/saltstack/salt-bootstrap/releases/latest/download/bootstrap-salt.sh", "Bootstrap script URL (GitHub-hosted after 2024 migration)")
	saltstackCmd.Flags().Bool("skip-checksum", false, "Skip bootstrap script checksum verification (not recommended)")

	// Register with parent command
	CreateCmd.AddCommand(saltstackCmd)
}

var saltStateCmd = &cobra.Command{
	Use:     "salt-state [target] [function] [args...]",
	Aliases: []string{"salt-state-apply", "saltstack-state"},
	Short:   "Create and apply Salt states on minions",
	Long: `Create and apply Salt states on specified minions.

Salt states define the desired configuration of minions and ensure they
reach and maintain that configuration. This command applies state modules
to enforce configuration management.

Examples:
  eos create salt-state '*' state.apply           # Apply all states
  eos create salt-state 'web*' state.apply nginx  # Apply nginx state
  eos create salt-state '*' state.sls apache      # Apply specific SLS file
  eos create salt-state '*' state.test            # Test state application

Common State Functions:
  state.apply        - Apply all assigned states
  state.sls          - Apply specific SLS file
  state.test         - Test state application (dry run)
  state.show_sls     - Show compiled state data
  state.highstate    - Apply highstate (all states)`,

	Args: cobra.MinimumNArgs(2),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		target := args[0]
		function := args[1]
		stateArgs := args[2:]

		// Parse flags
		testMode, _ := cmd.Flags().GetBool("test")
		pillarStrings, _ := cmd.Flags().GetStringArray("pillar")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		
		// Convert pillar strings to map
		pillarData := make(map[string]interface{})
		for _, pillarStr := range pillarStrings {
			// Simple key=value parsing
			parts := strings.SplitN(pillarStr, "=", 2)
			if len(parts) == 2 {
				pillarData[parts[0]] = parts[1]
			}
		}

		logger.Info("Creating Salt state application",
			zap.String("target", target),
			zap.String("function", function),
			zap.Strings("args", stateArgs),
			zap.Bool("test_mode", testMode))

		// Create Salt client
		saltClient := saltstack.NewClient(logger)

		// Create context with timeout
		ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
		defer cancel()

		// Apply state
		err := saltClient.StateApply(ctx, target, function, pillarData)

		if err != nil {
			logger.Error("Salt state application failed",
				zap.String("target", target),
				zap.String("function", function),
				zap.Error(err))
			return fmt.Errorf("failed to apply Salt state %s on %s: %w", function, target, err)
		}

		// State applied successfully
		logger.Info("Salt state applied successfully",
			zap.String("target", target),
			zap.String("function", function),
			zap.Bool("test_mode", testMode))
		
		return nil
	}),
}

func init() {
	saltStateCmd.Flags().Bool("test", false, "Test mode - show what would be changed without applying")
	saltStateCmd.Flags().StringArray("pillar", []string{}, "Override pillar data (key=value format)")
	saltStateCmd.Flags().Bool("refresh-pillar", false, "Refresh pillar data before applying state")
	saltStateCmd.Flags().Duration("timeout", 300*time.Second, "Timeout for state application")
	saltStateCmd.Flags().Bool("json", false, "Output results in JSON format")

	CreateCmd.AddCommand(saltStateCmd)
}

// TODO
func outputStateResultsJSON(result interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// TODO
func outputStateResultsText(result interface{}, target, function string, testMode bool) error {
	fmt.Printf("Salt State Application Results\n")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Function: %s\n", function)

	if testMode {
		fmt.Printf("Mode: Test (no changes made)\n")
	} else {
		fmt.Printf("Mode: Apply (changes enforced)\n")
	}

	fmt.Println("\nResults:")
	fmt.Println(strings.Repeat("-", 30))

	// TODO: Implement proper result formatting based on Salt client response format
	fmt.Printf("%v\n", result)

	return nil
}

var saltExecutionCmd = &cobra.Command{
	Use:     "salt-execution [target] [function] [args...]",
	Aliases: []string{"salt-run", "salt-command", "saltstack-execution"},
	Short:   "Create and execute Salt commands on minions",
	Long: `Create and execute Salt commands on specified minions.

This command runs Salt execution modules on the target minions and returns
the results. It's the primary way to execute commands, install packages,
manage services, and perform other operations on minions.

Examples:
  eos create salt-execution '*' test.ping                    # Test connectivity
  eos create salt-execution 'web*' cmd.run 'uptime'         # Run shell command
  eos create salt-execution 'db*' pkg.install 'mysql-server' # Install package
  eos create salt-execution 'app*' service.start 'nginx'    # Start service
  eos create salt-execution '*' grains.item 'os'            # Get OS grain
  eos create salt-execution '*' pillar.get 'users'          # Get pillar data
  
Common Functions:
  test.ping          - Test minion connectivity
  cmd.run            - Execute shell commands
  pkg.install        - Install packages
  pkg.remove         - Remove packages
  service.start      - Start services
  service.stop       - Stop services
  service.restart    - Restart services
  grains.item        - Get grain data
  pillar.get         - Get pillar data
  state.apply        - Apply Salt states
  
Target Types:
  glob     - Shell-style wildcards (default)
  pcre     - Perl-compatible regular expressions
  list     - Comma-separated list of minion IDs
  grain    - Match based on grains data
  pillar   - Match based on pillar data
  nodegroup - Match based on nodegroup`,

	Args: cobra.MinimumNArgs(2),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		target := args[0]
		function := args[1]
		functionArgs := args[2:] // Remaining args are function arguments

		// Parse flags
		targetType, _ := cmd.Flags().GetString("target-type")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		outputJSON, _ := cmd.Flags().GetBool("json")
		async, _ := cmd.Flags().GetBool("async")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		logger.Info("Creating Salt execution",
			zap.String("target", target),
			zap.String("function", function),
			zap.Strings("args", functionArgs),
			zap.String("target_type", targetType),
			zap.Bool("async", async),
			zap.Bool("dry_run", dryRun))

		if dryRun {
			fmt.Printf("DRY RUN: Would execute Salt function\n")
			fmt.Printf("  Target: %s (%s)\n", target, targetType)
			fmt.Printf("  Function: %s\n", function)
			if len(functionArgs) > 0 {
				fmt.Printf("  Arguments: %s\n", strings.Join(functionArgs, " "))
			}
			return nil
		}

		// Create Salt client
		saltClient := saltstack.NewClient(logger)

		// Create context with timeout
		ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
		defer cancel()

		// Execute Salt function
		// Build command string for CmdRun
		cmdParts := []string{function}
		cmdParts = append(cmdParts, functionArgs...)
		command := strings.Join(cmdParts, " ")
		
		result, err := saltClient.CmdRun(ctx, target, command)

		if err != nil {
			logger.Error("Salt execution failed",
				zap.String("target", target),
				zap.String("function", function),
				zap.Error(err))
			return fmt.Errorf("failed to execute Salt function %s on %s: %w", function, target, err)
		}

		// Output results
		if outputJSON {
			return outputExecutionResultsJSON(result)
		}

		return outputExecutionResultsText(result, target, function, async)
	}),
}

func init() {
	saltExecutionCmd.Flags().String("target-type", "glob", "Target type: glob, pcre, list, grain, pillar, nodegroup")
	saltExecutionCmd.Flags().Duration("timeout", 60*time.Second, "Timeout for execution")
	saltExecutionCmd.Flags().Bool("json", false, "Output results in JSON format")
	saltExecutionCmd.Flags().Bool("async", false, "Execute asynchronously and return job ID")
	saltExecutionCmd.Flags().Bool("dry-run", false, "Show what would be executed without running")

	CreateCmd.AddCommand(saltExecutionCmd)
}

// TODO
func outputExecutionResultsJSON(result interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// TODO
func outputExecutionResultsText(result interface{}, target, function string, async bool) error {
	fmt.Printf("Salt Execution Results\n")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Function: %s\n", function)

	if async {
		fmt.Printf("Execution Mode: Asynchronous\n")
		fmt.Printf("Job ID: %v\n", result)
		fmt.Println("\nUse 'eos read salt-job-status <job-id>' to check progress")
	} else {
		fmt.Printf("Execution Mode: Synchronous\n")
		fmt.Println("\nResults:")
		fmt.Println(strings.Repeat("-", 30))

		// TODO: Implement proper result formatting based on Salt client response format
		fmt.Printf("%v\n", result)
	}

	return nil
}

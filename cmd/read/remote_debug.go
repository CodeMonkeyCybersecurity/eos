package read

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/remotedebug"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var remoteDebugCmd = &cobra.Command{
	Use:     "remote-debug [host]",
	Aliases: []string{"debug-remote", "ssh-debug"},
	Short:   "Diagnose and fix issues on remote Ubuntu/Linux systems",
	Long: `Remote debugging tool for diagnosing and fixing common Ubuntu/Linux server issues.
	
This tool can diagnose:
- SSH connectivity issues
- Resource exhaustion (CPU, memory, disk, processes)
- Authentication problems (PAM, LDAP, etc)
- Network and firewall issues
- Security tool interference
- System misconfigurations

Examples:
  eos read remote-debug server1.example.com
  eos read remote-debug 192.168.1.100 --user=admin
  eos read remote-debug myserver --interactive
  eos read remote-debug server1 --fix --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(runRemoteDebug),
}

func init() {
	ReadCmd.AddCommand(remoteDebugCmd)

	// SSH connection flags
	remoteDebugCmd.Flags().StringP("user", "u", "", "SSH username (prompted if not provided)")
	remoteDebugCmd.Flags().StringP("password", "p", "", "SSH password")
	remoteDebugCmd.Flags().String("key", "", "Path to SSH private key")
	remoteDebugCmd.Flags().String("port", "22", "SSH port")
	remoteDebugCmd.Flags().String("sudo-pass", "", "Sudo password")

	// Operation mode flags
	remoteDebugCmd.Flags().BoolP("interactive", "i", false, "Interactive troubleshooting mode")
	remoteDebugCmd.Flags().Bool("fix", false, "Attempt to fix detected issues")
	remoteDebugCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	remoteDebugCmd.Flags().Bool("json", false, "Output results as JSON")

	// Diagnostic options
	remoteDebugCmd.Flags().String("check", "all", "Specific check to run (disk/memory/network/auth/all)")
	remoteDebugCmd.Flags().Bool("kernel-logs", false, "Include kernel log analysis")
	remoteDebugCmd.Flags().String("since", "1h", "Time range for log analysis (e.g., 1h, 30m, 24h)")
}

func runRemoteDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// CRITICAL: Detect flag-like args (P0-1 fix)
	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}

	host := args[0]

	logger.Info("Starting remote debug session",
		zap.String("host", host),
		zap.String("action", "remote-debug"),
		zap.String("phase", "start"))

	// Parse flags
	config := &remotedebug.Config{
		Host:     host,
		Port:     cmd.Flag("port").Value.String(),
		KeyPath:  cmd.Flag("key").Value.String(),
		Password: cmd.Flag("password").Value.String(),
		SudoPass: cmd.Flag("sudo-pass").Value.String(),
	}

	// Get username interactively if not provided
	user := cmd.Flag("user").Value.String()
	if user == "" {
		logger.Info("Username not provided via flag, prompting user")
		logger.Info("terminal prompt: Please enter SSH username")

		var err error
		user, err = eos_io.PromptInput(rc, "SSH username: ", "username")
		if err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}
	}
	config.User = user

	// Get password if not provided and no key specified
	if config.Password == "" && config.KeyPath == "" {
		logger.Info("No authentication method provided, prompting for password")
		logger.Info("terminal prompt: Please enter SSH password")

		password, err := eos_io.PromptSecurePassword(rc, "SSH password: ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		config.Password = password
	}

	// Create debugger instance
	debugger := remotedebug.New(rc, config)

	// Determine operation mode
	interactive, _ := cmd.Flags().GetBool("interactive")
	fix, _ := cmd.Flags().GetBool("fix")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	outputJSON, _ := cmd.Flags().GetBool("json")
	kernelLogs, _ := cmd.Flags().GetBool("kernel-logs")
	checkType := cmd.Flag("check").Value.String()
	since := cmd.Flag("since").Value.String()

	// Set output format
	if outputJSON {
		debugger.SetOutputFormat(remotedebug.OutputJSON)
	}

	// Execute based on mode
	if interactive {
		logger.Info("Entering interactive troubleshooting mode")
		return debugger.RunInteractive()
	}

	if fix {
		logger.Info("Running diagnostic and fix mode",
			zap.Bool("dry_run", dryRun))
		return debugger.DiagnoseAndFix(dryRun)
	}

	// Default: run diagnostics
	logger.Info("Running system diagnostics",
		zap.String("check_type", checkType),
		zap.Bool("kernel_logs", kernelLogs),
		zap.String("since", since))

	opts := remotedebug.DiagnosticOptions{
		CheckType:  checkType,
		KernelLogs: kernelLogs,
		Since:      since,
	}

	return debugger.RunDiagnostics(opts)
}

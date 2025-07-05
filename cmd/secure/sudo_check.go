package secure

import (
	"encoding/json"
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewSudoCheckCmd creates the sudo check command
func NewSudoCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sudo-check",
		Aliases: []string{"sudo", "privilege", "privcheck"},
		Short:   "Check if running with root or sudo privileges",
		Long: `Check if the current process is running with root or sudo privileges.

This command is useful for scripts and operations that require elevated privileges.
It can be configured to require root access, allow sudo, or just report privilege status.

Examples:
  eos secure sudo-check                    # Check and report privilege status
  eos secure sudo-check --require          # Require root/sudo and exit if not found
  eos secure sudo-check --info             # Show detailed privilege information
  eos secure sudo-check --json             # Output privilege status in JSON format
  eos secure sudo-check --silent           # Silent check (no output, exit code only)`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
			require, _ := cmd.Flags().GetBool("require")
			info, _ := cmd.Flags().GetBool("info")
			silent, _ := cmd.Flags().GetBool("silent")
			outputJSON, _ := cmd.Flags().GetBool("json")
			allowSudo, _ := cmd.Flags().GetBool("allow-sudo")
			noColor, _ := cmd.Flags().GetBool("no-color")
			customMessage, _ := cmd.Flags().GetString("message")

			logger.Info("Checking sudo privileges", 
				zap.Bool("require", require),
				zap.Bool("info", info),
				zap.Bool("silent", silent))

			config := privilege_check.DefaultPrivilegeConfig()
			config.AllowSudo = allowSudo
			config.ExitOnFailure = require
			config.ShowColorOutput = !noColor

			manager := privilege_check.NewPrivilegeManager(config)

			// Handle info mode
			if info {
				return handleInfoMode(rc, manager, outputJSON)
			}

			// Handle privilege check
			requirement := privilege_check.SudoNotRequired
			if require {
				requirement = privilege_check.SudoRequired
			}

			options := &privilege_check.CheckOptions{
				Requirement:   requirement,
				CustomMessage: customMessage,
				SilentMode:    silent,
			}

			result, err := manager.RequireSudo(rc, options)
			if err != nil {
				logger.Error("Failed to check sudo privileges", zap.Error(err))
				return err
			}

			if outputJSON {
				return outputJSONSudoResult(result)
			}

			// Exit with appropriate code
			if !result.Success {
				os.Exit(1)
			}

			return nil
		}),
	}

	cmd.Flags().Bool("require", false, "Require root/sudo privileges (exit 1 if not found)")
	cmd.Flags().Bool("info", false, "Show detailed privilege information")
	cmd.Flags().Bool("silent", false, "Silent mode (no output, exit code only)")
	cmd.Flags().Bool("json", false, "Output in JSON format")
	cmd.Flags().Bool("allow-sudo", true, "Allow sudo privileges (not just root)")
	cmd.Flags().Bool("no-color", false, "Disable colored output")
	cmd.Flags().StringP("message", "m", "", "Custom message to display on failure")

	return cmd
}

// handleInfoMode handles the detailed information display
func handleInfoMode(rc *eos_io.RuntimeContext, manager *privilege_check.PrivilegeManager, outputJSON bool) error {
	if outputJSON {
		check, err := manager.CheckPrivileges(rc)
		if err != nil {
			return err
		}
		return outputJSONSudoResult(check)
	}

	info, err := manager.GetPrivilegeInfo(rc)
	if err != nil {
		return err
	}

	fmt.Print(info)
	return nil
}

// outputJSONSudoResult outputs the result in JSON format
func outputJSONSudoResult(result any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
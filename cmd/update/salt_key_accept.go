// cmd/update/salt_key_accept.go
package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var saltKeyAcceptCmd = &cobra.Command{
	Use:     "salt-key-accept [pattern]",
	Aliases: []string{"salt-key-approve", "accept-salt-keys"},
	Short:   "Accept Salt minion authentication keys",
	Long: `Accept Salt minion authentication keys to allow communication.

Once a minion key is accepted, the minion can receive and execute commands
from the Salt master. This is a security-critical operation that should
only be performed for trusted minions.

Examples:
  eos update salt-key-accept 'web01'          # Accept specific minion
  eos update salt-key-accept 'web*'           # Accept pattern match
  eos update salt-key-accept --all            # Accept all pending keys
  eos update salt-key-accept --include 'web01,web02'  # Accept specific list

Security Notice:
  - Only accept keys from trusted minions
  - Verify minion identity before accepting
  - Use patterns carefully to avoid accepting unwanted keys
  - Consider using --dry-run to preview changes`,

	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse pattern from args or flags
		var pattern string
		if len(args) > 0 {
			pattern = args[0]
		}

		// Parse flags
		acceptAll, _ := cmd.Flags().GetBool("all")
		includeList, _ := cmd.Flags().GetString("include")
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		// Validate input
		if !acceptAll && pattern == "" && includeList == "" {
			return fmt.Errorf("must specify pattern, --all, or --include")
		}

		logger.Info("Accepting Salt keys",
			zap.String("pattern", pattern),
			zap.Bool("accept_all", acceptAll),
			zap.String("include_list", includeList),
			zap.Bool("force", force),
			zap.Bool("dry_run", dryRun))

		if dryRun {
			fmt.Println("DRY RUN: Would accept Salt keys")
			if acceptAll {
				fmt.Println("  Target: All pending keys")
			} else if pattern != "" {
				fmt.Printf("  Pattern: %s\n", pattern)
			} else if includeList != "" {
				fmt.Printf("  Include List: %s\n", includeList)
			}
			return nil
		}

		// Security confirmation for --all
		if acceptAll && !force {
			fmt.Print("WARNING: This will accept ALL pending keys. Continue? [y/N]: ")
			var response string
			fmt.Scanln(&response)
			if response != "y" && response != "Y" && response != "yes" {
				return fmt.Errorf("operation cancelled by user")
			}
		}

		// Salt key accept feature temporarily disabled during refactoring
		logger.Warn("Salt key accept feature temporarily disabled during refactoring")
		return fmt.Errorf("AcceptKeys methods not available in current saltstack.KeyManager interface")
	}),
}

func init() {
	saltKeyAcceptCmd.Flags().Bool("all", false, "Accept all pending keys")
	saltKeyAcceptCmd.Flags().String("include", "", "Comma-separated list of specific keys to accept")
	saltKeyAcceptCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompts")
	saltKeyAcceptCmd.Flags().Bool("dry-run", false, "Show what would be accepted without making changes")

	UpdateCmd.AddCommand(saltKeyAcceptCmd)
}
// cmd/delete/salt_key.go
package delete

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var saltKeyCmd = &cobra.Command{
	Use:     "salt-key [pattern]",
	Aliases: []string{"salt-minion-key", "saltstack-key"},
	Short:   "Delete Salt minion authentication keys",
	Long: `Delete Salt minion authentication keys from the master.

This permanently removes minion keys from the Salt master. Deleted keys
will need to be re-accepted if the minion attempts to reconnect.

WARNING: This is a destructive operation that will prevent the minion
from communicating with the master until its key is re-accepted.

Examples:
  eos delete salt-key 'old-server'            # Delete specific minion key
  eos delete salt-key 'test-*'                # Delete pattern match
  eos delete salt-key --include 'web01,web02' # Delete specific list
  eos delete salt-key --dry-run 'test-*'      # Preview deletion

Security Notice:
  - This permanently removes authentication keys
  - Minions will need re-authentication after deletion
  - Use --dry-run to preview changes before deletion
  - Cannot be undone - minion must re-register`,

	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse pattern from args
		var pattern string
		if len(args) > 0 {
			pattern = args[0]
		}

		// Parse flags
		includeList, _ := cmd.Flags().GetString("include")
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		// Validate input
		if pattern == "" && includeList == "" {
			return fmt.Errorf("must specify pattern or --include")
		}

		logger.Info("Deleting Salt keys",
			zap.String("pattern", pattern),
			zap.String("include_list", includeList),
			zap.Bool("force", force),
			zap.Bool("dry_run", dryRun))

		if dryRun {
			fmt.Println("DRY RUN: Would delete Salt keys")
			if pattern != "" {
				fmt.Printf("  Pattern: %s\n", pattern)
			} else {
				fmt.Printf("  Include List: %s\n", includeList)
			}
			return nil
		}

		// Security confirmation unless forced
		if !force {
			logger.Info("terminal prompt: Confirmation for Salt key deletion")
			if !interaction.PromptYesNo(rc.Ctx, "WARNING: This will permanently delete Salt keys. Continue?", false) {
				return fmt.Errorf("operation cancelled by user")
			}
		}

		// Create Salt key manager
		keyManager := saltstack.NewKeyManager(otelzap.Ctx(rc.Ctx))

		// Prepare deletion options
		opts := &saltstack.DeleteKeysOptions{
			Force:  force,
			DryRun: dryRun,
		}

		if includeList != "" {
			keys := strings.Split(includeList, ",")
			for i, key := range keys {
				keys[i] = strings.TrimSpace(key)
			}
			opts.Keys = keys
		} else {
			opts.Pattern = pattern
		}

		// Delete keys using the helper function
		result, err := keyManager.DeleteKeysWithOptions(rc, opts)
		if err != nil {
			logger.Error("Failed to delete Salt keys", zap.Error(err))
			return fmt.Errorf("failed to delete Salt keys: %w", err)
		}

		// Output results
		fmt.Printf("Salt Key Deletion Results\n")
		fmt.Println(strings.Repeat("=", 40))

		if pattern != "" {
			fmt.Printf("Pattern: %s\n", pattern)
		} else {
			fmt.Printf("Include List: %s\n", includeList)
		}
		fmt.Printf("Message: %s\n", result.Message)
		fmt.Printf("Deleted Keys: %v\n", result.DeletedKeys)
		if len(result.ErrorKeys) > 0 {
			fmt.Printf("Failed Keys: %v\n", result.ErrorKeys)
		}

		logger.Info("Salt keys deleted successfully",
			zap.Int("deleted_count", len(result.DeletedKeys)),
			zap.Int("error_count", len(result.ErrorKeys)))
		return nil
	}),
}

func init() {
	saltKeyCmd.Flags().String("include", "", "Comma-separated list of specific keys to delete")
	saltKeyCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompts")
	saltKeyCmd.Flags().Bool("dry-run", false, "Show what would be deleted without making changes")

	DeleteCmd.AddCommand(saltKeyCmd)
}

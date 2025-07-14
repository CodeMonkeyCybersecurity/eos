// cmd/list/salt_keys.go
package list

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var saltKeysCmd = &cobra.Command{
	Use:     "salt-keys",
	Aliases: []string{"salt-minion-keys", "saltstack-keys"},
	Short:   "List Salt minion authentication keys by status",
	Long: `List Salt minion authentication keys organized by their status.

Salt uses a PKI system where minions must have their keys accepted by the master
before they can receive commands. This command shows all keys organized by:

Key States:
  - accepted: Keys that are trusted and can receive commands
  - unaccepted: New keys waiting for approval
  - rejected: Keys that have been explicitly rejected
  - denied: Keys that have been denied access

Examples:
  eos list salt-keys                           # List all keys by status
  eos list salt-keys --pattern 'web*'         # Filter keys by pattern
  eos list salt-keys --json                   # Output in JSON format
  eos list salt-keys --status accepted        # Show only accepted keys`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Parse flags
		pattern, _ := cmd.Flags().GetString("pattern")
		statusFilter, _ := cmd.Flags().GetString("status")
		outputJSON, _ := cmd.Flags().GetBool("json")

		logger.Info("Listing Salt keys",
			zap.String("pattern", pattern),
			zap.String("status_filter", statusFilter))

		// Create Salt client
		saltClient := saltstack.NewClient(otelzap.Ctx(rc.Ctx))

		// Create context with timeout
		ctx, cancel := context.WithTimeout(rc.Ctx, 15*time.Second)
		defer cancel()

		// Get key list using salt-key command
		output, err := saltClient.CmdRun(ctx, "local", "salt-key -L")
		if err != nil {
			logger.Error("Failed to list Salt keys", zap.Error(err))
			return fmt.Errorf("failed to list Salt keys: %w", err)
		}

		// For now, just use the raw output as keys
		keys := map[string]interface{}{"output": output}

		// Apply status filter if specified
		if statusFilter != "" && statusFilter != "all" {
			keys = filterKeysByStatus(keys, statusFilter).(map[string]interface{})
		}

		// Output results
		if outputJSON {
			return outputKeysJSON(keys)
		}

		return outputKeysTable(logger, keys, pattern, statusFilter)
	}),
}

func init() {
	saltKeysCmd.Flags().String("pattern", "", "Filter keys by pattern (glob style)")
	saltKeysCmd.Flags().String("status", "all", "Filter by status: all, accepted, unaccepted, rejected, denied")
	saltKeysCmd.Flags().Bool("json", false, "Output results in JSON format")

	ListCmd.AddCommand(saltKeysCmd)
}

// TODO
func filterKeysByStatus(keys interface{}, status string) interface{} {
	// TODO: Implement filtering based on actual Salt client response format
	return keys
}

// TODO
func outputKeysJSON(keys interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(keys)
}

// TODO
func outputKeysTable(logger otelzap.LoggerWithCtx, keys interface{}, pattern, statusFilter string) error {
	logger.Info("terminal prompt: Salt Minion Keys")
	if pattern != "" {
		logger.Info("terminal prompt: Pattern", zap.String("pattern", pattern))
	}
	if statusFilter != "all" {
		logger.Info("terminal prompt: Status", zap.String("status", statusFilter))
	}
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 60)))

	// TODO: Implement actual key listing based on Salt client response format
	logger.Info("terminal prompt: Accepted Keys:")
	logger.Info("terminal prompt:   (key listing implementation pending Salt client structure)")

	logger.Info("terminal prompt: Unaccepted Keys:")
	logger.Info("terminal prompt:   (key listing implementation pending Salt client structure)")

	logger.Info("terminal prompt: Rejected Keys:")
	logger.Info("terminal prompt:   (key listing implementation pending Salt client structure)")

	return nil
}

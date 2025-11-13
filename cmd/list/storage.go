// cmd/list/disks.go
package list

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var disksCmd = &cobra.Command{
	Use:     "disks",
	Aliases: []string{"disk", "disk-devices"},
	Short:   "List all available disk devices",
	Long: `List all available disk devices with their properties.

Shows device name, size, vendor, model, and mount points for each disk.

Examples:
  eos list disks                        # List all disks
  eos list disks --json               # Output in JSON format`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Listing disk devices")

		outputJSON, _ := cmd.Flags().GetBool("json")
		bootstrap, _ := cmd.Flags().GetBool("bootstrap")

		if bootstrap {
			logger.Info("Using bootstrap mode (direct execution without )")
		} else {
			// For now, still use direct execution even without bootstrap flag
			// TODO: When  integration is ready, implement -based disk listing
			logger.Info(" not configured, falling back to direct execution")
		}

		// Use simplified function instead of manager pattern
		result, err := storage.ListDisks(rc)
		if err != nil {
			logger.Error("Failed to list disks", zap.Error(err))
			return err
		}

		if outputJSON {
			return storage.OutputDiskListJSON(result)
		}

		return storage.OutputDiskListTable(result)
	}),
}

func init() {
	disksCmd.Flags().Bool("json", false, "Output in JSON format")
	disksCmd.Flags().Bool("bootstrap", false, "Use direct execution without  (for initial system discovery)")

	ListCmd.AddCommand(disksCmd)
}

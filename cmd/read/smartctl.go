// cmd/read/smartctl.go

package read

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// ReadSMARTCmd checks all SMART-compatible devices and logs health summaries
var ReadSMARTCmd = &cobra.Command{
	Use:   "smartctl",
	Short: "Check SMART health across all available storage devices",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
		devices, err := eos_unix.DiscoverDevices(rc.Ctx)
		if err != nil {
			rc.Log.Error("Failed to discover devices", zap.Error(err))
			return cerr.Wrap(err, "device discovery failed")
		}
		if len(devices) == 0 {
			rc.Log.Warn("No SMART-compatible devices found")
			return nil
		}

		for _, dev := range devices {
			device, devType := dev[0], dev[1]
			rc.Log.Info("Checking device", zap.String("device", device), zap.String("type", devType))

			report, err := eos_unix.CheckSMART(rc.Ctx, device, devType)
			if err != nil {
				rc.Log.Error("SMART check failed", zap.String("device", device), zap.Error(err))
				continue
			}

			rc.Log.Info("SMART result",
				zap.String("device", report.Device),
				zap.String("health", report.HealthStatus),
				zap.Int("life_remaining_pct", report.PercentLifeRemaining),
				zap.Int("reallocated_sectors", report.ReallocatedSectors),
				zap.Int("uncorrectable_errors", report.UncorrectableErrors),
			)

			for _, warning := range report.Warnings {
				rc.Log.Warn("SMART warning", zap.String("device", report.Device), zap.String("warning", warning))
			}
		}

		return nil
	}),
}

// init registers subcommands for the read command
func init() {
	ReadCmd.AddCommand(ReadSMARTCmd)
}

// cmd/update/storage_emergency.go

package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/emergency"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var storageEmergencyCmd = &cobra.Command{
	Use:   "storage-emergency",
	Short: "Emergency storage recovery operations",
	Long: `Perform emergency storage recovery when disk is critically full.
This command will aggressively free space by:
- Stopping non-critical services
- Removing all temporary files
- Clearing package caches
- Compressing or removing logs
- Creating emergency diagnostics`,
	RunE: eos_cli.Wrap(runStorageEmergency),
}

var (
	emergencyDiagnostics bool
	emergencyRecover     bool
)

func init() {
	UpdateCmd.AddCommand(storageEmergencyCmd)
	
	storageEmergencyCmd.Flags().BoolVar(&emergencyDiagnostics, "diagnostics", false,
		"Generate emergency diagnostics report")
	storageEmergencyCmd.Flags().BoolVar(&emergencyRecover, "recover", false,
		"Attempt automatic recovery")
}

func runStorageEmergency(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Error("EMERGENCY: Storage recovery mode activated")
	
	// Create emergency handler
	handler := emergency.NewHandler(rc)
	
	// ASSESS - Run diagnostics first
	if emergencyDiagnostics || !emergencyRecover {
		logger.Info("Running emergency diagnostics")
		
		report, err := handler.GenerateDiagnostics()
		if err != nil {
			logger.Error("Failed to generate diagnostics", zap.Error(err))
		} else {
			// Display diagnostics
			logger.Info("Emergency diagnostics report",
				zap.Any("disk_usage", report.DiskUsage),
				zap.Strings("large_files", report.LargeFiles),
				zap.Strings("growth_dirs", report.GrowthDirs))
		}
		
		if !emergencyRecover {
			return nil
		}
	}
	
	// INTERVENE - Perform recovery
	logger.Warn("Starting emergency recovery - this will stop services and delete data")
	
	result, err := handler.EmergencyRecover()
	if err != nil {
		return fmt.Errorf("emergency recovery failed: %w", err)
	}
	
	// EVALUATE - Show results
	logger.Info("Emergency recovery completed",
		zap.Uint64("freed_bytes", result.FreedBytes),
		zap.Uint64("freed_mb", result.FreedBytes/(1024*1024)),
		zap.Strings("stopped_services", result.StoppedServices),
		zap.Int("deleted_files", result.DeletedFiles))
	
	if result.FreedBytes < 1024*1024*100 { // Less than 100MB freed
		logger.Error("Emergency recovery freed minimal space - manual intervention required")
		return fmt.Errorf("insufficient space recovered")
	}
	
	return nil
}
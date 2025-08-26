// cmd/read/monitor.go

package read

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/analyzer"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/threshold"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var storageMonitorCmd = &cobra.Command{
	Use:   "storage-monitor",
	Short: "Monitor storage and trigger actions based on thresholds",
	Long: `Monitor storage usage across all mount points and automatically trigger
actions when thresholds are exceeded. Actions include compression, cleanup,
service degradation, and emergency recovery.`,
	RunE: eos_cli.Wrap(runStorageMonitor),
}

var (
	monitorDaemon   bool
	monitorInterval string
)

func init() {
	ReadCmd.AddCommand(storageMonitorCmd)
	
	storageMonitorCmd.Flags().BoolVar(&monitorDaemon, "daemon", false, "Run as a daemon")
	storageMonitorCmd.Flags().StringVar(&monitorInterval, "interval", "5m", "Monitoring interval")
}

func runStorageMonitor(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting storage monitor")
	
	// ASSESS - Detect environment
	env, err := environment.Detect(rc)
	if err != nil {
		return fmt.Errorf("failed to detect environment: %w", err)
	}
	
	logger.Info("Environment detected",
		zap.Int("machine_count", env.MachineCount),
		zap.String("my_role", string(env.MyRole)),
		zap.String("scale", string(env.GetScale())))
	
	// Load appropriate thresholds
	thresholdMgr := threshold.NewManager(rc, env)
	config := thresholdMgr.GetConfig()
	
	logger.Info("Loaded thresholds for environment",
		zap.Float64("warning", config.Warning),
		zap.Float64("critical", config.Critical))
	
	// Parse interval
	interval, err := time.ParseDuration(monitorInterval)
	if err != nil {
		return fmt.Errorf("invalid interval: %w", err)
	}
	
	// Create analyzer
	analyzerConfig := analyzer.Config{
		Interval:   interval,
		Thresholds: config,
	}
	storageAnalyzer := analyzer.New(rc, analyzerConfig, thresholdMgr)
	
	// INTERVENE - Run analysis
	if monitorDaemon {
		logger.Info("Starting monitoring daemon",
			zap.Duration("interval", interval))
		return storageAnalyzer.Monitor(rc.Ctx)
	}
	
	// Single run
	statuses, err := storageAnalyzer.Analyze()
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}
	
	// EVALUATE - Display results
	displayStorageStatus(logger, statuses)
	
	return nil
}

func displayStorageStatus(logger otelzap.LoggerWithCtx, statuses []*analyzer.StorageStatus) {
	logger.Info("Storage analysis complete")
	
	for _, status := range statuses {
		logger.Info("Mount point status",
			zap.String("mount", status.MountPoint),
			zap.String("filesystem", status.Filesystem),
			zap.Float64("usage_percent", status.UsagePercent),
			zap.Uint64("free_bytes", status.FreeBytes),
			zap.Float64("growth_rate_gb_day", status.GrowthRate))
		
		// Log alerts
		for _, alert := range status.Alerts {
			switch alert.Level {
			case "critical":
				logger.Error(alert.Message,
					zap.String("mount", status.MountPoint),
					zap.String("action", string(alert.Action)))
			case "error":
				logger.Error(alert.Message,
					zap.String("mount", status.MountPoint),
					zap.String("action", string(alert.Action)))
			case "warning":
				logger.Warn(alert.Message,
					zap.String("mount", status.MountPoint),
					zap.String("action", string(alert.Action)))
			default:
				logger.Info(alert.Message,
					zap.String("mount", status.MountPoint),
					zap.String("action", string(alert.Action)))
			}
		}
		
		// Calculate time until full
		if status.GrowthRate > 0 {
			freeGB := float64(status.FreeBytes) / (1024 * 1024 * 1024)
			daysUntilFull := freeGB / status.GrowthRate
			
			if daysUntilFull < 30 {
				logger.Warn("Storage will be full soon",
					zap.String("mount", status.MountPoint),
					zap.Float64("days_until_full", daysUntilFull))
			}
		}
	}
}
// cmd/read/storage_analyze.go

package read

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/analyzer"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/filesystem"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/threshold"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var storageAnalyzeCmd = &cobra.Command{
	Use:   "storage-analyze",
	Short: "Analyze current storage state and provide recommendations",
	Long: `Performs comprehensive storage analysis including:
- Current usage across all mount points
- Threshold status and recommended actions
- Filesystem optimization opportunities
- Data classification summary
- Growth rate projections`,
	RunE: eos_cli.Wrap(runStorageAnalyze),
}

var (
	analyzeDetailed bool
	analyzeJSON     bool
)

func init() {
	ReadCmd.AddCommand(storageAnalyzeCmd)
	
	storageAnalyzeCmd.Flags().BoolVar(&analyzeDetailed, "detailed", false,
		"Show detailed analysis including file classification")
	storageAnalyzeCmd.Flags().BoolVar(&analyzeJSON, "json", false,
		"Output in JSON format")
}

func runStorageAnalyze(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting storage analysis")
	
	// ASSESS - Detect environment
	env, err := environment.Detect(rc)
	if err != nil {
		logger.Warn("Failed to detect environment, using defaults", zap.Error(err))
		env = &environment.Environment{MachineCount: 1}
	}
	
	profile := env.GetStorageProfile()
	logger.Info("Environment profile",
		zap.String("scale", string(profile.Scale)),
		zap.String("role", string(env.MyRole)),
		zap.Any("thresholds", profile.DefaultThresholds))
	
	// Create threshold manager
	thresholdMgr := threshold.NewManager(rc, env)
	
	// Create analyzer
	config := analyzer.Config{
		Thresholds: thresholdMgr.GetConfig(),
	}
	storageAnalyzer := analyzer.New(rc, config, thresholdMgr)
	
	// INTERVENE - Perform analysis
	statuses, err := storageAnalyzer.Analyze()
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}
	
	// Create filesystem detector
	fsDetector := filesystem.NewDetector(rc)
	
	// EVALUATE - Display results
	logger.Info("=== Storage Analysis Report ===")
	
	var criticalCount, warningCount int
	
	for _, status := range statuses {
		// Determine status level
		level := "OK"
		if status.UsagePercent >= profile.DefaultThresholds.Critical {
			level = "CRITICAL"
			criticalCount++
		} else if status.UsagePercent >= profile.DefaultThresholds.Warning {
			level = "WARNING"
			warningCount++
		}
		
		logger.Info("Mount point analysis",
			zap.String("mount", status.MountPoint),
			zap.String("status", level),
			zap.String("filesystem", status.Filesystem),
			zap.Float64("usage_percent", status.UsagePercent),
			zap.Uint64("total_gb", status.TotalBytes/(1024*1024*1024)),
			zap.Uint64("free_gb", status.FreeBytes/(1024*1024*1024)),
			zap.Float64("growth_gb_day", status.GrowthRate))
		
		// Show projected full date
		if status.GrowthRate > 0 {
			freeGB := float64(status.FreeBytes) / (1024 * 1024 * 1024)
			daysUntilFull := freeGB / status.GrowthRate
			
			if daysUntilFull < 365 {
				logger.Warn("Storage projection",
					zap.String("mount", status.MountPoint),
					zap.Float64("days_until_full", daysUntilFull),
					zap.Float64("months_until_full", daysUntilFull/30))
			}
		}
		
		// Show filesystem optimization opportunities
		if analyzeDetailed {
			fs := filesystem.Filesystem(status.Filesystem)
			opts := fsDetector.GetOptimizationOptions(fs, "general")
			if len(opts) > 0 {
				logger.Info("Optimization opportunities",
					zap.String("mount", status.MountPoint),
					zap.Any("options", opts))
			}
		}
		
		// Show alerts
		for _, alert := range status.Alerts {
			switch alert.Level {
			case "critical", "error":
				logger.Error(alert.Message,
					zap.String("mount", status.MountPoint))
			case "warning":
				logger.Warn(alert.Message,
					zap.String("mount", status.MountPoint))
			default:
				logger.Info(alert.Message,
					zap.String("mount", status.MountPoint))
			}
		}
	}
	
	// Summary
	logger.Info("=== Analysis Summary ===")
	logger.Info("Storage health",
		zap.Int("total_mounts", len(statuses)),
		zap.Int("critical", criticalCount),
		zap.Int("warnings", warningCount))
	
	// Recommendations
	if criticalCount > 0 {
		logger.Error("IMMEDIATE ACTION REQUIRED")
		logger.Error("Run: eos update storage-emergency --recover")
	} else if warningCount > 0 {
		logger.Warn("Preventive action recommended")
		logger.Warn("Run: eos update storage-cleanup --level=compress")
	}
	
	// Environment-specific recommendations
	switch profile.Scale {
	case environment.ScaleSingle:
		if criticalCount > 0 || warningCount > 0 {
			logger.Info("Single machine recommendation: Enable aggressive cleanup policy")
		}
	case environment.ScaleDistributed:
		logger.Info("Distributed environment: Consider data migration to less utilized nodes")
	}
	
	return nil
}
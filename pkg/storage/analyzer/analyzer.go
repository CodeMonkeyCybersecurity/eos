// pkg/storage/analyzer/analyzer.go

package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/threshold"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Analyzer performs storage analysis and monitoring
type Analyzer struct {
	rc         *eos_io.RuntimeContext
	config     Config
	thresholds *threshold.Manager
	classifier *DataClassifier
	executor   *threshold.ActionExecutor
}

// Config holds analyzer configuration
type Config struct {
	Interval   time.Duration
	Thresholds threshold.Config
}

// StorageStatus represents the current storage state
type StorageStatus struct {
	MountPoint   string
	Device       string
	Filesystem   string
	TotalBytes   uint64
	UsedBytes    uint64
	FreeBytes    uint64
	UsagePercent float64
	GrowthRate   float64 // GB/day
	Alerts       []Alert
	LastChecked  time.Time
}

// Alert represents a storage alert
type Alert struct {
	Level     string    // info, warning, error, critical
	Message   string
	Timestamp time.Time
	Action    threshold.Action
}

// New creates a new storage analyzer
func New(rc *eos_io.RuntimeContext, config Config, thresholdMgr *threshold.Manager) *Analyzer {
	return &Analyzer{
		rc:         rc,
		config:     config,
		thresholds: thresholdMgr,
		classifier: NewDataClassifier(),
		executor:   threshold.NewActionExecutor(rc),
	}
}

// Analyze performs a storage analysis
func (a *Analyzer) Analyze() ([]*StorageStatus, error) {
	logger := otelzap.Ctx(a.rc.Ctx)
	logger.Info("Starting storage analysis")
	
	// Get current usage for all mount points
	statuses, err := a.getCurrentUsage()
	if err != nil {
		return nil, fmt.Errorf("failed to get current usage: %w", err)
	}
	
	// Analyze each mount point
	for _, status := range statuses {
		// Calculate growth rate (would need historical data in production)
		status.GrowthRate = a.calculateGrowthRate(status)
		
		// Check thresholds and determine actions
		actions := a.thresholds.DetermineActions(status.UsagePercent)
		
		// Execute actions if needed
		for _, action := range actions {
			if action == threshold.ActionNone {
				continue
			}
			
			alert := Alert{
				Level:     a.getAlertLevel(action),
				Message:   threshold.GetActionDescription(action),
				Timestamp: time.Now(),
				Action:    action,
			}
			status.Alerts = append(status.Alerts, alert)
			
			if err := a.executor.Execute(action, status.MountPoint); err != nil {
				logger.Error("Failed to execute action",
					zap.String("action", string(action)),
					zap.String("mount_point", status.MountPoint),
					zap.Error(err))
				
				status.Alerts = append(status.Alerts, Alert{
					Level:     "error",
					Message:   fmt.Sprintf("Failed to execute %s: %v", action, err),
					Timestamp: time.Now(),
				})
			}
		}
	}
	
	return statuses, nil
}

// Monitor starts continuous monitoring
func (a *Analyzer) Monitor(ctx context.Context) error {
	logger := otelzap.Ctx(a.rc.Ctx)
	logger.Info("Starting storage monitoring",
		zap.Duration("interval", a.config.Interval))
	
	ticker := time.NewTicker(a.config.Interval)
	defer ticker.Stop()
	
	// Initial analysis
	if _, err := a.Analyze(); err != nil {
		logger.Error("Initial analysis failed", zap.Error(err))
	}
	
	for {
		select {
		case <-ctx.Done():
			logger.Info("Storage monitoring stopped")
			return ctx.Err()
			
		case <-ticker.C:
			if _, err := a.Analyze(); err != nil {
				logger.Error("Analysis failed", zap.Error(err))
			}
		}
	}
}

// getCurrentUsage retrieves current disk usage information
func (a *Analyzer) getCurrentUsage() ([]*StorageStatus, error) {
	logger := otelzap.Ctx(a.rc.Ctx)
	
	// Use df to get disk usage
	output, err := execute.Run(a.rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-B1", "-T", "-x", "tmpfs", "-x", "devtmpfs"},
		Capture: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run df: %w", err)
	}
	
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("unexpected df output")
	}
	
	var statuses []*StorageStatus
	
	// Skip header line
	for i := 1; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		if len(fields) < 7 {
			logger.Warn("Skipping malformed df line", zap.String("line", lines[i]))
			continue
		}
		
		// Parse fields
		device := fields[0]
		filesystem := fields[1]
		totalBytes, _ := strconv.ParseUint(fields[2], 10, 64)
		usedBytes, _ := strconv.ParseUint(fields[3], 10, 64)
		freeBytes, _ := strconv.ParseUint(fields[4], 10, 64)
		usagePercentStr := strings.TrimSuffix(fields[5], "%")
		usagePercent, _ := strconv.ParseFloat(usagePercentStr, 64)
		mountPoint := fields[6]
		
		// Skip system filesystems
		if strings.HasPrefix(mountPoint, "/dev") ||
			strings.HasPrefix(mountPoint, "/sys") ||
			strings.HasPrefix(mountPoint, "/proc") ||
			strings.HasPrefix(mountPoint, "/run") && mountPoint != "/run/shm" {
			continue
		}
		
		status := &StorageStatus{
			MountPoint:   mountPoint,
			Device:       device,
			Filesystem:   filesystem,
			TotalBytes:   totalBytes,
			UsedBytes:    usedBytes,
			FreeBytes:    freeBytes,
			UsagePercent: usagePercent,
			LastChecked:  time.Now(),
		}
		
		statuses = append(statuses, status)
		
		logger.Debug("Analyzed mount point",
			zap.String("mount_point", mountPoint),
			zap.Float64("usage_percent", usagePercent),
			zap.Uint64("free_bytes", freeBytes))
	}
	
	return statuses, nil
}

// calculateGrowthRate calculates storage growth rate
// In production, this would use historical data
func (a *Analyzer) calculateGrowthRate(status *StorageStatus) float64 {
	// Placeholder - in production would query historical data
	// Returns estimated GB/day growth rate
	return 0.5
}

// getAlertLevel determines alert level based on action
func (a *Analyzer) getAlertLevel(action threshold.Action) string {
	switch action {
	case threshold.ActionNone:
		return "info"
	case threshold.ActionMonitor:
		return "info"
	case threshold.ActionCompress:
		return "warning"
	case threshold.ActionCleanup:
		return "warning"
	case threshold.ActionDegrade:
		return "error"
	case threshold.ActionEmergency:
		return "error"
	case threshold.ActionCritical:
		return "critical"
	default:
		return "info"
	}
}
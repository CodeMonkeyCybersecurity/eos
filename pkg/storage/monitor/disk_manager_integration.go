// pkg/storage_monitor/disk_manager_integration.go

package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiskManagerService provides high-level disk management operations
type DiskManagerService struct {
	diskManager DiskManager
	logger      otelzap.LoggerWithCtx
	rc          *eos_io.RuntimeContext
}

// NewDiskManagerService creates a new disk manager service
func NewDiskManagerService(rc *eos_io.RuntimeContext) (*DiskManagerService, error) {
	// Create SaltStack client
	saltClient := saltstack.NewClient(otelzap.Ctx(rc.Ctx))

	// Create disk manager with SaltStack backend
	diskManager := NewSaltStackDiskManager(saltClient, rc)

	return &DiskManagerService{
		diskManager: diskManager,
		logger:      otelzap.Ctx(rc.Ctx),
		rc:          rc,
	}, nil
}

// PerformDiskHealthCheck performs comprehensive disk health monitoring
func (dms *DiskManagerService) PerformDiskHealthCheck(ctx context.Context, target string) (*DiskHealthReport, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Starting comprehensive disk health check", zap.String("target", target))

	report := &DiskHealthReport{
		Target:    target,
		Timestamp: time.Now(),
		Status:    "CHECKING",
	}

	// Get all disk usage
	usageData, err := dms.diskManager.GetAllDiskUsage(ctx, target)
	if err != nil {
		report.Status = "ERROR"
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to get disk usage: %v", err))
		return report, fmt.Errorf("failed to get disk usage: %w", err)
	}
	report.DiskUsage = usageData

	// Check SMART data for all disks
	smartData, err := dms.diskManager.CheckDiskHealth(ctx, target)
	if err != nil {
		logger.Warn("Failed to get SMART data", zap.Error(err))
		report.Warnings = append(report.Warnings, fmt.Sprintf("SMART data unavailable: %v", err))
	} else {
		report.SMARTData = smartData
	}

	// Get mount points
	mountPoints, err := dms.diskManager.GetMountPoints(ctx, target)
	if err != nil {
		logger.Warn("Failed to get mount points", zap.Error(err))
		report.Warnings = append(report.Warnings, fmt.Sprintf("Mount points unavailable: %v", err))
	} else {
		report.MountPoints = mountPoints
	}

	// Analyze health status
	dms.analyzeHealthStatus(report)

	logger.Info("Disk health check completed",
		zap.String("status", report.Status),
		zap.Int("disk_count", len(report.DiskUsage)),
		zap.Int("smart_devices", len(report.SMARTData)))

	return report, nil
}

// PerformDiskCleanup performs intelligent disk cleanup based on usage patterns
func (dms *DiskManagerService) PerformDiskCleanup(ctx context.Context, target string, options CleanupOptions) (*DiskCleanupReport, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Starting disk cleanup operation",
		zap.String("target", target),
		zap.Bool("dry_run", options.DryRun))

	report := &DiskCleanupReport{
		Target:    target,
		Timestamp: time.Now(),
		Options:   options,
	}

	// Get current disk usage before cleanup
	beforeUsage, err := dms.diskManager.GetAllDiskUsage(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("failed to get initial disk usage: %w", err)
	}
	report.BeforeUsage = beforeUsage

	// Perform cleanup
	cleanupResult, err := dms.diskManager.CleanupTempFiles(ctx, target, options)
	if err != nil {
		report.Status = "FAILED"
		report.Error = err.Error()
		return report, fmt.Errorf("cleanup operation failed: %w", err)
	}
	report.CleanupResult = *cleanupResult

	// Get disk usage after cleanup (if not dry run)
	if !options.DryRun {
		afterUsage, err := dms.diskManager.GetAllDiskUsage(ctx, target)
		if err != nil {
			logger.Warn("Failed to get post-cleanup disk usage", zap.Error(err))
		} else {
			report.AfterUsage = afterUsage
			dms.calculateCleanupEffectiveness(report)
		}
	}

	report.Status = "SUCCESS"
	logger.Info("Disk cleanup completed",
		zap.String("status", report.Status),
		zap.Int64("bytes_freed", cleanupResult.FreedBytes),
		zap.Int("files_removed", cleanupResult.FilesRemoved))

	return report, nil
}

// AutoExpandFilesystems automatically expands filesystems that are running low on space
func (dms *DiskManagerService) AutoExpandFilesystems(ctx context.Context, target string, thresholdPercent float64) (*FilesystemExpansionReport, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Starting automatic filesystem expansion",
		zap.String("target", target),
		zap.Float64("threshold_percent", thresholdPercent))

	report := &FilesystemExpansionReport{
		Target:    target,
		Timestamp: time.Now(),
		Threshold: thresholdPercent,
	}

	// Get current disk usage
	usageData, err := dms.diskManager.GetAllDiskUsage(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}

	// Identify filesystems that need expansion
	var candidatesForExpansion []DiskUsage
	for _, usage := range usageData {
		if usage.UsedPercent >= thresholdPercent {
			candidatesForExpansion = append(candidatesForExpansion, usage)
		}
	}

	report.CandidateFilesystems = candidatesForExpansion

	if len(candidatesForExpansion) == 0 {
		report.Status = "NO_ACTION_NEEDED"
		logger.Info("No filesystems require expansion")
		return report, nil
	}

	// Attempt to expand each candidate filesystem
	for _, candidate := range candidatesForExpansion {
		expansionResult := FilesystemExpansionResult{
			Path:        candidate.Path,
			Device:      candidate.Device,
			BeforeUsage: candidate,
		}

		err := dms.diskManager.ExpandFilesystem(ctx, target, candidate.Device)
		if err != nil {
			expansionResult.Status = "FAILED"
			expansionResult.Error = err.Error()
			logger.Warn("Failed to expand filesystem",
				zap.String("device", candidate.Device),
				zap.Error(err))
		} else {
			expansionResult.Status = "SUCCESS"

			// Get updated usage after expansion
			afterUsage, err := dms.diskManager.GetDiskUsage(ctx, target, candidate.Path)
			if err != nil {
				logger.Warn("Failed to get post-expansion usage", zap.Error(err))
			} else {
				expansionResult.AfterUsage = *afterUsage
			}
		}

		report.ExpansionResults = append(report.ExpansionResults, expansionResult)
	}

	// Determine overall status
	successCount := 0
	for _, result := range report.ExpansionResults {
		if result.Status == "SUCCESS" {
			successCount++
		}
	}

	if successCount == len(report.ExpansionResults) {
		report.Status = "SUCCESS"
	} else if successCount > 0 {
		report.Status = "PARTIAL_SUCCESS"
	} else {
		report.Status = "FAILED"
	}

	logger.Info("Filesystem expansion completed",
		zap.String("status", report.Status),
		zap.Int("candidates", len(candidatesForExpansion)),
		zap.Int("successful", successCount))

	return report, nil
}

// MonitorDiskGrowth tracks disk usage growth patterns
func (dms *DiskManagerService) MonitorDiskGrowth(ctx context.Context, target string, paths []string) (*DiskGrowthReport, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Starting disk growth monitoring",
		zap.String("target", target),
		zap.Strings("paths", paths))

	report := &DiskGrowthReport{
		Target:    target,
		Timestamp: time.Now(),
		Paths:     paths,
	}

	// Get current usage for all specified paths
	for _, path := range paths {
		usage, err := dms.diskManager.GetDiskUsage(ctx, target, path)
		if err != nil {
			logger.Warn("Failed to get usage for path",
				zap.String("path", path),
				zap.Error(err))
			continue
		}

		// Load historical growth data (this would integrate with existing growth tracking)
		growthMetrics, err := dms.loadGrowthMetrics(ctx, target, path)
		if err != nil {
			logger.Warn("Failed to load growth metrics",
				zap.String("path", path),
				zap.Error(err))
			// Create new metrics if none exist
			growthMetrics = &GrowthMetrics{
				Path:        path,
				CurrentSize: usage.UsedSize,
			}
		} else {
			// Update metrics with current data
			growthMetrics.PreviousSize = growthMetrics.CurrentSize
			growthMetrics.CurrentSize = usage.UsedSize
			growthMetrics.GrowthBytes = growthMetrics.CurrentSize - growthMetrics.PreviousSize

			if growthMetrics.PreviousSize > 0 {
				growthMetrics.GrowthPercent = float64(growthMetrics.GrowthBytes) / float64(growthMetrics.PreviousSize) * 100
			}
		}

		report.GrowthMetrics = append(report.GrowthMetrics, *growthMetrics)
	}

	// Analyze growth patterns and generate alerts
	dms.analyzeGrowthPatterns(report)

	logger.Info("Disk growth monitoring completed",
		zap.Int("paths_monitored", len(report.GrowthMetrics)),
		zap.Int("alerts", len(report.Alerts)))

	return report, nil
}

// Helper methods for analysis and reporting

func (dms *DiskManagerService) analyzeHealthStatus(report *DiskHealthReport) {
	criticalIssues := 0
	warnings := 0

	// Check disk usage thresholds
	for _, usage := range report.DiskUsage {
		if usage.UsedPercent >= 95 {
			criticalIssues++
			report.Errors = append(report.Errors,
				fmt.Sprintf("Critical: %s is %0.1f%% full", usage.Path, usage.UsedPercent))
		} else if usage.UsedPercent >= 85 {
			warnings++
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("Warning: %s is %0.1f%% full", usage.Path, usage.UsedPercent))
		}
	}

	// Check SMART data
	for _, smart := range report.SMARTData {
		if smart.OverallHealth != "PASSED" && smart.OverallHealth != "" {
			criticalIssues++
			report.Errors = append(report.Errors,
				fmt.Sprintf("Critical: Disk %s health status: %s", smart.Device, smart.OverallHealth))
		}
	}

	// Determine overall status
	if criticalIssues > 0 {
		report.Status = "CRITICAL"
	} else if warnings > 0 {
		report.Status = "WARNING"
	} else {
		report.Status = "HEALTHY"
	}

	report.Summary = DiskHealthSummary{
		TotalDisks:    len(report.DiskUsage),
		HealthyDisks:  len(report.DiskUsage) - criticalIssues - warnings,
		WarningDisks:  warnings,
		CriticalDisks: criticalIssues,
		TotalCapacity: dms.calculateTotalCapacity(report.DiskUsage),
		TotalUsed:     dms.calculateTotalUsed(report.DiskUsage),
		AverageUsage:  dms.calculateAverageUsage(report.DiskUsage),
	}
}

func (dms *DiskManagerService) calculateCleanupEffectiveness(report *DiskCleanupReport) {
	if len(report.BeforeUsage) != len(report.AfterUsage) {
		return
	}

	var totalFreed int64
	for i, before := range report.BeforeUsage {
		if i < len(report.AfterUsage) {
			after := report.AfterUsage[i]
			if before.Path == after.Path {
				freed := before.UsedSize - after.UsedSize
				if freed > 0 {
					totalFreed += freed
				}
			}
		}
	}

	report.EffectivenessMetrics = CleanupEffectivenessMetrics{
		TotalFreedBytes:    totalFreed,
		TargetFreedBytes:   report.CleanupResult.FreedBytes,
		EffectivenessRatio: float64(totalFreed) / float64(report.CleanupResult.FreedBytes),
	}
}

func (dms *DiskManagerService) analyzeGrowthPatterns(report *DiskGrowthReport) {
	for _, metrics := range report.GrowthMetrics {
		// Generate alerts based on growth patterns
		if metrics.GrowthPercent > 20 {
			alert := DiskGrowthAlert{
				Path:        metrics.Path,
				Severity:    "HIGH",
				Message:     fmt.Sprintf("Rapid growth detected: %0.1f%% increase", metrics.GrowthPercent),
				GrowthBytes: metrics.GrowthBytes,
			}
			report.Alerts = append(report.Alerts, alert)
		} else if metrics.GrowthPercent > 10 {
			alert := DiskGrowthAlert{
				Path:        metrics.Path,
				Severity:    "MEDIUM",
				Message:     fmt.Sprintf("Moderate growth detected: %0.1f%% increase", metrics.GrowthPercent),
				GrowthBytes: metrics.GrowthBytes,
			}
			report.Alerts = append(report.Alerts, alert)
		}
	}
}

func (dms *DiskManagerService) loadGrowthMetrics(ctx context.Context, target, path string) (*GrowthMetrics, error) {
	// This would integrate with the existing growth tracking functionality
	// For now, return a placeholder implementation
	return &GrowthMetrics{
		Path:       path,
		TimeWindow: 24 * time.Hour,
	}, nil
}

func (dms *DiskManagerService) calculateTotalCapacity(usage []DiskUsage) int64 {
	var total int64
	for _, u := range usage {
		total += u.TotalSize
	}
	return total
}

func (dms *DiskManagerService) calculateTotalUsed(usage []DiskUsage) int64 {
	var total int64
	for _, u := range usage {
		total += u.UsedSize
	}
	return total
}

func (dms *DiskManagerService) calculateAverageUsage(usage []DiskUsage) float64 {
	if len(usage) == 0 {
		return 0
	}

	var total float64
	for _, u := range usage {
		total += u.UsedPercent
	}
	return total / float64(len(usage))
}

// Report types for comprehensive disk management operations

type DiskHealthReport struct {
	Target      string            `json:"target"`
	Timestamp   time.Time         `json:"timestamp"`
	Status      string            `json:"status"` // HEALTHY, WARNING, CRITICAL, ERROR
	DiskUsage   []DiskUsage       `json:"disk_usage"`
	SMARTData   []SMARTData       `json:"smart_data"`
	MountPoints []MountInfo       `json:"mount_points"`
	Summary     DiskHealthSummary `json:"summary"`
	Warnings    []string          `json:"warnings"`
	Errors      []string          `json:"errors"`
}

type DiskHealthSummary struct {
	TotalDisks    int     `json:"total_disks"`
	HealthyDisks  int     `json:"healthy_disks"`
	WarningDisks  int     `json:"warning_disks"`
	CriticalDisks int     `json:"critical_disks"`
	TotalCapacity int64   `json:"total_capacity"`
	TotalUsed     int64   `json:"total_used"`
	AverageUsage  float64 `json:"average_usage"`
}

type DiskCleanupReport struct {
	Target               string                      `json:"target"`
	Timestamp            time.Time                   `json:"timestamp"`
	Status               string                      `json:"status"`
	Options              CleanupOptions              `json:"options"`
	BeforeUsage          []DiskUsage                 `json:"before_usage"`
	AfterUsage           []DiskUsage                 `json:"after_usage"`
	CleanupResult        DiskCleanupResult           `json:"cleanup_result"`
	EffectivenessMetrics CleanupEffectivenessMetrics `json:"effectiveness_metrics"`
	Error                string                      `json:"error,omitempty"`
}

type CleanupEffectivenessMetrics struct {
	TotalFreedBytes    int64   `json:"total_freed_bytes"`
	TargetFreedBytes   int64   `json:"target_freed_bytes"`
	EffectivenessRatio float64 `json:"effectiveness_ratio"`
}

type FilesystemExpansionReport struct {
	Target               string                      `json:"target"`
	Timestamp            time.Time                   `json:"timestamp"`
	Status               string                      `json:"status"`
	Threshold            float64                     `json:"threshold"`
	CandidateFilesystems []DiskUsage                 `json:"candidate_filesystems"`
	ExpansionResults     []FilesystemExpansionResult `json:"expansion_results"`
}

type FilesystemExpansionResult struct {
	Path        string    `json:"path"`
	Device      string    `json:"device"`
	Status      string    `json:"status"`
	BeforeUsage DiskUsage `json:"before_usage"`
	AfterUsage  DiskUsage `json:"after_usage"`
	Error       string    `json:"error,omitempty"`
}

type DiskGrowthReport struct {
	Target        string            `json:"target"`
	Timestamp     time.Time         `json:"timestamp"`
	Paths         []string          `json:"paths"`
	GrowthMetrics []GrowthMetrics   `json:"growth_metrics"`
	Alerts        []DiskGrowthAlert `json:"alerts"`
}

type DiskGrowthAlert struct {
	Path        string `json:"path"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	GrowthBytes int64  `json:"growth_bytes"`
}

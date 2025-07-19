// pkg/storage/emergency/recovery.go

package emergency

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Handler manages emergency storage recovery operations
type Handler struct {
	rc *eos_io.RuntimeContext
}

// RecoveryResult contains the results of emergency recovery
type RecoveryResult struct {
	FreedBytes      uint64
	DeletedFiles    int
	StoppedServices []string
	CompressedFiles int
	Errors          []error
}

// DiagnosticsReport contains emergency diagnostics information
type DiagnosticsReport struct {
	Timestamp  time.Time
	DiskUsage  map[string]DiskInfo
	LargeFiles []string
	GrowthDirs []string
	Services   []ServiceInfo
}

// DiskInfo contains disk usage information
type DiskInfo struct {
	MountPoint   string
	TotalBytes   uint64
	UsedBytes    uint64
	FreeBytes    uint64
	UsagePercent float64
}

// ServiceInfo contains service status information
type ServiceInfo struct {
	Name   string
	Status string
	Memory uint64
}

// NewHandler creates a new emergency handler
func NewHandler(rc *eos_io.RuntimeContext) *Handler {
	return &Handler{rc: rc}
}

// EmergencyRecover performs emergency storage recovery
func (h *Handler) EmergencyRecover() (*RecoveryResult, error) {
	logger := otelzap.Ctx(h.rc.Ctx)
	logger.Error("EMERGENCY RECOVERY: Starting aggressive space recovery")
	
	result := &RecoveryResult{}
	
	// Get initial disk usage
	initialUsage, err := h.getDiskUsage("/")
	if err != nil {
		logger.Error("Failed to get initial disk usage", zap.Error(err))
	}
	
	// 1. Stop non-critical services
	logger.Info("Stopping non-critical services")
	stoppedServices := h.stopNonCriticalServices()
	result.StoppedServices = stoppedServices
	
	// 2. Clear all temporary files
	logger.Info("Clearing temporary files")
	if err := h.clearTemporaryFiles(); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("temp cleanup: %w", err))
	}
	
	// 3. Clear package caches
	logger.Info("Clearing package caches")
	if err := h.clearPackageCaches(); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("cache cleanup: %w", err))
	}
	
	// 4. Aggressive log cleanup
	logger.Info("Performing aggressive log cleanup")
	compressed, deleted := h.aggressiveLogCleanup()
	result.CompressedFiles = compressed
	result.DeletedFiles += deleted
	
	// 5. Docker cleanup if present
	logger.Info("Cleaning Docker resources")
	if err := h.dockerEmergencyCleanup(); err != nil {
		logger.Debug("Docker cleanup skipped or failed", zap.Error(err))
	}
	
	// 6. Clear user caches
	logger.Info("Clearing user caches")
	if err := h.clearUserCaches(); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("user cache cleanup: %w", err))
	}
	
	// Calculate freed space
	if initialUsage != nil {
		finalUsage, err := h.getDiskUsage("/")
		if err == nil && finalUsage != nil {
			result.FreedBytes = initialUsage.UsedBytes - finalUsage.UsedBytes
			logger.Info("Space recovered",
				zap.Uint64("freed_bytes", result.FreedBytes),
				zap.Uint64("freed_mb", result.FreedBytes/(1024*1024)))
		}
	}
	
	return result, nil
}

// GenerateDiagnostics creates an emergency diagnostics report
func (h *Handler) GenerateDiagnostics() (*DiagnosticsReport, error) {
	logger := otelzap.Ctx(h.rc.Ctx)
	logger.Info("Generating emergency diagnostics")
	
	report := &DiagnosticsReport{
		Timestamp: time.Now(),
		DiskUsage: make(map[string]DiskInfo),
	}
	
	// Get disk usage for all mount points
	output, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-B1"},
		Capture: true,
	})
	if err == nil {
		report.DiskUsage = h.parseDfOutput(output)
	}
	
	// Find large files
	largeFiles, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "find",
		Args:    []string{"/", "-type", "f", "-size", "+100M", "-exec", "ls", "-lh", "{}", ";"},
		Capture: true,
		Timeout: 30 * time.Second,
	})
	if err == nil {
		report.LargeFiles = strings.Split(strings.TrimSpace(largeFiles), "\n")
	}
	
	// Find rapidly growing directories
	output, err = execute.Run(h.rc.Ctx, execute.Options{
		Command: "du",
		Args:    []string{"-h", "--max-depth=2", "/var", "/tmp", "/home"},
		Capture: true,
		Timeout: 30 * time.Second,
	})
	if err == nil {
		report.GrowthDirs = h.parseGrowthDirs(output)
	}
	
	return report, nil
}

// stopNonCriticalServices stops services that can be safely stopped
func (h *Handler) stopNonCriticalServices() []string {
	logger := otelzap.Ctx(h.rc.Ctx)
	
	// List of services safe to stop in emergency
	nonCritical := []string{
		"jenkins",
		"gitlab-runner",
		"elasticsearch",
		"grafana",
		"prometheus",
		"minio",
		"nexus",
	}
	
	var stopped []string
	for _, service := range nonCritical {
		// Check if service is running
		if _, err := execute.Run(h.rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", service},
			Capture: true,
		}); err == nil {
			// Stop the service
			if _, err := execute.Run(h.rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"stop", service},
				Capture: false,
			}); err == nil {
				stopped = append(stopped, service)
				logger.Info("Stopped service", zap.String("service", service))
			}
		}
	}
	
	return stopped
}

// clearTemporaryFiles removes all temporary files
func (h *Handler) clearTemporaryFiles() error {
	logger := otelzap.Ctx(h.rc.Ctx)
	
	tempDirs := []string{"/tmp", "/var/tmp"}
	for _, dir := range tempDirs {
		logger.Info("Clearing temporary directory", zap.String("dir", dir))
		
		// Remove all files (keeping directory structure)
		if _, err := execute.Run(h.rc.Ctx, execute.Options{
			Command: "find",
			Args:    []string{dir, "-type", "f", "-delete"},
			Capture: false,
		}); err != nil {
			logger.Error("Failed to clear temp files", 
				zap.String("dir", dir), 
				zap.Error(err))
		}
	}
	
	return nil
}

// clearPackageCaches clears package manager caches
func (h *Handler) clearPackageCaches() error {
	logger := otelzap.Ctx(h.rc.Ctx)
	
	// APT cache
	if _, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"clean"},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to clean APT cache", zap.Error(err))
	}
	
	// Remove old packages
	if _, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"autoremove", "--purge", "-y"},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to autoremove packages", zap.Error(err))
	}
	
	// Snap cache if present
	if _, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "snap",
		Args:    []string{"list", "--all"},
		Capture: true,
	}); err == nil {
		// Snap is installed, clean it
		execute.Run(h.rc.Ctx, execute.Options{
			Command: "sh",
			Args:    []string{"-c", "snap list --all | awk '/disabled/{print $1, $3}' | while read name rev; do snap remove \"$name\" --revision=\"$rev\"; done"},
			Capture: false,
		})
	}
	
	return nil
}

// aggressiveLogCleanup performs aggressive log cleanup
func (h *Handler) aggressiveLogCleanup() (compressed, deleted int) {
	logger := otelzap.Ctx(h.rc.Ctx)
	
	// Delete all compressed logs
	output, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "find",
		Args:    []string{"/var/log", "-name", "*.gz", "-delete", "-print"},
		Capture: true,
	})
	if err == nil {
		deleted = len(strings.Split(strings.TrimSpace(output), "\n"))
	}
	
	// Delete old logs
	output, err = execute.Run(h.rc.Ctx, execute.Options{
		Command: "find",
		Args:    []string{"/var/log", "-name", "*.log.*", "-mtime", "+1", "-delete", "-print"},
		Capture: true,
	})
	if err == nil {
		deleted += len(strings.Split(strings.TrimSpace(output), "\n"))
	}
	
	// Truncate active logs
	if _, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "find",
		Args:    []string{"/var/log", "-name", "*.log", "-size", "+100M", "-exec", "truncate", "-s", "0", "{}", ";"},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to truncate large logs", zap.Error(err))
	}
	
	// Clear journal
	if _, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "journalctl",
		Args:    []string{"--vacuum-size=50M"},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to vacuum journal", zap.Error(err))
	}
	
	return compressed, deleted
}

// dockerEmergencyCleanup performs emergency Docker cleanup
func (h *Handler) dockerEmergencyCleanup() error {
	// Check if Docker is installed
	if _, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"docker"},
		Capture: true,
	}); err != nil {
		return fmt.Errorf("docker not found")
	}
	
	// Prune everything
	execute.Run(h.rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"system", "prune", "-a", "-f", "--volumes"},
		Capture: false,
	})
	
	return nil
}

// clearUserCaches clears user cache directories
func (h *Handler) clearUserCaches() error {
	// Clear common cache directories
	cacheDirs := []string{
		"/home/*/.cache",
		"/root/.cache",
		"/var/cache/apt/archives/*.deb",
	}
	
	for _, pattern := range cacheDirs {
		execute.Run(h.rc.Ctx, execute.Options{
			Command: "sh",
			Args:    []string{"-c", fmt.Sprintf("rm -rf %s", pattern)},
			Capture: false,
		})
	}
	
	return nil
}

// getDiskUsage gets disk usage for a path
func (h *Handler) getDiskUsage(path string) (*DiskInfo, error) {
	output, err := execute.Run(h.rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-B1", path},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("unexpected df output")
	}
	
	fields := strings.Fields(lines[1])
	if len(fields) < 6 {
		return nil, fmt.Errorf("unexpected df format")
	}
	
	total, _ := strconv.ParseUint(fields[1], 10, 64)
	used, _ := strconv.ParseUint(fields[2], 10, 64)
	free, _ := strconv.ParseUint(fields[3], 10, 64)
	percentStr := strings.TrimSuffix(fields[4], "%")
	percent, _ := strconv.ParseFloat(percentStr, 64)
	
	return &DiskInfo{
		MountPoint:   path,
		TotalBytes:   total,
		UsedBytes:    used,
		FreeBytes:    free,
		UsagePercent: percent,
	}, nil
}

// parseDfOutput parses df output into DiskInfo map
func (h *Handler) parseDfOutput(output string) map[string]DiskInfo {
	result := make(map[string]DiskInfo)
	
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i := 1; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		if len(fields) >= 6 {
			total, _ := strconv.ParseUint(fields[1], 10, 64)
			used, _ := strconv.ParseUint(fields[2], 10, 64)
			free, _ := strconv.ParseUint(fields[3], 10, 64)
			percentStr := strings.TrimSuffix(fields[4], "%")
			percent, _ := strconv.ParseFloat(percentStr, 64)
			
			mountPoint := fields[5]
			if len(fields) > 6 {
				mountPoint = fields[6]
			}
			
			result[mountPoint] = DiskInfo{
				MountPoint:   mountPoint,
				TotalBytes:   total,
				UsedBytes:    used,
				FreeBytes:    free,
				UsagePercent: percent,
			}
		}
	}
	
	return result
}

// parseGrowthDirs parses du output for large directories
func (h *Handler) parseGrowthDirs(output string) []string {
	var dirs []string
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			size := fields[0]
			path := fields[1]
			
			// Check if size is large (contains G or has large M value)
			if strings.Contains(size, "G") || 
			   (strings.Contains(size, "M") && h.parseSizeValue(size) > 500) {
				dirs = append(dirs, fmt.Sprintf("%s %s", size, path))
			}
		}
	}
	
	return dirs
}

// parseSizeValue extracts numeric value from size string
func (h *Handler) parseSizeValue(size string) float64 {
	size = strings.TrimSpace(size)
	if len(size) == 0 {
		return 0
	}
	
	// Remove unit suffix
	numStr := size[:len(size)-1]
	val, _ := strconv.ParseFloat(numStr, 64)
	
	// Convert to MB
	unit := size[len(size)-1:]
	switch unit {
	case "G":
		return val * 1024
	case "M":
		return val
	case "K":
		return val / 1024
	default:
		return val
	}
}
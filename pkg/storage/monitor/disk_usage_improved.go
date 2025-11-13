package monitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// DiskUsageChecker interface for better testability
type DiskUsageChecker interface {
	CheckDiskUsage(ctx context.Context, paths []string) ([]DiskUsage, error)
	MonitorDiskUsage(ctx context.Context, config *MonitorConfig) ([]Alert, error)
	FindLargeDirectories(ctx context.Context, path string, topN int) ([]DirectoryInfo, error)
	FindLargeFiles(ctx context.Context, path string, minSize int64, topN int) ([]FileInfo, error)
}

// SystemDiskChecker implements DiskUsageChecker using system calls
type SystemDiskChecker struct {
	commandRunner CommandRunner
}

// CommandRunner interface for executing system commands (testable)
type CommandRunner interface {
	RunCommand(ctx context.Context, name string, args ...string) ([]byte, error)
}

// SystemCommandRunner implements CommandRunner using real system commands
type SystemCommandRunner struct{}

func (s *SystemCommandRunner) RunCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// NewSystemDiskChecker creates a new system disk checker
func NewSystemDiskChecker() *SystemDiskChecker {
	return &SystemDiskChecker{
		commandRunner: &SystemCommandRunner{},
	}
}

// CheckDiskUsageV2 demonstrates improved error handling and context usage
func (s *SystemDiskChecker) CheckDiskUsage(ctx context.Context, paths []string) ([]DiskUsage, error) {
	if len(paths) == 0 {
		paths = []string{"/"}
	}

	// Pre-allocate slice with known capacity
	usageData := make([]DiskUsage, 0, len(paths))

	// Use errgroup for better error handling in concurrent scenarios
	for _, path := range paths {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		usage, err := s.getDiskUsageForPath(ctx, path)
		if err != nil {
			// Wrap error with more context
			return nil, fmt.Errorf("failed to get disk usage for path %q: %w", path, err)
		}

		usageData = append(usageData, *usage)
	}

	return usageData, nil
}

// MonitorDiskUsage with improved error handling
func (s *SystemDiskChecker) MonitorDiskUsage(ctx context.Context, config *MonitorConfig) ([]Alert, error) {
	if config == nil {
		return nil, eos_err.NewUserError("monitor config cannot be nil")
	}

	// Validate configuration
	if err := s.validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid monitor configuration: %w", err)
	}

	monitorPaths := config.MonitorPaths
	if len(monitorPaths) == 0 {
		mounts, err := s.getAllMountPoints(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get mount points: %w", err)
		}
		monitorPaths = mounts
	}

	alerts := make([]Alert, 0)
	excluded := make(map[string]bool, len(config.ExcludePaths))
	for _, ex := range config.ExcludePaths {
		excluded[ex] = true
	}

	for _, path := range monitorPaths {
		select {
		case <-ctx.Done():
			return alerts, ctx.Err()
		default:
		}

		if excluded[path] {
			continue
		}

		usage, err := s.getDiskUsageForPath(ctx, path)
		if err != nil {
			// Log warning but continue with other paths
			continue
		}

		if isExcludedFilesystem(usage.Filesystem, config.ExcludeFilesystems) {
			continue
		}

		// Generate alerts using helper function
		pathAlerts := s.generateAlertsForUsage(usage, config)
		alerts = append(alerts, pathAlerts...)
	}

	return alerts, nil
}

// FindLargeDirectories with improved error handling and context support
func (s *SystemDiskChecker) FindLargeDirectories(ctx context.Context, path string, topN int) ([]DirectoryInfo, error) {
	if topN <= 0 {
		return nil, eos_err.NewUserError("topN must be positive, got %d", topN)
	}

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, eos_err.NewUserError("path not found: %s", path)
		}
		return nil, fmt.Errorf("failed to access path %q: %w", path, err)
	}

	// Use command runner for testability
	output, err := s.commandRunner.RunCommand(ctx, "du", "-xb", "--max-depth=3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to run du command: %w", err)
	}

	dirs, err := s.parseDuOutput(string(output), path, topN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse du output: %w", err)
	}

	// Enrich with additional information
	if err := s.enrichDirectoryInfo(ctx, dirs); err != nil {
		// Log warning but don't fail the entire operation
		return dirs, nil
	}

	return dirs, nil
}

// FindLargeFiles with improved error handling
func (s *SystemDiskChecker) FindLargeFiles(ctx context.Context, path string, minSize int64, topN int) ([]FileInfo, error) {
	if minSize <= 0 {
		return nil, eos_err.NewUserError("minSize must be positive, got %d", minSize)
	}
	if topN <= 0 {
		return nil, eos_err.NewUserError("topN must be positive, got %d", topN)
	}

	// Try find command first, fallback to manual search
	files, err := s.findLargeFilesWithCommand(ctx, path, minSize, topN)
	if err != nil {
		// Fallback to manual search
		return s.findLargeFilesManual(ctx, path, minSize, topN)
	}

	return files, nil
}

// Helper methods with improved error handling

func (s *SystemDiskChecker) validateConfig(config *MonitorConfig) error {
	if config.DiskUsageWarning < 0 || config.DiskUsageWarning > 100 {
		return fmt.Errorf("disk usage warning threshold must be 0-100, got %.1f", config.DiskUsageWarning)
	}
	if config.DiskUsageCritical < 0 || config.DiskUsageCritical > 100 {
		return fmt.Errorf("disk usage critical threshold must be 0-100, got %.1f", config.DiskUsageCritical)
	}
	if config.DiskUsageWarning >= config.DiskUsageCritical {
		return fmt.Errorf("warning threshold (%.1f) must be less than critical threshold (%.1f)",
			config.DiskUsageWarning, config.DiskUsageCritical)
	}
	return nil
}

func (s *SystemDiskChecker) getDiskUsageForPath(ctx context.Context, path string) (*DiskUsage, error) {
	var stat syscall.Statfs_t

	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, fmt.Errorf("failed to get filesystem stats: %w", err)
	}

	usage := &DiskUsage{
		Path:          path,
		TotalSize:     int64(stat.Blocks) * int64(stat.Bsize),
		AvailableSize: int64(stat.Bavail) * int64(stat.Bsize),
		InodesTotal:   stat.Files,
		InodesFree:    stat.Ffree,
		Timestamp:     time.Now(),
	}

	usage.UsedSize = usage.TotalSize - usage.AvailableSize
	if usage.TotalSize > 0 {
		usage.UsedPercent = float64(usage.UsedSize) * 100.0 / float64(usage.TotalSize)
	}

	usage.InodesUsed = usage.InodesTotal - usage.InodesFree
	if usage.InodesTotal > 0 {
		usage.InodesUsedPercent = float64(usage.InodesUsed) * 100.0 / float64(usage.InodesTotal)
	}

	// Get device and filesystem info with context
	if device, fs, options, err := s.getMountInfo(ctx, path); err == nil {
		usage.Device = device
		usage.Filesystem = fs
		usage.MountOptions = options
	}

	return usage, nil
}

func (s *SystemDiskChecker) getAllMountPoints(ctx context.Context) ([]string, error) {
	output, err := s.commandRunner.RunCommand(ctx, "findmnt", "-rno", "TARGET")
	if err != nil {
		return nil, fmt.Errorf("failed to get mount points: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	mounts := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			mounts = append(mounts, line)
		}
	}

	return mounts, nil
}

func (s *SystemDiskChecker) getMountInfo(ctx context.Context, path string) (device, filesystem string, options []string, err error) {
	output, err := s.commandRunner.RunCommand(ctx, "findmnt", "-rno", "SOURCE,FSTYPE,OPTIONS", "-T", path)
	if err != nil {
		return "", "", nil, err
	}

	parts := strings.Fields(string(output))
	if len(parts) >= 3 {
		device = parts[0]
		filesystem = parts[1]
		options = strings.Split(parts[2], ",")
	}
	return device, filesystem, options, nil
}

func (s *SystemDiskChecker) generateAlertsForUsage(usage *DiskUsage, config *MonitorConfig) []Alert {
	var alerts []Alert
	now := time.Now()

	// Disk usage alerts
	if usage.UsedPercent >= config.DiskUsageCritical {
		alerts = append(alerts, Alert{
			ID:        generateAlertID(usage.Path, AlertTypeDiskUsage),
			Type:      AlertTypeDiskUsage,
			Severity:  AlertSeverityCritical,
			Path:      usage.Path,
			Device:    usage.Device,
			Message:   fmt.Sprintf("Critical disk usage on %s: %.1f%% used", usage.Path, usage.UsedPercent),
			Value:     usage.UsedPercent,
			Threshold: config.DiskUsageCritical,
			Timestamp: now,
		})
	} else if usage.UsedPercent >= config.DiskUsageWarning {
		alerts = append(alerts, Alert{
			ID:        generateAlertID(usage.Path, AlertTypeDiskUsage),
			Type:      AlertTypeDiskUsage,
			Severity:  AlertSeverityWarning,
			Path:      usage.Path,
			Device:    usage.Device,
			Message:   fmt.Sprintf("Warning: disk usage on %s: %.1f%% used", usage.Path, usage.UsedPercent),
			Value:     usage.UsedPercent,
			Threshold: config.DiskUsageWarning,
			Timestamp: now,
		})
	}

	// Inode usage alerts
	if usage.InodesUsedPercent >= 90.0 {
		alerts = append(alerts, Alert{
			ID:        generateAlertID(usage.Path, AlertTypeFilesystem),
			Type:      AlertTypeFilesystem,
			Severity:  AlertSeverityCritical,
			Path:      usage.Path,
			Device:    usage.Device,
			Message:   fmt.Sprintf("Critical inode usage on %s: %.1f%% used", usage.Path, usage.InodesUsedPercent),
			Value:     usage.InodesUsedPercent,
			Threshold: 90.0,
			Timestamp: now,
		})
	}

	return alerts
}

func (s *SystemDiskChecker) parseDuOutput(output, rootPath string, topN int) ([]DirectoryInfo, error) {
	lines := strings.Split(output, "\n")
	dirSizes := make(map[string]DirectoryInfo)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		var size int64
		if _, err := fmt.Sscanf(parts[0], "%d", &size); err != nil {
			continue
		}

		dirPath := strings.Join(parts[1:], " ")
		if dirPath == rootPath {
			continue
		}

		dirSizes[dirPath] = DirectoryInfo{
			Path: dirPath,
			Size: size,
		}
	}

	// Convert to slice and sort
	dirs := make([]DirectoryInfo, 0, len(dirSizes))
	for _, dir := range dirSizes {
		dirs = append(dirs, dir)
	}

	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].Size > dirs[j].Size
	})

	if len(dirs) > topN {
		dirs = dirs[:topN]
	}

	return dirs, nil
}

func (s *SystemDiskChecker) enrichDirectoryInfo(ctx context.Context, dirs []DirectoryInfo) error {
	for i := range dirs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if info, err := os.Stat(dirs[i].Path); err == nil {
			dirs[i].ModifiedTime = info.ModTime()
		}

		// Count files (with context checking)
		fileCount := 0
		err := filepath.Walk(dirs[i].Path, func(path string, info os.FileInfo, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err == nil && !info.IsDir() {
				fileCount++
			}
			return nil
		})

		if err != nil && err != ctx.Err() {
			// Log warning but continue
			continue
		}

		dirs[i].FileCount = fileCount
	}

	return nil
}

func (s *SystemDiskChecker) findLargeFilesWithCommand(ctx context.Context, path string, minSize int64, topN int) ([]FileInfo, error) {
	output, err := s.commandRunner.RunCommand(ctx, "find", path, "-type", "f", "-size",
		fmt.Sprintf("+%dc", minSize), "-printf", "%s %p\n")
	if err != nil {
		return nil, err
	}

	return s.parseFindOutput(string(output), topN)
}

func (s *SystemDiskChecker) parseFindOutput(output string, topN int) ([]FileInfo, error) {
	lines := strings.Split(output, "\n")
	files := make([]FileInfo, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}

		var size int64
		if _, err := fmt.Sscanf(parts[0], "%d", &size); err != nil {
			continue
		}

		filePath := parts[1]
		fileInfo := FileInfo{
			Path: filePath,
			Size: size,
		}

		// Get additional info
		if info, err := os.Stat(filePath); err == nil {
			fileInfo.ModifiedTime = info.ModTime()
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				fileInfo.AccessTime = getAccessTime(stat)
			}
		}

		files = append(files, fileInfo)
	}

	// Sort by size
	sort.Slice(files, func(i, j int) bool {
		return files[i].Size > files[j].Size
	})

	if len(files) > topN {
		files = files[:topN]
	}

	return files, nil
}

func (s *SystemDiskChecker) findLargeFilesManual(ctx context.Context, path string, minSize int64, topN int) ([]FileInfo, error) {
	files := make([]FileInfo, 0)

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil || info.IsDir() {
			return nil
		}

		if info.Size() >= minSize {
			fileInfo := FileInfo{
				Path:         filePath,
				Size:         info.Size(),
				ModifiedTime: info.ModTime(),
			}

			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				fileInfo.AccessTime = getAccessTime(stat)
			}

			files = append(files, fileInfo)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort by size
	sort.Slice(files, func(i, j int) bool {
		return files[i].Size > files[j].Size
	})

	if len(files) > topN {
		files = files[:topN]
	}

	return files, nil
}

// Convenience functions that maintain backward compatibility
func CheckDiskUsageV2(rc *eos_io.RuntimeContext, paths []string) ([]DiskUsage, error) {
	checker := NewSystemDiskChecker()
	return checker.CheckDiskUsage(rc.Ctx, paths)
}

func MonitorDiskUsageV2(rc *eos_io.RuntimeContext, config *MonitorConfig) ([]Alert, error) {
	checker := NewSystemDiskChecker()
	return checker.MonitorDiskUsage(rc.Ctx, config)
}

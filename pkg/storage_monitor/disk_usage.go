package storage_monitor

import (
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
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckDiskUsage checks disk usage for specified paths
func CheckDiskUsage(rc *eos_io.RuntimeContext, paths []string) ([]DiskUsage, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing disk usage",
		zap.Strings("paths", paths))

	if len(paths) == 0 {
		paths = []string{"/"}
	}

	// INTERVENE
	logger.Info("Collecting disk usage information")

	usageData := make([]DiskUsage, 0, len(paths))

	for _, path := range paths {
		usage, err := getDiskUsageForPath(rc, path)
		if err != nil {
			logger.Warn("Failed to get disk usage",
				zap.String("path", path),
				zap.Error(err))
			continue
		}

		usageData = append(usageData, *usage)

		logger.Debug("Disk usage collected",
			zap.String("path", path),
			zap.Float64("usedPercent", usage.UsedPercent))
	}

	// EVALUATE
	logger.Info("Disk usage check completed",
		zap.Int("pathsChecked", len(usageData)))

	return usageData, nil
}

// MonitorDiskUsage monitors disk usage and generates alerts
func MonitorDiskUsage(rc *eos_io.RuntimeContext, config *MonitorConfig) ([]Alert, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing system for disk usage monitoring",
		zap.Float64("warningThreshold", config.DiskUsageWarning),
		zap.Float64("criticalThreshold", config.DiskUsageCritical))

	// Get all mount points if no specific paths
	monitorPaths := config.MonitorPaths
	if len(monitorPaths) == 0 {
		mounts, err := getAllMountPoints(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to get mount points: %w", err)
		}
		monitorPaths = mounts
	}

	// INTERVENE
	logger.Info("Monitoring disk usage",
		zap.Int("pathCount", len(monitorPaths)))

	alerts := make([]Alert, 0)

	for _, path := range monitorPaths {
		// Skip excluded paths
		if isExcludedPath(path, config.ExcludePaths) {
			continue
		}

		usage, err := getDiskUsageForPath(rc, path)
		if err != nil {
			logger.Warn("Failed to check disk usage",
				zap.String("path", path),
				zap.Error(err))
			continue
		}

		// Skip excluded filesystems
		if isExcludedFilesystem(usage.Filesystem, config.ExcludeFilesystems) {
			continue
		}

		// Check thresholds
		if usage.UsedPercent >= config.DiskUsageCritical {
			alert := Alert{
				ID:        generateAlertID(path, AlertTypeDiskUsage),
				Type:      AlertTypeDiskUsage,
				Severity:  AlertSeverityCritical,
				Path:      path,
				Device:    usage.Device,
				Message:   fmt.Sprintf("Critical disk usage on %s: %.1f%% used", path, usage.UsedPercent),
				Value:     usage.UsedPercent,
				Threshold: config.DiskUsageCritical,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)

			logger.Error("Critical disk usage detected",
				zap.String("path", path),
				zap.Float64("usedPercent", usage.UsedPercent))

		} else if usage.UsedPercent >= config.DiskUsageWarning {
			alert := Alert{
				ID:        generateAlertID(path, AlertTypeDiskUsage),
				Type:      AlertTypeDiskUsage,
				Severity:  AlertSeverityWarning,
				Path:      path,
				Device:    usage.Device,
				Message:   fmt.Sprintf("Warning: disk usage on %s: %.1f%% used", path, usage.UsedPercent),
				Value:     usage.UsedPercent,
				Threshold: config.DiskUsageWarning,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)

			logger.Warn("High disk usage detected",
				zap.String("path", path),
				zap.Float64("usedPercent", usage.UsedPercent))
		}

		// Check inode usage
		if usage.InodesUsedPercent >= 90.0 {
			alert := Alert{
				ID:        generateAlertID(path, AlertTypeFilesystem),
				Type:      AlertTypeFilesystem,
				Severity:  AlertSeverityCritical,
				Path:      path,
				Device:    usage.Device,
				Message:   fmt.Sprintf("Critical inode usage on %s: %.1f%% used", path, usage.InodesUsedPercent),
				Value:     usage.InodesUsedPercent,
				Threshold: 90.0,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)
		}
	}

	// EVALUATE
	logger.Info("Disk usage monitoring completed",
		zap.Int("alertsGenerated", len(alerts)))

	return alerts, nil
}

// FindLargeDirectories finds directories consuming the most space
func FindLargeDirectories(rc *eos_io.RuntimeContext, path string, topN int) ([]DirectoryInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing directory sizes",
		zap.String("path", path),
		zap.Int("topN", topN))

	if _, err := os.Stat(path); err != nil {
		return nil, eos_err.NewUserError("path not found: %s", path)
	}

	// INTERVENE
	logger.Info("Analyzing directory sizes")

	dirSizes := make(map[string]DirectoryInfo)

	// Use du command for efficiency
	duCmd := exec.CommandContext(rc.Ctx, "du", "-xb", "--max-depth=3", path)
	output, err := duCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run du command: %w", err)
	}

	lines := strings.Split(string(output), "\n")
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
		fmt.Sscanf(parts[0], "%d", &size)
		dirPath := strings.Join(parts[1:], " ")

		// Skip the root path itself
		if dirPath == path {
			continue
		}

		dirSizes[dirPath] = DirectoryInfo{
			Path: dirPath,
			Size: size,
		}
	}

	// Sort by size
	dirs := make([]DirectoryInfo, 0, len(dirSizes))
	for _, dir := range dirSizes {
		dirs = append(dirs, dir)
	}

	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].Size > dirs[j].Size
	})

	// Take top N
	if len(dirs) > topN {
		dirs = dirs[:topN]
	}

	// Get additional info for top directories
	for i := range dirs {
		if info, err := os.Stat(dirs[i].Path); err == nil {
			dirs[i].ModifiedTime = info.ModTime()
		}

		// Count files
		fileCount := 0
		if err := filepath.Walk(dirs[i].Path, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				fileCount++
			}
			return nil
		}); err != nil {
			fmt.Printf("Warning: Failed to walk directory %s: %v\n", dirs[i].Path, err)
		}
		dirs[i].FileCount = fileCount
	}

	// EVALUATE
	logger.Info("Directory analysis completed",
		zap.Int("directoriesFound", len(dirs)))

	return dirs, nil
}

// FindLargeFiles finds the largest files in a path
func FindLargeFiles(rc *eos_io.RuntimeContext, path string, minSize int64, topN int) ([]FileInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing large files",
		zap.String("path", path),
		zap.Int64("minSize", minSize),
		zap.Int("topN", topN))

	// INTERVENE
	logger.Info("Searching for large files")

	// Use find command for efficiency
	findCmd := exec.CommandContext(rc.Ctx, "find", path, "-type", "f", "-size",
		fmt.Sprintf("+%dc", minSize), "-printf", "%s %p\n")

	output, err := findCmd.Output()
	if err != nil {
		// Fallback to manual search
		return findLargeFilesManual(rc, path, minSize, topN)
	}

	files := make([]FileInfo, 0)
	lines := strings.Split(string(output), "\n")

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
		fmt.Sscanf(parts[0], "%d", &size)
		filePath := parts[1]

		fileInfo := FileInfo{
			Path: filePath,
			Size: size,
		}

		// Get additional info
		if info, err := os.Stat(filePath); err == nil {
			fileInfo.ModifiedTime = info.ModTime()

			// Get access time
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

	// Take top N
	if len(files) > topN {
		files = files[:topN]
	}

	// EVALUATE
	logger.Info("Large file search completed",
		zap.Int("filesFound", len(files)))

	return files, nil
}

// Helper functions

func getDiskUsageForPath(rc *eos_io.RuntimeContext, path string) (*DiskUsage, error) {
	var stat syscall.Statfs_t

	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, err
	}

	usage := &DiskUsage{
		Path:          path,
		TotalSize:     int64(stat.Blocks) * int64(stat.Bsize),
		AvailableSize: int64(stat.Bavail) * int64(stat.Bsize),
		InodesTotal:   stat.Files,
		InodesFree:    stat.Ffree,
	}

	usage.UsedSize = usage.TotalSize - usage.AvailableSize
	if usage.TotalSize > 0 {
		usage.UsedPercent = float64(usage.UsedSize) * 100.0 / float64(usage.TotalSize)
	}

	usage.InodesUsed = usage.InodesTotal - usage.InodesFree
	if usage.InodesTotal > 0 {
		usage.InodesUsedPercent = float64(usage.InodesUsed) * 100.0 / float64(usage.InodesTotal)
	}

	// Get device and filesystem info
	if device, fs, options := getMountInfo(rc, path); device != "" {
		usage.Device = device
		usage.Filesystem = fs
		usage.MountOptions = options
	}

	return usage, nil
}

func getAllMountPoints(rc *eos_io.RuntimeContext) ([]string, error) {
	mountCmd := exec.CommandContext(rc.Ctx, "findmnt", "-rno", "TARGET")
	output, err := mountCmd.Output()
	if err != nil {
		return nil, err
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

func getMountInfo(rc *eos_io.RuntimeContext, path string) (device, filesystem string, options []string) {
	findmntCmd := exec.CommandContext(rc.Ctx, "findmnt", "-rno", "SOURCE,FSTYPE,OPTIONS", "-T", path)
	if output, err := findmntCmd.Output(); err == nil {
		parts := strings.Fields(string(output))
		if len(parts) >= 3 {
			device = parts[0]
			filesystem = parts[1]
			options = strings.Split(parts[2], ",")
		}
	}
	return
}

func isExcludedPath(path string, excludePaths []string) bool {
	for _, exclude := range excludePaths {
		if strings.HasPrefix(path, exclude) {
			return true
		}
	}
	return false
}

func isExcludedFilesystem(fs string, excludeFS []string) bool {
	for _, exclude := range excludeFS {
		if fs == exclude {
			return true
		}
	}
	// Also exclude pseudo filesystems by default
	pseudoFS := []string{"proc", "sysfs", "devfs", "devpts", "tmpfs", "securityfs", "cgroup"}
	for _, pseudo := range pseudoFS {
		if fs == pseudo {
			return true
		}
	}
	return false
}

func generateAlertID(path string, alertType AlertType) string {
	return fmt.Sprintf("%s:%s:%d", alertType, path, time.Now().Unix())
}

func findLargeFilesManual(rc *eos_io.RuntimeContext, path string, minSize int64, topN int) ([]FileInfo, error) {
	files := make([]FileInfo, 0)

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
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

	// Take top N
	if len(files) > topN {
		files = files[:topN]
	}

	return files, nil
}

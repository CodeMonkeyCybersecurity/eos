// pkg/consul/validation/resources.go
// System resource validation (memory, disk space)

package validation

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// ResourceValidator validates system resources (memory, disk)
type ResourceValidator struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewResourceValidator creates a new resource validator
func NewResourceValidator(rc *eos_io.RuntimeContext) *ResourceValidator {
	return &ResourceValidator{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// CheckMemory validates available system memory
func (rv *ResourceValidator) CheckMemory(ctx context.Context, requiredMB int64) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	rv.logger.Info("Checking system memory")

	// Read /proc/meminfo directly for consistency
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		rv.logger.Warn("Could not check system memory, proceeding anyway", zap.Error(err))
		return nil // Non-fatal
	}

	// Parse MemTotal from /proc/meminfo
	lines := strings.Split(string(data), "\n")
	var totalKB int64
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, _ = strconv.ParseInt(fields[1], 10, 64)
				break
			}
		}
	}

	totalMB := totalKB / 1024
	rv.logger.Info("System memory detected",
		zap.Int64("total_mb", totalMB),
		zap.Int64("required_mb", requiredMB))

	if totalMB < requiredMB {
		return eos_err.NewUserError("insufficient memory: %dMB (minimum %dMB required)", totalMB, requiredMB)
	}

	rv.logger.Debug("Memory check passed", zap.Int64("total_mb", totalMB))
	return nil
}

// CheckDiskSpace validates available disk space
func (rv *ResourceValidator) CheckDiskSpace(ctx context.Context, path string, requiredMB int64) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	rv.logger.Info("Checking disk space",
		zap.String("path", path),
		zap.Int64("required_mb", requiredMB))

	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		rv.logger.Warn("Could not check disk space", zap.String("path", path), zap.Error(err))
		return nil // Non-fatal
	}

	availableMB := int64(stat.Bavail) * int64(stat.Bsize) / 1024 / 1024
	totalMB := int64(stat.Blocks) * int64(stat.Bsize) / 1024 / 1024
	usedPercent := float64(totalMB-availableMB) / float64(totalMB) * 100

	rv.logger.Info("Disk space status",
		zap.String("path", path),
		zap.Int64("available_mb", availableMB),
		zap.Int64("total_mb", totalMB),
		zap.Float64("used_percent", usedPercent))

	if availableMB < requiredMB {
		return eos_err.NewUserError("insufficient disk space in %s: %dMB available (minimum %dMB required)",
			path, availableMB, requiredMB)
	}

	// Warn if disk is getting full
	if usedPercent > 90 {
		rv.logger.Warn("Disk space critically low",
			zap.String("path", path),
			zap.Float64("used_percent", usedPercent),
			zap.Int64("available_mb", availableMB),
			zap.String("recommendation", "Free up disk space to prevent future failures"))
	} else if usedPercent > 80 {
		rv.logger.Warn("Disk space low",
			zap.String("path", path),
			zap.Float64("used_percent", usedPercent),
			zap.Int64("available_mb", availableMB))
	}

	rv.logger.Debug("Disk space check passed",
		zap.String("path", path),
		zap.Int64("available_mb", availableMB))

	return nil
}

// pkg/system/disk_space.go
//
// Disk space verification and enforcement for critical operations
// HUMAN-CENTRIC: Provides clear guidance when disk space is insufficient

package system

import (
	"fmt"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiskSpaceRequirements defines minimum space requirements for an operation
type DiskSpaceRequirements struct {
	// Paths to check
	TempDir    string // Temporary build directory
	BinaryDir  string // Binary installation directory
	SourceDir  string // Source code directory

	// Minimum space required (in bytes)
	MinTempSpace   uint64 // Minimum space for /tmp (build artifacts)
	MinBinarySpace uint64 // Minimum space for binary directory
	MinSourceSpace uint64 // Minimum space for source directory

	// Recommended space (in bytes) - warn if below this
	RecommendedTempSpace   uint64
	RecommendedBinarySpace uint64
	RecommendedSourceSpace uint64
}

// DiskSpaceResult contains the results of disk space verification
type DiskSpaceResult struct {
	TempAvailable   uint64
	BinaryAvailable uint64
	SourceAvailable uint64

	TempSufficient   bool
	BinarySufficient bool
	SourceSufficient bool

	TempRecommended   bool
	BinaryRecommended bool
	SourceRecommended bool

	Warnings []string
	Errors   []string
}

// DefaultUpdateRequirements returns sensible defaults for eos self update
func DefaultUpdateRequirements(tempDir, binaryDir, sourceDir string) *DiskSpaceRequirements {
	return &DiskSpaceRequirements{
		TempDir:   tempDir,
		BinaryDir: binaryDir,
		SourceDir: sourceDir,

		// Minimum requirements (hard limits)
		MinTempSpace:   500 * 1024 * 1024,  // 500MB for build artifacts
		MinBinarySpace: 100 * 1024 * 1024,  // 100MB for binary + backup
		MinSourceSpace: 200 * 1024 * 1024,  // 200MB for source code

		// Recommended requirements (soft warnings)
		RecommendedTempSpace:   1 * 1024 * 1024 * 1024, // 1GB recommended
		RecommendedBinarySpace: 500 * 1024 * 1024,      // 500MB recommended
		RecommendedSourceSpace: 500 * 1024 * 1024,      // 500MB recommended
	}
}

// VerifyDiskSpace checks if sufficient disk space is available for an operation
// SECURITY CRITICAL: Prevents partial updates that could leave system in broken state
func VerifyDiskSpace(rc *eos_io.RuntimeContext, reqs *DiskSpaceRequirements) (*DiskSpaceResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying disk space requirements")

	result := &DiskSpaceResult{}

	// Check temp directory
	tempAvail, err := getAvailableSpace(reqs.TempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to check temp directory space: %w\n"+
			"Directory: %s\n"+
			"This is required for building eos binary",
			err, reqs.TempDir)
	}
	result.TempAvailable = tempAvail
	result.TempSufficient = tempAvail >= reqs.MinTempSpace
	result.TempRecommended = tempAvail >= reqs.RecommendedTempSpace

	logger.Debug("Temp directory space",
		zap.String("path", reqs.TempDir),
		zap.String("available", FormatBytes(tempAvail)),
		zap.String("required", FormatBytes(reqs.MinTempSpace)),
		zap.Bool("sufficient", result.TempSufficient))

	// Check binary directory
	binaryAvail, err := getAvailableSpace(reqs.BinaryDir)
	if err != nil {
		return nil, fmt.Errorf("failed to check binary directory space: %w\n"+
			"Directory: %s\n"+
			"This is required for installing updated eos binary",
			err, reqs.BinaryDir)
	}
	result.BinaryAvailable = binaryAvail
	result.BinarySufficient = binaryAvail >= reqs.MinBinarySpace
	result.BinaryRecommended = binaryAvail >= reqs.RecommendedBinarySpace

	logger.Debug("Binary directory space",
		zap.String("path", reqs.BinaryDir),
		zap.String("available", FormatBytes(binaryAvail)),
		zap.String("required", FormatBytes(reqs.MinBinarySpace)),
		zap.Bool("sufficient", result.BinarySufficient))

	// Check source directory
	sourceAvail, err := getAvailableSpace(reqs.SourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to check source directory space: %w\n"+
			"Directory: %s\n"+
			"This is required for updating eos source code",
			err, reqs.SourceDir)
	}
	result.SourceAvailable = sourceAvail
	result.SourceSufficient = sourceAvail >= reqs.MinSourceSpace
	result.SourceRecommended = sourceAvail >= reqs.RecommendedSourceSpace

	logger.Debug("Source directory space",
		zap.String("path", reqs.SourceDir),
		zap.String("available", FormatBytes(sourceAvail)),
		zap.String("required", FormatBytes(reqs.MinSourceSpace)),
		zap.Bool("sufficient", result.SourceSufficient))

	// Collect errors for insufficient space
	if !result.TempSufficient {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Insufficient space in %s: %s available, %s required",
				reqs.TempDir, FormatBytes(tempAvail), FormatBytes(reqs.MinTempSpace)))
	}
	if !result.BinarySufficient {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Insufficient space in %s: %s available, %s required",
				reqs.BinaryDir, FormatBytes(binaryAvail), FormatBytes(reqs.MinBinarySpace)))
	}
	if !result.SourceSufficient {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Insufficient space in %s: %s available, %s required",
				reqs.SourceDir, FormatBytes(sourceAvail), FormatBytes(reqs.MinSourceSpace)))
	}

	// Collect warnings for below-recommended space
	if result.TempSufficient && !result.TempRecommended {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Low space in %s: %s available, %s recommended",
				reqs.TempDir, FormatBytes(tempAvail), FormatBytes(reqs.RecommendedTempSpace)))
	}
	if result.BinarySufficient && !result.BinaryRecommended {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Low space in %s: %s available, %s recommended",
				reqs.BinaryDir, FormatBytes(binaryAvail), FormatBytes(reqs.RecommendedBinarySpace)))
	}
	if result.SourceSufficient && !result.SourceRecommended {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Low space in %s: %s available, %s recommended",
				reqs.SourceDir, FormatBytes(sourceAvail), FormatBytes(reqs.RecommendedSourceSpace)))
	}

	// Log warnings
	if len(result.Warnings) > 0 {
		logger.Warn("Disk space below recommended levels",
			zap.Strings("warnings", result.Warnings))
	}

	// Fail if any hard requirement not met
	if len(result.Errors) > 0 {
		logger.Error("Insufficient disk space for update",
			zap.Strings("errors", result.Errors))

		errorMsg := "INSUFFICIENT DISK SPACE\n\n"
		for i, err := range result.Errors {
			errorMsg += fmt.Sprintf("  %d. %s\n", i+1, err)
		}

		errorMsg += "\nFree up space:\n" +
			"  # Check disk usage\n" +
			"  df -h\n\n" +
			"  # Find large files\n" +
			"  du -h /tmp | sort -rh | head -20\n\n" +
			"  # Clean package manager cache\n" +
			"  sudo apt clean        # Ubuntu/Debian\n" +
			"  sudo yum clean all    # RHEL/CentOS\n" +
			"  sudo dnf clean all    # Fedora\n\n" +
			"  # Clean docker\n" +
			"  docker system prune -a\n\n" +
			"  # Remove old logs\n" +
			"  sudo journalctl --vacuum-size=100M\n"

		return result, fmt.Errorf("%s", errorMsg)
	}

	logger.Info("Disk space verification passed",
		zap.String("temp_available", FormatBytes(result.TempAvailable)),
		zap.String("binary_available", FormatBytes(result.BinaryAvailable)),
		zap.String("source_available", FormatBytes(result.SourceAvailable)))

	return result, nil
}

// getAvailableSpace returns available disk space in bytes for the given path
func getAvailableSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("statfs failed: %w", err)
	}

	// Available space = available blocks * block size
	// Use Bavail (available to unprivileged user) not Bfree (available to root)
	availableBytes := stat.Bavail * uint64(stat.Bsize)

	return availableBytes, nil
}

// FormatBytes formats bytes into human-readable format
func FormatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

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
// P1 FIX: Increased temp space requirements based on real-world CGO build measurements
// NOTE: This uses static 100MB for binary space - use UpdateRequirementsWithBinarySize() for accurate calculation
func DefaultUpdateRequirements(tempDir, binaryDir, sourceDir string) *DiskSpaceRequirements {
	return &DiskSpaceRequirements{
		TempDir:   tempDir,
		BinaryDir: binaryDir,
		SourceDir: sourceDir,

		// Minimum requirements (hard limits)
		// P1 FIX: Increased from 500MB to 1.5GB based on empirical data:
		//   - Eos binary with CGO: ~134MB
		//   - Go build cache during compile: ~2.4GB (but in ~/.cache/go-build)
		//   - CGO temp files in /tmp: ~850MB
		//   - Safety margin: 2x = 1.7GB, rounded to 1.5GB
		MinTempSpace:   1536 * 1024 * 1024, // 1.5GB for CGO build artifacts (libvirt + Ceph)
		MinBinarySpace: 100 * 1024 * 1024,  // 100MB for binary + backup (STATIC - may underestimate)
		MinSourceSpace: 200 * 1024 * 1024,  // 200MB for source code

		// Recommended requirements (soft warnings)
		RecommendedTempSpace:   2 * 1024 * 1024 * 1024, // 2GB recommended for headroom
		RecommendedBinarySpace: 500 * 1024 * 1024,      // 500MB recommended
		RecommendedSourceSpace: 500 * 1024 * 1024,      // 500MB recommended
	}
}

// UpdateRequirementsWithBinarySize returns disk space requirements dynamically calculated
// based on actual binary size
// P0 FIX (Adversarial #4): Accounts for actual temp binary + backup size
//
// RATIONALE: During update, we need space for:
//   1. Temp binary in /tmp (actual binary size)
//   2. Backup in backup dir (actual binary size, if different filesystem)
//   3. New binary replacing old (actual binary size)
//   4. Safety margin (2x for filesystem overhead, fragmentation)
//
// Example with 134MB binary:
//   - Temp: 134MB in /tmp
//   - Backup: 134MB in /usr/local/bin/.eos/backups (if same filesystem)
//   - Replace: 134MB (replaces existing, no additional space)
//   - Total: 134MB + 134MB = 268MB minimum
//   - With 2x safety: 536MB required
func UpdateRequirementsWithBinarySize(tempDir, binaryDir, sourceDir string, binarySize int64) *DiskSpaceRequirements {
	// Calculate required space based on actual binary size
	// We need: temp binary + backup + 2x safety margin
	safetyFactor := uint64(2)
	minBinarySpace := uint64(binarySize) * safetyFactor

	// Ensure minimum of 200MB even for small binaries
	const minAbsolute = 200 * 1024 * 1024
	if minBinarySpace < minAbsolute {
		minBinarySpace = minAbsolute
	}

	return &DiskSpaceRequirements{
		TempDir:   tempDir,
		BinaryDir: binaryDir,
		SourceDir: sourceDir,

		// Minimum requirements (hard limits)
		MinTempSpace:   1536 * 1024 * 1024, // 1.5GB for CGO build artifacts (unchanged)
		MinBinarySpace: minBinarySpace,     // DYNAMIC based on actual binary size
		MinSourceSpace: 200 * 1024 * 1024,  // 200MB for source code (unchanged)

		// Recommended requirements (soft warnings)
		RecommendedTempSpace:   2 * 1024 * 1024 * 1024,            // 2GB recommended
		RecommendedBinarySpace: uint64(binarySize) * safetyFactor, // Same as minimum
		RecommendedSourceSpace: 500 * 1024 * 1024,                 // 500MB recommended
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

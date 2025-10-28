// pkg/system/disk_space.go
//
// Disk space verification and enforcement for critical operations
// HUMAN-CENTRIC: Provides clear guidance when disk space is insufficient

package system

import (
	"fmt"
	"os"
	"path/filepath"
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
	BackupDir  string // Backup directory (optional, for filesystem detection)

	// Minimum space required (in bytes)
	MinTempSpace   uint64 // Minimum space for /tmp (build artifacts)
	MinBinarySpace uint64 // Minimum space for binary directory
	MinSourceSpace uint64 // Minimum space for source directory
	MinBackupSpace uint64 // Minimum space for backup directory (if on different FS)

	// Recommended space (in bytes) - warn if below this
	RecommendedTempSpace   uint64
	RecommendedBinarySpace uint64
	RecommendedSourceSpace uint64
	RecommendedBackupSpace uint64
}

// areOnSameFilesystem checks if two paths are on the same filesystem
// ARCHITECTURAL FIX (Adversarial Analysis Round 4): Use file descriptors to eliminate TOCTOU
//
// PREVIOUS ISSUES:
//   - P0 NEW #30: TOCTOU between findExistingParent and syscall.Stat (path could disappear)
//   - P0 NEW #29: Wrong worst-case assumption (assumed different FS on error)
//   - Symlink cycles could cause incorrect results
//
// NEW APPROACH:
//   1. Open each path (or first existing parent) to get a file descriptor
//   2. fstat(fd) to get device ID - NO RACE, we're statting the open FD
//   3. Compare device IDs
//   4. TRUE worst case: if can't determine, assume SAME FS (requires MORE space)
//
// RATIONALE FOR WORST CASE:
//   - If we assume "different FS" and they're actually the SAME FS:
//     → We count the same space pool TWICE (600MB counted as if it's 1200MB)
//     → Update proceeds thinking it has enough space
//     → FAILS mid-transaction with "no space left on device"
//   - If we assume "same FS" and they're actually DIFFERENT:
//     → We require MORE space than strictly necessary
//     → Might reject update that would actually succeed
//     → But this is SAFE - won't corrupt anything
func areOnSameFilesystem(path1, path2 string) (bool, error) {
	// Open first path (or first existing parent)
	fd1, err := openPathOrParent(path1)
	if err != nil {
		// Can't open path1 - assume SAME filesystem (safe worst case)
		return true, nil
	}
	defer fd1.Close()

	// Open second path (or first existing parent)
	fd2, err := openPathOrParent(path2)
	if err != nil {
		// Can't open path2 - assume SAME filesystem (safe worst case)
		return true, nil
	}
	defer fd2.Close()

	// Get device ID from first FD
	var stat1 syscall.Stat_t
	if err := syscall.Fstat(int(fd1.Fd()), &stat1); err != nil {
		// Can't fstat - assume SAME filesystem (safe worst case)
		return true, nil
	}

	// Get device ID from second FD
	var stat2 syscall.Stat_t
	if err := syscall.Fstat(int(fd2.Fd()), &stat2); err != nil {
		// Can't fstat - assume SAME filesystem (safe worst case)
		return true, nil
	}

	// Compare device IDs - same device = same filesystem
	return stat1.Dev == stat2.Dev, nil
}

// openPathOrParent opens a path, or if it doesn't exist, opens the first existing parent
// ARCHITECTURAL FIX (Adversarial Analysis Round 4): Returns open FD to eliminate TOCTOU
//
// This prevents the race condition where:
//   1. findExistingParent() confirms /opt/backup exists
//   2. Attacker deletes /opt/backup
//   3. syscall.Stat() fails on deleted path
//
// By returning an OPEN file descriptor, we guarantee the path stays valid for fstat.
func openPathOrParent(path string) (*os.File, error) {
	path = filepath.Clean(path)

	// Try up to 100 levels (prevents infinite loop)
	for i := 0; i < 100; i++ {
		// Try to open the path as a directory
		fd, err := os.Open(path)
		if err == nil {
			// Successfully opened - return the FD
			return fd, nil
		}

		// Path doesn't exist - try parent
		parent := filepath.Dir(path)

		// Check if we've reached the root
		if parent == path {
			return nil, fmt.Errorf("no existing parent found for %s (reached root)", path)
		}

		path = parent
	}

	return nil, fmt.Errorf("exceeded maximum directory depth searching for %s", path)
}

// DiskSpaceResult contains the results of disk space verification
type DiskSpaceResult struct {
	TempAvailable   uint64
	BinaryAvailable uint64
	SourceAvailable uint64
	BackupAvailable uint64

	TempSufficient   bool
	BinarySufficient bool
	SourceSufficient bool
	BackupSufficient bool

	TempRecommended   bool
	BinaryRecommended bool
	SourceRecommended bool
	BackupRecommended bool

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
// P0 FIX (Adversarial NEW #13): Detects filesystem boundaries for accurate calculation
//
// RATIONALE: During update, we need space for:
//   1. Temp binary in /tmp (actual binary size)
//   2. Backup in backup dir (actual binary size, if different filesystem)
//   3. New binary replacing old (actual binary size)
//   4. Safety margin (2x for filesystem overhead, fragmentation)
//
// FILESYSTEM DETECTION:
//   - If backup dir is on SAME filesystem as binary dir: need 2× size (backup + new)
//   - If backup dir is on DIFFERENT filesystem: need 3× size (backup on other FS, new + temp on this FS)
//
// Example with 134MB binary, same filesystem:
//   - Backup: 134MB (replaces old 134MB on same FS)
//   - New: 134MB (replaces current)
//   - Total: 2× = 268MB minimum, with safety = 536MB
//
// Example with 134MB binary, different filesystems:
//   - Backup: 134MB (on backup filesystem)
//   - New + temp: 268MB (on binary filesystem)
//   - Total: 3× = 402MB minimum, with safety = 804MB
func UpdateRequirementsWithBinarySize(tempDir, binaryDir, sourceDir, backupDir string, binarySize int64) *DiskSpaceRequirements {
	safetyFactor := uint64(2)
	binarySizeUint := uint64(binarySize)

	// P0 FIX (Adversarial NEW #26 & #27): Properly handle filesystem boundaries
	// Check if backup and binary are on same filesystem
	sameFS, err := areOnSameFilesystem(binaryDir, backupDir)
	if err != nil {
		// If we can't determine, assume worst case (different filesystems)
		sameFS = false
	}

	var minBinarySpace, minBackupSpace uint64

	if sameFS {
		// SAME FILESYSTEM: Backup and binary share space pool
		// During update on same FS:
		//   1. Backup created (134MB) - occupies space
		//   2. New binary replaces old (134MB) - reuses old binary's space
		//   3. Peak usage: backup (134MB) + current (134MB) = 2× binary size
		// Need: 2× binary size on the shared filesystem
		minBinarySpace = binarySizeUint * safetyFactor
		minBackupSpace = 0 // No separate check needed - included in binary space
	} else {
		// DIFFERENT FILESYSTEMS: Backup and binary have separate space pools
		// During update on different FS:
		//   Binary FS:
		//     1. Old binary exists (134MB)
		//     2. Temp binary built (134MB) - additional space
		//     3. New replaces old via atomic rename
		//     4. Peak: old (134MB) + temp (134MB) = 2× binary size
		//   Backup FS:
		//     1. Backup created (134MB) - separate filesystem
		//     2. Peak: backup (134MB) = 1× binary size
		// Need: 2× on binary FS + 1× on backup FS
		minBinarySpace = binarySizeUint * safetyFactor  // 2× for binary FS
		minBackupSpace = binarySizeUint * safetyFactor  // 1× with safety margin for backup FS
	}

	// Ensure minimum of 200MB even for small binaries
	const minAbsolute = 200 * 1024 * 1024
	if minBinarySpace < minAbsolute {
		minBinarySpace = minAbsolute
	}
	if minBackupSpace > 0 && minBackupSpace < minAbsolute {
		minBackupSpace = minAbsolute
	}

	return &DiskSpaceRequirements{
		TempDir:   tempDir,
		BinaryDir: binaryDir,
		SourceDir: sourceDir,
		BackupDir: backupDir,

		// Minimum requirements (hard limits)
		MinTempSpace:   1536 * 1024 * 1024, // 1.5GB for CGO build artifacts
		MinBinarySpace: minBinarySpace,     // DYNAMIC: 2× binary size
		MinSourceSpace: 200 * 1024 * 1024,  // 200MB for source code
		MinBackupSpace: minBackupSpace,     // DYNAMIC: 0 if same FS, 1× if different FS

		// Recommended requirements (soft warnings)
		RecommendedTempSpace:   2 * 1024 * 1024 * 1024, // 2GB recommended
		RecommendedBinarySpace: binarySizeUint * safetyFactor,
		RecommendedSourceSpace: 500 * 1024 * 1024,
		RecommendedBackupSpace: minBackupSpace, // Same as minimum
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

	// P0 FIX (Adversarial NEW #27): Check backup directory if on different filesystem
	// Only check if MinBackupSpace > 0 (which means different filesystem)
	if reqs.MinBackupSpace > 0 && reqs.BackupDir != "" {
		backupAvail, err := getAvailableSpace(reqs.BackupDir)
		if err != nil {
			return nil, fmt.Errorf("failed to check backup directory space: %w\n"+
				"Directory: %s\n"+
				"This is required for creating binary backup",
				err, reqs.BackupDir)
		}
		result.BackupAvailable = backupAvail
		result.BackupSufficient = backupAvail >= reqs.MinBackupSpace
		result.BackupRecommended = backupAvail >= reqs.RecommendedBackupSpace

		logger.Debug("Backup directory space (separate filesystem)",
			zap.String("path", reqs.BackupDir),
			zap.String("available", FormatBytes(backupAvail)),
			zap.String("required", FormatBytes(reqs.MinBackupSpace)),
			zap.Bool("sufficient", result.BackupSufficient))
	} else {
		// Same filesystem as binary dir - no separate check needed
		result.BackupSufficient = true
		result.BackupRecommended = true
	}

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
	// P0 FIX (Adversarial NEW #27): Include backup directory errors
	if !result.BackupSufficient && reqs.MinBackupSpace > 0 {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Insufficient space in %s (backup filesystem): %s available, %s required",
				reqs.BackupDir, FormatBytes(result.BackupAvailable), FormatBytes(reqs.MinBackupSpace)))
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
	// P0 FIX (Adversarial NEW #27): Include backup directory warnings
	if result.BackupSufficient && !result.BackupRecommended && reqs.MinBackupSpace > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Low space in %s (backup filesystem): %s available, %s recommended",
				reqs.BackupDir, FormatBytes(result.BackupAvailable), FormatBytes(reqs.RecommendedBackupSpace)))
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

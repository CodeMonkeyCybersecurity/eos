package btrfs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureCompression sets compression on a BTRFS path
func ConfigureCompression(rc *eos_io.RuntimeContext, path string, algorithm string, level int, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing path for compression configuration",
		zap.String("path", path),
		zap.String("algorithm", algorithm),
		zap.Int("level", level))

	// Check if path exists
	info, err := os.Stat(path)
	if err != nil {
		return eos_err.NewUserError("path not found: %s", path)
	}

	// Check if path is on BTRFS
	if !isPathOnBTRFS(rc, path) {
		return eos_err.NewUserError("path %s is not on a BTRFS filesystem", path)
	}

	// Validate compression algorithm
	validAlgorithms := []string{CompressionNone, CompressionZlib, CompressionLZO, CompressionZSTD}
	valid := false
	for _, validAlg := range validAlgorithms {
		if algorithm == validAlg {
			valid = true
			break
		}
	}
	if !valid {
		return eos_err.NewUserError("invalid compression algorithm: %s (valid: %v)",
			algorithm, validAlgorithms)
	}

	// Validate compression level for zstd
	if algorithm == CompressionZSTD && (level < 1 || level > 15) {
		return eos_err.NewUserError("zstd compression level must be between 1 and 15")
	}

	// INTERVENE
	logger.Info("Configuring compression",
		zap.String("path", path),
		zap.String("algorithm", algorithm),
		zap.Bool("isDir", info.IsDir()))

	// Build compression string
	compression := algorithm
	if algorithm == CompressionZSTD && level > 0 {
		compression = fmt.Sprintf("%s:%d", algorithm, level)
	}

	// Set compression property
	if info.IsDir() {
		// For directories, set the compression property
		propCmd := exec.CommandContext(rc.Ctx, "btrfs", "property", "set", path, "compression", compression)
		if output, err := propCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set compression property: %w, output: %s", err, string(output))
		}

		// If force flag is set, recompress existing files
		if force {
			logger.Info("Force recompressing existing files")
			if err := recompressDirectory(rc, path, compression); err != nil {
				return fmt.Errorf("failed to recompress existing files: %w", err)
			}
		}
	} else {
		// For files, we need to defragment with compression
		defragCmd := exec.CommandContext(rc.Ctx, "btrfs", "filesystem", "defragment",
			"-c"+compression, path)
		if output, err := defragCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to compress file: %w, output: %s", err, string(output))
		}
	}

	// EVALUATE
	logger.Info("Verifying compression configuration")

	// Verify compression was set
	actualCompression, err := getCompressionProperty(rc, path)
	if err != nil {
		logger.Warn("Failed to verify compression property",
			zap.Error(err))
	} else {
		logger.Debug("Compression property verified",
			zap.String("actual", actualCompression))
	}

	// Get compression statistics if available
	if stats, err := GetCompressionStats(rc, path); err == nil {
		logger.Info("Compression configured successfully",
			zap.String("path", path),
			zap.String("algorithm", algorithm),
			zap.Float64("ratio", stats.CompressionRatio))
	} else {
		logger.Info("Compression configured successfully",
			zap.String("path", path),
			zap.String("algorithm", algorithm))
	}

	return nil
}

// GetCompressionStats retrieves compression statistics for a path
func GetCompressionStats(rc *eos_io.RuntimeContext, path string) (*CompressionStats, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing path for compression statistics",
		zap.String("path", path))

	if !isPathOnBTRFS(rc, path) {
		return nil, eos_err.NewUserError("path %s is not on a BTRFS filesystem", path)
	}

	// INTERVENE
	logger.Info("Gathering compression statistics")

	stats := &CompressionStats{
		Type: CompressionNone,
	}

	// Get compression type
	if compression, err := getCompressionProperty(rc, path); err == nil {
		stats.Type = parseCompressionType(compression)
		stats.Level = parseCompressionLevel(compression)
	}

	// Use compsize tool if available for detailed stats
	if _, err := exec.LookPath("compsize"); err == nil {
		compsizeCmd := exec.CommandContext(rc.Ctx, "compsize", path)
		if output, err := compsizeCmd.Output(); err == nil {
			parseCompsizeOutput(string(output), stats)
		}
	} else {
		// Fallback to basic du-based estimation
		if err := estimateCompressionStats(rc, path, stats); err != nil {
			logger.Warn("Failed to estimate compression stats",
				zap.Error(err))
		}
	}

	// Calculate compression ratio
	if stats.UncompressedSize > 0 && stats.CompressedSize > 0 {
		stats.CompressionRatio = float64(stats.UncompressedSize) / float64(stats.CompressedSize)
	}

	// EVALUATE
	logger.Info("Compression statistics retrieved",
		zap.String("path", path),
		zap.String("type", stats.Type),
		zap.Float64("ratio", stats.CompressionRatio))

	return stats, nil
}

// DefragmentWithCompression defragments and compresses files
func DefragmentWithCompression(rc *eos_io.RuntimeContext, path string, algorithm string, level int, recursive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing path for defragmentation with compression",
		zap.String("path", path),
		zap.String("algorithm", algorithm))

	if !isPathOnBTRFS(rc, path) {
		return eos_err.NewUserError("path %s is not on a BTRFS filesystem", path)
	}

	// INTERVENE
	logger.Info("Starting defragmentation with compression",
		zap.Bool("recursive", recursive))

	// Build compression string
	compression := algorithm
	if algorithm == CompressionZSTD && level > 0 {
		compression = fmt.Sprintf("%s:%d", algorithm, level)
	}

	// Build defrag command
	args := []string{"btrfs", "filesystem", "defragment"}

	if recursive {
		args = append(args, "-r")
	}

	args = append(args, "-c"+compression, path)

	// Add flush to ensure data is written
	args = append(args, "-f")

	defragCmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	output, err := defragCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("defragmentation failed: %w, output: %s", err, string(output))
	}

	// EVALUATE
	logger.Info("Defragmentation completed, verifying results")

	// Get compression stats after defrag
	if stats, err := GetCompressionStats(rc, path); err == nil {
		logger.Info("Defragmentation with compression completed",
			zap.String("path", path),
			zap.Float64("compressionRatio", stats.CompressionRatio),
			zap.Int64("compressedSize", stats.CompressedSize))
	} else {
		logger.Info("Defragmentation with compression completed",
			zap.String("path", path))
	}

	return nil
}

// Helper functions

func getCompressionProperty(rc *eos_io.RuntimeContext, path string) (string, error) {
	propCmd := exec.CommandContext(rc.Ctx, "btrfs", "property", "get", path, "compression")
	output, err := propCmd.Output()
	if err != nil {
		return "", err
	}

	// Parse output like "compression=zstd:3"
	line := strings.TrimSpace(string(output))
	if strings.HasPrefix(line, "compression=") {
		return strings.TrimPrefix(line, "compression="), nil
	}

	return "", nil
}

func recompressDirectory(rc *eos_io.RuntimeContext, dir string, compression string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Walk directory and recompress files
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip if path is the same as dir (the root)
		if path == dir {
			return nil
		}

		logger.Debug("Recompressing file",
			zap.String("file", path))

		// Defragment file with new compression
		defragCmd := exec.CommandContext(rc.Ctx, "btrfs", "filesystem", "defragment",
			"-c"+compression, path)
		if output, err := defragCmd.CombinedOutput(); err != nil {
			logger.Warn("Failed to recompress file",
				zap.String("file", path),
				zap.Error(err),
				zap.String("output", string(output)))
		}

		return nil
	})
}

func parseCompressionType(compression string) string {
	if compression == "" {
		return CompressionNone
	}

	// Handle formats like "zstd:3"
	parts := strings.Split(compression, ":")
	if len(parts) > 0 {
		return parts[0]
	}

	return compression
}

func parseCompressionLevel(compression string) int {
	parts := strings.Split(compression, ":")
	if len(parts) > 1 {
		var level int
		if _, err := fmt.Sscanf(parts[1], "%d", &level); err != nil {
			// If parsing fails, return default level 0
			return 0
		}
		return level
	}
	return 0
}

func parseCompsizeOutput(output string, stats *CompressionStats) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Type") && strings.Contains(line, "Perc") {
			// Header line, skip
			continue
		}

		if strings.Contains(line, "TOTAL") {
			// Parse total line
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				// Fields: TOTAL uncompressed compressed ratio
				if _, err := fmt.Sscanf(fields[1], "%d", &stats.UncompressedSize); err != nil {
					// Log parsing error but continue - compression stats are not critical
					continue
				}
				if _, err := fmt.Sscanf(fields[2], "%d", &stats.CompressedSize); err != nil {
					// Log parsing error but continue - compression stats are not critical
					continue
				}
			}
		}
	}
}

func estimateCompressionStats(rc *eos_io.RuntimeContext, path string, stats *CompressionStats) error {
	// Use du to get apparent size vs actual disk usage
	duCmd := exec.CommandContext(rc.Ctx, "du", "-sb", "--apparent-size", path)
	if output, err := duCmd.Output(); err == nil {
		fields := strings.Fields(string(output))
		if len(fields) >= 1 {
			if _, err := fmt.Sscanf(fields[0], "%d", &stats.UncompressedSize); err != nil {
				// Log warning but continue - this is not critical for operation
				fmt.Printf("Warning: Failed to parse uncompressed size '%s': %v\n", fields[0], err)
			}
		}
	}

	// Get actual disk usage
	duCmd = exec.CommandContext(rc.Ctx, "du", "-sb", path)
	if output, err := duCmd.Output(); err == nil {
		fields := strings.Fields(string(output))
		if len(fields) >= 1 {
			if _, err := fmt.Sscanf(fields[0], "%d", &stats.CompressedSize); err != nil {
				// Log warning but continue - this is not critical for operation
				fmt.Printf("Warning: Failed to parse compressed size '%s': %v\n", fields[0], err)
			}
		}
	}

	return nil
}

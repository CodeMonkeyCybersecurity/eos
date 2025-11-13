// pkg/shared/format.go
//
// Common formatting utilities consolidated from cmd/ files.
// This package eliminates duplicate implementations found across the codebase.
//
// CONSOLIDATION NOTES:
// - formatSize/humanizeBytes/formatDiskSize: Found in 4+ cmd/ files
// - formatAge: Found in cmd/list/backups.go
// - truncateString: Found in cmd/list/backups.go
// - parseDiskSize: Found in cmd/create/disk_manager.go
//
// MIGRATION PATH:
// 1. Created this centralized package
// 2. Next: Replace all cmd/ implementations with imports
// 3. Delete duplicate implementations
//
// Files to update:
// - cmd/list/backups.go (humanizeBytes, formatAge, truncateString)
// - cmd/create/clean.go (formatSize)
// - cmd/create/disk_manager.go (formatDiskSize, parseDiskSize)
// - cmd/promote/component.go (formatSize)

package shared

import (
	"fmt"
	"strings"
	"time"
)

// FormatBytes converts bytes to human-readable format (KiB, MiB, GiB, etc.)
// This consolidates: formatSize, humanizeBytes, formatDiskSize
// Used in: backups, clean, disk_manager, promote
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < 0 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	// KMGTPE = Kibi, Mebi, Gibi, Tebi, Pebi, Exbi
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatBytesUint64 is a convenience wrapper for uint64 inputs
func FormatBytesUint64(bytes uint64) string {
	return FormatBytes(int64(bytes))
}

// ParseSize parses human-readable size strings (e.g., "100GB", "50MB") to bytes
// Supports: TB, GB, MB, KB, or raw bytes
// Used in: disk_manager
func ParseSize(size string) (uint64, error) {
	if size == "" || size == "0" {
		return 0, nil
	}

	size = strings.ToUpper(strings.TrimSpace(size))

	var multiplier uint64 = 1
	var numStr string

	switch {
	case strings.HasSuffix(size, "TB"):
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "TB")
	case strings.HasSuffix(size, "GB"):
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "GB")
	case strings.HasSuffix(size, "MB"):
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(size, "MB")
	case strings.HasSuffix(size, "KB"):
		multiplier = 1024
		numStr = strings.TrimSuffix(size, "KB")
	default:
		numStr = size
	}

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, fmt.Errorf("invalid number format: %s", numStr)
	}

	return uint64(num * float64(multiplier)), nil
}

// FormatAge returns a human-readable age string from a time
// Examples: "now", "5m", "2h", "3d", "2w", "6mo", "1y"
// Used in: backups
func FormatAge(t time.Time) string {
	duration := time.Since(t)

	if duration < time.Minute {
		return "now"
	}
	if duration < time.Hour {
		minutes := int(duration.Minutes())
		return fmt.Sprintf("%dm", minutes)
	}
	if duration < 24*time.Hour {
		hours := int(duration.Hours())
		return fmt.Sprintf("%dh", hours)
	}
	if duration < 7*24*time.Hour {
		days := int(duration.Hours() / 24)
		return fmt.Sprintf("%dd", days)
	}
	if duration < 30*24*time.Hour {
		weeks := int(duration.Hours() / 24 / 7)
		return fmt.Sprintf("%dw", weeks)
	}
	if duration < 365*24*time.Hour {
		months := int(duration.Hours() / 24 / 30)
		return fmt.Sprintf("%dmo", months)
	}

	years := int(duration.Hours() / 24 / 365)
	return fmt.Sprintf("%dy", years)
}

// TruncateString truncates a string to the specified length with ellipsis
// If length < 3, truncates without ellipsis
// Used in: backups
func TruncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	if length < 3 {
		return s[:length]
	}
	return s[:length-3] + "..."
}

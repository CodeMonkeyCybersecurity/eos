// Package utils provides common utility functions used throughout the Eos codebase.
// These utilities follow the DRY principle and centralize commonly used operations.
package utils

import (
	"fmt"
	"time"
)

// FormatBytes converts a byte count into a human-readable string with appropriate units.
// It uses binary units (KiB, MiB, GiB, etc.) following the IEC standard.
//
// Example:
//   FormatBytes(1024) -> "1.0 KiB"
//   FormatBytes(1536) -> "1.5 KiB"
//   FormatBytes(1073741824) -> "1.0 GiB"
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatBytesDecimal converts a byte count into a human-readable string using decimal units.
// It uses decimal units (KB, MB, GB, etc.) where 1 KB = 1000 bytes.
//
// Example:
//   FormatBytesDecimal(1000) -> "1.0 KB"
//   FormatBytesDecimal(1500) -> "1.5 KB"
//   FormatBytesDecimal(1000000000) -> "1.0 GB"
func FormatBytesDecimal(bytes int64) string {
	const unit = 1000
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	value := float64(bytes)
	unitIndex := -1
	
	for value >= unit && unitIndex < len(units)-1 {
		value /= unit
		unitIndex++
	}
	
	return fmt.Sprintf("%.1f %s", value, units[unitIndex])
}

// FormatDuration formats a duration into a human-readable string.
// It provides more concise output than the standard Duration.String().
//
// Example:
//   FormatDuration(90*time.Second) -> "1m30s"
//   FormatDuration(2*time.Hour + 30*time.Minute) -> "2h30m"
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return d.String()
	}
	
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	
	if h > 0 {
		if m > 0 {
			return fmt.Sprintf("%dh%dm", h, m)
		}
		return fmt.Sprintf("%dh", h)
	}
	
	if m > 0 {
		if s > 0 {
			return fmt.Sprintf("%dm%ds", m, s)
		}
		return fmt.Sprintf("%dm", m)
	}
	
	return fmt.Sprintf("%ds", s)
}

// FormatPercentage formats a float as a percentage string.
//
// Example:
//   FormatPercentage(0.156) -> "15.6%"
//   FormatPercentage(1.0) -> "100.0%"
func FormatPercentage(value float64) string {
	return fmt.Sprintf("%.1f%%", value*100)
}

// FormatCount adds appropriate singular/plural suffix to a count.
//
// Example:
//   FormatCount(1, "file", "files") -> "1 file"
//   FormatCount(5, "file", "files") -> "5 files"
func FormatCount(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}
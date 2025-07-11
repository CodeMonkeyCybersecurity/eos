// Package utils provides common utility functions
package utils

import "fmt"

// FormatBytes converts bytes to human-readable format.
// It follows the Assess → Intervene → Evaluate pattern.
func FormatBytes(bytes int64) string {
	// ASSESS - Check if bytes is small enough to display as-is
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	// INTERVENE - Calculate appropriate unit
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	// EVALUATE - Format with appropriate unit
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
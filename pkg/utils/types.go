// pkg/utils/types.go
// DEPRECATED: This file exposes internal functions.
// Use the direct function calls instead.

package utils

// Note: GrepProcess is now exported directly in process.go
// This file is kept for backward compatibility

// utils.TruncateString truncates a string if it's longer than maxLen
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

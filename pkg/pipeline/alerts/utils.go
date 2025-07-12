package alerts

import (
	"time"
)

// FormatOptionalTime formats optional timestamp fields
// Migrated from cmd/read/pipeline_alerts.go formatOptionalTime
func FormatOptionalTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("15:04:05")
}

// GetStateColor returns ANSI color codes for different alert states
// Migrated from cmd/read/pipeline_alerts.go getStateColor
func GetStateColor(state string) string {
	switch state {
	case "new":
		return "\033[33m" // Yellow
	case "summarized":
		return "\033[34m" // Blue
	case "sent":
		return "\033[32m" // Green
	case "failed":
		return "\033[31m" // Red
	case "archived":
		return "\033[90m" // Gray
	default:
		return ""
	}
}

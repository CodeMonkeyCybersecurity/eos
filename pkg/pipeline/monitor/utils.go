package monitor

import (
	"fmt"
	"time"
)

// FormatRelativeTime formats a timestamp as relative time (e.g., "5m", "2h", "3d")
// Migrated from cmd/read/pipeline.go formatRelativeTime
func FormatRelativeTime(t time.Time) string {
	// ASSESS - Calculate time difference
	diff := time.Since(t)

	// INTERVENE - Format based on duration
	if diff < time.Minute {
		return "now"
	} else if diff < time.Hour {
		return fmt.Sprintf("%dm", int(diff.Minutes()))
	} else if diff < 24*time.Hour {
		return fmt.Sprintf("%dh", int(diff.Hours()))
	} else {
		return fmt.Sprintf("%dd", int(diff.Hours()/24))
	}

	// EVALUATE - Return formatted time string
}

// GetStateColor returns ANSI color code for alert states
// This is a placeholder until we migrate the actual function from pipeline_alerts.go
func GetStateColor(state string) string {
	switch state {
	case "new":
		return "\033[93m" // Yellow
	case "sent":
		return "\033[92m" // Green
	case "failed":
		return "\033[91m" // Red
	default:
		return "\033[90m" // Gray
	}
}

// GetAgentStatusColor returns ANSI color code for agent status
// This is a placeholder until we migrate the actual function from delphi_agents.go
func GetAgentStatusColor(status *string) string {
	if status == nil {
		return "\033[90m" // Gray
	}

	switch *status {
	case "active":
		return "\033[92m" // Green
	case "disconnected":
		return "\033[91m" // Red
	case "never_connected":
		return "\033[93m" // Yellow
	default:
		return "\033[90m" // Gray
	}
}

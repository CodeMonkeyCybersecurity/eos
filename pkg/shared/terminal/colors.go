// Package terminal provides terminal-related utilities including ANSI colors and formatting.
package terminal

import "strings"

// ANSI color codes
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorMagenta = "\033[35m"
	ColorGray    = "\033[90m"
)

// GetAgentStatusColor returns the ANSI color code for an agent status.
// Returns appropriate color based on status:
//   - Green for "active"
//   - Red for "disconnected"
//   - Yellow for "pending"
//   - Magenta for "never_connected"
//   - Gray for nil or unknown statuses
func GetAgentStatusColor(status *string) string {
	if status == nil {
		return ColorGray
	}

	switch strings.ToLower(*status) {
	case "active":
		return ColorGreen
	case "disconnected":
		return ColorRed
	case "pending":
		return ColorYellow
	case "never_connected":
		return ColorMagenta
	default:
		return ColorGray
	}
}

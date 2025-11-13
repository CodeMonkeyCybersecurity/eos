// Package format provides common formatting utilities for strings, numbers, and other data types.
package format

import (
	"fmt"
	"time"
)

// OptionalTimeShort formats an optional time pointer in a compact, human-readable format.
// Returns "-" if the pointer is nil.
// Shows relative time from now:
//   - "now" if less than 1 minute
//   - "Xm" for minutes
//   - "Xh" for hours
//   - "Xd" for days
func OptionalTimeShort(t *time.Time) string {
	if t == nil {
		return "-"
	}

	now := time.Now()
	diff := now.Sub(*t)

	if diff < time.Minute {
		return "now"
	} else if diff < time.Hour {
		return fmt.Sprintf("%dm", int(diff.Minutes()))
	} else if diff < 24*time.Hour {
		return fmt.Sprintf("%dh", int(diff.Hours()))
	} else {
		return fmt.Sprintf("%dd", int(diff.Hours()/24))
	}
}

// Package format provides common formatting utilities for strings, numbers, and other data types.
package format

// OptionalString formats an optional string pointer with a maximum length.
// Returns "-" if the pointer is nil, otherwise returns the string value
// truncated to maxLen with "..." suffix if needed.
func OptionalString(s *string, maxLen int) string {
	if s == nil {
		return "-"
	}
	str := *s
	if len(str) > maxLen {
		return str[:maxLen-3] + "..."
	}
	return str
}

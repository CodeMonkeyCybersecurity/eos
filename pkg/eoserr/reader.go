/* pkg/eoserr/reader.go */

package eoserr

import "strings"

// ExtractSummary extracts a concise summary from the full command output.
// It looks for lines containing keywords like "error", "failed", or "cannot".
// If such lines are found, it returns a combination (up to two) as the summary.
// Otherwise, it falls back to returning the first non-empty line.
func ExtractSummary(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "No output provided."
	}

	lines := strings.Split(trimmed, "\n")
	var candidates []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "error") ||
			strings.Contains(lowerLine, "failed") ||
			strings.Contains(lowerLine, "cannot") {
			candidates = append(candidates, line)
		}
	}

	if len(candidates) > 0 {
		if len(candidates) > 2 {
			candidates = candidates[:2]
		}
		return strings.Join(candidates, " - ")
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}

	return "Unknown error."
}

// IsExpectedUserError determines if an error is a recoverable, non-fatal user error.
func IsExpectedUserError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no test-data found") ||
		strings.Contains(msg, "vault read failed at") ||
		strings.Contains(msg, "disk fallback read failed")
}
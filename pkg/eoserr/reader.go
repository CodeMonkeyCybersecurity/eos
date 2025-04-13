/* pkg/eoserr/reader.go */

package eoserr

import "strings"

// extractSummary extracts a concise summary from the full command output.
// It looks for lines containing keywords like "error", "failed", or "cannot".
// If such lines are found, it returns a combination (up to two) as the summary.
// Otherwise, it falls back to returning the first non-empty line.
func ExtractSummary(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "No output provided."
	}

	// Split the output into lines.
	lines := strings.Split(trimmed, "\n")
	var candidates []string

	// Look for lines that suggest an error.
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lowerLine := strings.ToLower(line)
		// Check for common error indicators.
		if strings.Contains(lowerLine, "error") ||
			strings.Contains(lowerLine, "failed") ||
			strings.Contains(lowerLine, "cannot") {
			candidates = append(candidates, line)
		}
	}

	// If candidate lines are found, join the first two lines for a concise summary.
	if len(candidates) > 0 {
		if len(candidates) > 2 {
			candidates = candidates[:2]
		}
		return strings.Join(candidates, " - ")
	}

	// Fallback: return the first non-empty line.
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}

	return "Unknown error."
}

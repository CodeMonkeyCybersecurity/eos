// pkg/eoserr/util.go

package eoserr

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

var debugMode bool

func SetDebugMode(enabled bool) {
	debugMode = enabled
}

func DebugEnabled() bool {
	return debugMode
}

// ExtractSummary extracts a concise error summary from full output.
func ExtractSummary(output string, maxCandidates int) string {
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
			strings.Contains(lowerLine, "cannot") ||
			strings.Contains(lowerLine, "panic") ||
			strings.Contains(lowerLine, "fatal") ||
			strings.Contains(lowerLine, "timeout") {
			candidates = append(candidates, line)
		}
	}

	if len(candidates) > 0 {
		if len(candidates) > maxCandidates {
			candidates = candidates[:maxCandidates]
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

// NewExpectedError wraps an error for softer UX handling.
func NewExpectedError(err error) error {
	if err == nil {
		return nil
	}
	return &UserError{cause: err}
}

// IsExpectedUserError checks if the error is marked as expected.
func IsExpectedUserError(err error) bool {
	var e *UserError
	return errors.As(err, &e)
}

// PrintError prints a human-readable error message without exiting.
func PrintError(userMessage string, err error) {
	if DebugEnabled() {
		zap.L().Fatal(userMessage, zap.Error(err)) // Full structured fatal if debugging
		return
	}

	if err != nil {
		if IsExpectedUserError(err) {
			zap.L().Warn(userMessage, zap.Error(err))
			fmt.Fprintf(os.Stderr, "⚠️  Notice: %s: %v\n", userMessage, err)
		} else {
			zap.L().Error(userMessage, zap.Error(err))
			fmt.Fprintf(os.Stderr, "❌ Error: %s: %v\n", userMessage, err)
		}
	}
}

// ExitWithError prints the error and exits with status 1.
func ExitWithError(userMessage string, err error) {
	PrintError(userMessage, err)
	fmt.Fprintln(os.Stderr, "👉 Tip: rerun with --debug for more details.")
	os.Exit(1)
}

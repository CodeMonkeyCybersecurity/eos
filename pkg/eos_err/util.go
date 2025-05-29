// pkg/eos_err/util.go

package eos_err

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
func ExtractSummary(ctx context.Context, output string, maxCandidates int) string {
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
func NewExpectedError(ctx context.Context, err error) error {
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
func PrintError(ctx context.Context, userMessage string, err error) {
	if DebugEnabled() {
		otelzap.Ctx(ctx).Fatal(userMessage, zap.Error(err)) // Full structured fatal if debugging
		return
	}

	if err != nil {
		if IsExpectedUserError(err) {
			otelzap.Ctx(ctx).Warn(userMessage, zap.Error(err))
			fmt.Fprintf(os.Stderr, "⚠️  Notice: %s: %v\n", userMessage, err)
		} else {
			otelzap.Ctx(ctx).Error(userMessage, zap.Error(err))
			fmt.Fprintf(os.Stderr, "❌ Error: %s: %v\n", userMessage, err)
		}
	}
}

// ExitWithError prints the error and exits with status 1.
func ExitWithError(ctx context.Context, userMessage string, err error) {
	PrintError(ctx, userMessage, err)
	fmt.Fprintln(os.Stderr, "👉 Tip: rerun with --debug for more details.")
	os.Exit(1)
}

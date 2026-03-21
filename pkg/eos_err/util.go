// pkg/eos_err/util.go

package eos_err

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	debugMode   atomic.Bool
	outputMu    sync.Mutex
	errorOutput io.Writer = os.Stderr
)

func SetDebugMode(enabled bool) {
	debugMode.Store(enabled)
}

func DebugEnabled() bool {
	return debugMode.Load()
}

func writeErrorOutput(format string, args ...interface{}) {
	outputMu.Lock()
	defer outputMu.Unlock()
	_, _ = fmt.Fprintf(errorOutput, format, args...)
}

func setErrorOutput(w io.Writer) func() {
	outputMu.Lock()
	previous := errorOutput
	if w == nil {
		errorOutput = os.Stderr
	} else {
		errorOutput = w
	}
	outputMu.Unlock()

	return func() {
		outputMu.Lock()
		errorOutput = previous
		outputMu.Unlock()
	}
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

// NewUserError creates a new user error with formatting support.
func NewUserError(format string, args ...interface{}) error {
	return &UserError{cause: fmt.Errorf(format, args...)}
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
			writeErrorOutput(" Notice: %s: %v\n", userMessage, err)
		} else {
			otelzap.Ctx(ctx).Error(userMessage, zap.Error(err))
			writeErrorOutput(" Error: %s: %v\n", userMessage, err)
		}
	}
}

// ExitWithError prints the error and exits with status 1.
func ExitWithError(ctx context.Context, userMessage string, err error) {
	PrintError(ctx, userMessage, err)
	writeErrorOutput(" Tip: rerun with --debug for more details.\n")
	os.Exit(1)
}

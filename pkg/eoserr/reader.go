package eoserr

import (
	"errors"
	"strings"
)

// ExtractSummary extracts a concise summary from the full command output.
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

// expectedError is a lightweight wrapper to mark expected, user-recoverable errors.
type expectedError struct {
	cause error
}

func (e *expectedError) Error() string {
	return e.cause.Error()
}

func (e *expectedError) Unwrap() error {
	return e.cause
}

// NewExpectedError wraps an error as an expected user error.
func NewExpectedError(err error) error {
	if err == nil {
		return nil
	}
	return &expectedError{cause: err}
}

// IsExpectedUserError returns true if an error is a wrapped expected error.
func IsExpectedUserError(err error) bool {
	var e *expectedError
	return errors.As(err, &e)
}

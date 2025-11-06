// Package crypto provides secure operations infrastructure
package crypto

import (
	"context"
	"crypto/subtle"
	"regexp"

	"go.uber.org/zap"
)

// SecureOperationsImpl provides crypto operations
type SecureOperationsImpl struct {
	logger *zap.Logger
}

// NewSecureOperations creates a new secure operations implementation
func NewSecureOperations(logger *zap.Logger) *SecureOperationsImpl {
	return &SecureOperationsImpl{
		logger: logger,
	}
}

// SecureZero overwrites sensitive data in memory
func (s *SecureOperationsImpl) SecureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// SecureCompare performs constant-time comparison of two byte slices
func (s *SecureOperationsImpl) SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RedactString redacts sensitive parts of a string
func (s *SecureOperationsImpl) RedactString(ctx context.Context, input string, patterns []string) string {
	result := input

	for _, pattern := range patterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			s.logger.Warn("Invalid redaction pattern",
				zap.String("pattern", pattern),
				zap.Error(err),
			)
			continue
		}

		result = regex.ReplaceAllString(result, "[REDACTED]")
	}

	return result
}

// SanitizeInput sanitizes user input to prevent injection attacks
func (s *SecureOperationsImpl) SanitizeInput(ctx context.Context, input string, allowedChars string) (string, error) {
	if allowedChars == "" {
		// Default safe character set
		allowedChars = CharsetSafe
	}

	result := make([]byte, 0, len(input))
	for _, char := range input {
		for _, allowed := range allowedChars {
			if char == allowed {
				result = append(result, byte(char))
				break
			}
		}
	}

	sanitized := string(result)
	if sanitized != input {
		s.logger.Debug("Input sanitized",
			zap.Int("original_length", len(input)),
			zap.Int("sanitized_length", len(sanitized)),
		)
	}

	return sanitized, nil
}

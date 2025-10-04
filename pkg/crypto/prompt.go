// pkg/crypto/prompt.go

package crypto

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// PromptPassword securely prompts for a password twice, validates strength, and ensures match.
func PromptPassword(rc *eos_io.RuntimeContext, prompt string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	for attempts := 1; attempts <= MaxPasswordAttempts; attempts++ {
		logger.Info("Prompting for password", zap.Int("attempt", attempts))

		// SECURITY: Use structured logging instead of fmt.Print per CLAUDE.md P0 rule
		logger.Info("terminal prompt: password entry", zap.String("prompt", prompt))
		pw1Bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			logger.Error("Failed to read password input", zap.Error(err))
			return "", fmt.Errorf("failed to read password input: %w", err)
		}
		pw1 := strings.TrimSpace(string(pw1Bytes))

		if err := ValidateStrongPassword(rc.Ctx, pw1); err != nil {
			logger.Warn("Password strength validation failed - retrying", zap.Error(err))
			continue
		}

		logger.Info("terminal prompt: password confirmation")
		pw2Bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			logger.Error("Failed to read confirmation input", zap.Error(err))
			return "", fmt.Errorf("failed to read password confirmation: %w", err)
		}
		pw2 := strings.TrimSpace(string(pw2Bytes))

		if pw1 != pw2 {
			logger.Warn("Passwords do not match - retrying", zap.Int("attempt", attempts))
			continue
		}

		logger.Info("Password accepted", zap.Int("attempt", attempts))
		return pw1, nil
	}

	logger.Error("Maximum password attempts exceeded")
	return "", errors.New("maximum password attempts exceeded")
}

// PromptPasswordOrDefault prompts for a password and returns default if blank.
func PromptPasswordOrDefault(rc *eos_io.RuntimeContext, prompt string, defaultValue string) (string, error) {
	// SECURITY: Use structured logging instead of fmt.Printf per CLAUDE.md P0 rule
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("terminal prompt: password with default", zap.String("prompt", prompt))

	pwBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read password input", zap.Error(err))
		return "", fmt.Errorf("error reading password input: %w", err)
	}
	pass := strings.TrimSpace(string(pwBytes))
	if pass == "" {
		logger.Info("Using default password value")
		return defaultValue, nil
	}
	return pass, nil
}

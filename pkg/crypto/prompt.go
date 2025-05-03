// pkg/crypto/prompt.go

package crypto

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"go.uber.org/zap"
	"golang.org/x/term"
)

// PromptPassword securely prompts for a password twice, validates strength, and ensures match.
func PromptPassword(prompt string) (string, error) {
	for attempts := 1; attempts <= MaxPasswordAttempts; attempts++ {
		zap.L().Info("🔐 Prompting for password", zap.Int("attempt", attempts))

		fmt.Print(prompt)
		pw1Bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			zap.L().Error("❌ Failed to read password input", zap.Error(err))
			return "", fmt.Errorf("failed to read password input: %w", err)
		}
		pw1 := strings.TrimSpace(string(pw1Bytes))

		if err := ValidateStrongPassword(pw1); err != nil {
			zap.L().Warn("❌ Password strength validation failed", zap.Error(err))
			fmt.Println("❌ Password does not meet strength requirements. Please try again.")
			continue
		}

		fmt.Print("Confirm password: ")
		pw2Bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			zap.L().Error("❌ Failed to read confirmation input", zap.Error(err))
			return "", fmt.Errorf("failed to read password confirmation: %w", err)
		}
		pw2 := strings.TrimSpace(string(pw2Bytes))

		if pw1 != pw2 {
			zap.L().Warn("❌ Passwords do not match", zap.Int("attempt", attempts))
			fmt.Println("❌ Passwords do not match. Please try again.")
			continue
		}

		zap.L().Info("✅ Password accepted", zap.Int("attempt", attempts))
		return pw1, nil
	}

	zap.L().Error("⛔ Maximum password attempts exceeded")
	return "", errors.New("maximum password attempts exceeded")
}

// PromptPasswordOrDefault prompts for a password and returns default if blank.
func PromptPasswordOrDefault(prompt string, defaultValue string) (string, error) {
	fmt.Printf("%s [%s]: ", prompt, "********")
	pwBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		zap.L().Error("❌ Failed to read password input", zap.Error(err))
		return "", fmt.Errorf("error reading password input: %w", err)
	}
	pass := strings.TrimSpace(string(pwBytes))
	if pass == "" {
		zap.L().Info("ℹ️  Using default password value")
		return defaultValue, nil
	}
	return pass, nil
}

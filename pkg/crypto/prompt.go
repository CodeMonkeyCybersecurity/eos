// pkg/crypto/prompt.go

package crypto

import (
	"fmt"
	"strings"
	"syscall"

	"go.uber.org/zap"
	"golang.org/x/term"
)

// PromptStrongPassword prompts and validates a strong password with confirmation.
func PromptStrongPassword(label string, log *zap.Logger) (string, error) {
	for {
		pass, err := PromptPassword(label, log)
		if err != nil {
			return "", err
		}

		if err := ValidateStrongPassword(pass, log); err != nil {
			fmt.Printf("❌ %s\n", err.Error())
			continue
		}

		confirm, err := PromptPassword("Confirm "+label, log)
		if err != nil {
			return "", err
		}

		if pass != confirm {
			fmt.Println("❌ Passwords do not match.")
			continue
		}

		return pass, nil
	}
}

// PromptPassword hides user input and returns the entered password.
func PromptPassword(label string, log *zap.Logger) (string, error) {
	fmt.Printf("%s: ", label)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

// PromptPasswordWithDefault hides user input and returns password or default if blank.
func PromptPasswordWithDefault(label, defaultValue string, log *zap.Logger) (string, error) {
	fmt.Printf("%s [%s]: ", label, "********")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println("")
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}
	pass := strings.TrimSpace(string(bytePassword))
	if pass == "" {
		return defaultValue, nil
	}
	return pass, nil
}


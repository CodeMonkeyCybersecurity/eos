package eos_io

import (
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"golang.org/x/term"
)

// PromptSecurePassword prompts for a password without echoing to screen
// Migrated from cmd/create/user.go promptSecurePassword
func PromptSecurePassword(rc *RuntimeContext, prompt string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if we can read from terminal
	logger.Debug("Assessing secure password input capability")

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("stdin is not a terminal")
	}

	// INTERVENE - Read password securely
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Add newline after password input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	// EVALUATE - Ensure we got valid input
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}

	logger.Debug("Successfully read secure password input")
	return string(password), nil
}

// PromptInput prompts for general input from the user
func PromptInput(rc *RuntimeContext, prompt string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if we can read from terminal
	logger.Debug("Assessing input capability")

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("stdin is not a terminal")
	}

	// INTERVENE - Prompt and read input
	logger.Info("terminal prompt: " + prompt)
	if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
		return "", fmt.Errorf("failed to write prompt: %w", err)
	}

	var input string
	if _, err := fmt.Scanln(&input); err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}

	// EVALUATE - Ensure we got valid input
	input = strings.TrimSpace(input)
	if len(input) == 0 {
		return "", fmt.Errorf("input cannot be empty")
	}

	logger.Debug("Successfully read user input")
	return input, nil
}

package eos_io

import (
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
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

// PromptInputWithRetry prompts for input with retry logic and validation
func PromptInputWithRetry(rc *RuntimeContext, prompt string, validationFunc func(string) error, maxAttempts int) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if we can read from terminal
	logger.Debug("Assessing input capability for retry prompt")

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("stdin is not a terminal")
	}

	if maxAttempts <= 0 {
		maxAttempts = 3 // Default to 3 attempts
	}

	// INTERVENE - Prompt with retry logic
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		logger.Info("terminal prompt: " + prompt)
		if _, err := fmt.Fprint(os.Stderr, prompt); err != nil {
			return "", fmt.Errorf("failed to write prompt: %w", err)
		}

		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			// Handle empty input gracefully
			if strings.Contains(err.Error(), "unexpected newline") || strings.Contains(err.Error(), "EOF") {
				input = ""
			} else {
				return "", fmt.Errorf("failed to read input: %w", err)
			}
		}

		input = strings.TrimSpace(input)

		// If validation function provided, validate input
		if validationFunc != nil {
			if err := validationFunc(input); err != nil {
				logger.Warn("Invalid input provided",
					zap.Int("attempt", attempt),
					zap.Int("max_attempts", maxAttempts),
					zap.Error(err))
				
				if attempt < maxAttempts {
					logger.Info("terminal prompt: " + err.Error() + fmt.Sprintf(" (Attempt %d/%d)", attempt, maxAttempts))
					continue
				} else {
					return "", fmt.Errorf("maximum attempts reached (%d): %w", maxAttempts, err)
				}
			}
		} else {
			// Default validation: non-empty input
			if len(input) == 0 {
				logger.Warn("Empty input provided",
					zap.Int("attempt", attempt),
					zap.Int("max_attempts", maxAttempts))
				
				if attempt < maxAttempts {
					logger.Info("terminal prompt: Input cannot be empty" + fmt.Sprintf(" (Attempt %d/%d)", attempt, maxAttempts))
					continue
				} else {
					return "", fmt.Errorf("maximum attempts reached (%d): input cannot be empty", maxAttempts)
				}
			}
		}

		// EVALUATE - Valid input received
		logger.Debug("Successfully read and validated user input")
		return input, nil
	}

	return "", fmt.Errorf("unexpected end of retry loop")
}

// PromptValidatedInput is a convenience function for common validation scenarios
func PromptValidatedInput(rc *RuntimeContext, prompt string, validValues []string, maxAttempts int) (string, error) {
	validationFunc := func(input string) error {
		if len(input) == 0 {
			return fmt.Errorf("input cannot be empty")
		}
		
		if len(validValues) > 0 {
			for _, valid := range validValues {
				if input == valid {
					return nil
				}
			}
			return fmt.Errorf("invalid input '%s': must be one of %v", input, validValues)
		}
		
		return nil
	}

	return PromptInputWithRetry(rc, prompt, validationFunc, maxAttempts)
}

// PromptYesNo prompts for a yes/no confirmation with retry logic
func PromptYesNo(rc *RuntimeContext, prompt string, maxAttempts int) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	fullPrompt := prompt
	if !strings.HasSuffix(prompt, " ") {
		fullPrompt += " "
	}
	fullPrompt += "(y/N): "
	
	validationFunc := func(input string) error {
		if len(input) == 0 {
			// Default to "no" for empty input
			return nil
		}
		
		input = strings.ToLower(input)
		if input == "y" || input == "yes" || input == "n" || input == "no" {
			return nil
		}
		
		return fmt.Errorf("invalid input '%s': please enter 'y', 'yes', 'n', or 'no'", input)
	}
	
	result, err := PromptInputWithRetry(rc, fullPrompt, validationFunc, maxAttempts)
	if err != nil {
		return false, err
	}
	
	// Handle empty input (default to no)
	if len(result) == 0 {
		logger.Debug("Empty input received, defaulting to 'no'")
		return false, nil
	}
	
	result = strings.ToLower(result)
	isYes := result == "y" || result == "yes"
	
	logger.Debug("Yes/No prompt result", zap.Bool("is_yes", isYes), zap.String("input", result))
	return isYes, nil
}

// PromptConfirmation prompts for explicit confirmation by typing a specific phrase
func PromptConfirmation(rc *RuntimeContext, prompt string, confirmationPhrase string, maxAttempts int) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	fullPrompt := fmt.Sprintf("%s Type '%s' to confirm: ", prompt, confirmationPhrase)
	
	validationFunc := func(input string) error {
		if len(input) == 0 {
			return fmt.Errorf("input cannot be empty")
		}
		
		if input != confirmationPhrase {
			return fmt.Errorf("confirmation phrase does not match. Expected: '%s'", confirmationPhrase)
		}
		
		return nil
	}
	
	result, err := PromptInputWithRetry(rc, fullPrompt, validationFunc, maxAttempts)
	if err != nil {
		return false, err
	}
	
	confirmed := result == confirmationPhrase
	logger.Debug("Confirmation prompt result", zap.Bool("confirmed", confirmed))
	return confirmed, nil
}

package interaction

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// For testing: allow overriding stdin
var testStdin io.Reader

func getStdinReader() io.Reader {
	if testStdin != nil {
		return testStdin
	}
	return os.Stdin
}

// PromptWithDefault prompts the user and returns their response or a default value if empty.
func PromptWithDefault(label, defaultValue string) string {
	// SECURITY: Use structured logging instead of fmt.Printf per CLAUDE.md P0 rule
	logger := otelzap.L()
	logger.Info("terminal prompt: user input with default",
		zap.String("label", label),
		zap.String("default", defaultValue))

	reader := bufio.NewReader(getStdinReader())
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultValue
	}
	return text
}

// PromptRequired prompts the user for input and loops until a non-empty string is entered.
func PromptRequired(label string) string {
	// SECURITY: Use structured logging instead of fmt.Printf per CLAUDE.md P0 rule
	logger := otelzap.L()

	reader := bufio.NewReader(getStdinReader())
	for {
		logger.Info("terminal prompt: required user input", zap.String("label", label))
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text != "" {
			return text
		}
		logger.Warn("Input cannot be empty, retrying")
	}
}

// PromptInput is an alias for PromptRequired for backward compatibility
func PromptInput(args ...interface{}) string {
	// Handle both (label) and (ctx, label, default) signatures
	if len(args) == 1 {
		return PromptRequired(args[0].(string))
	} else if len(args) >= 2 {
		// args[0] is context (ignored), args[1] is label
		label := args[1].(string)
		if len(args) >= 3 {
			defaultVal := args[2].(string)
			return PromptWithDefault(label, defaultVal)
		}
		return PromptRequired(label)
	}
	return PromptRequired("")
}

// PromptYesNo prompts for yes/no and returns true for yes
// P0 FIX: Added error handling, input validation, and retry logic
// For new code, use pkg/prompt.YesNo which has RuntimeContext support
func PromptYesNo(args ...interface{}) bool {
	var question string
	var defaultYes bool

	// Handle both (question, defaultYes) and (ctx, question, defaultYes) signatures
	if len(args) == 2 {
		question = args[0].(string)
		defaultYes = args[1].(bool)
	} else if len(args) >= 3 {
		// args[0] is context (ignored)
		question = args[1].(string)
		defaultYes = args[2].(bool)
	} else {
		return false
	}

	prompt := question
	if defaultYes {
		prompt += " [Y/n]: "
	} else {
		prompt += " [y/N]: "
	}

	logger := otelzap.L()
	logger.Info("terminal prompt: yes/no question", zap.String("question", question))

	const maxAttempts = 3
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		reader := bufio.NewReader(getStdinReader())
		response, err := reader.ReadString('\n')

		// P0 FIX: Handle errors (was: response, _ := reader.ReadString('\n'))
		if err != nil {
			lastErr = err
			if err == io.EOF {
				logger.Warn("Reached end of input (EOF), using default",
					zap.Bool("default", defaultYes),
					zap.String("question", question))
				return defaultYes
			}
			logger.Warn("Failed to read input, retrying",
				zap.Error(err),
				zap.Int("attempt", attempt),
				zap.Int("max_attempts", maxAttempts))
			time.Sleep(100 * time.Millisecond)
			continue
		}

		response = strings.TrimSpace(strings.ToLower(response))

		// Handle empty input (use default)
		if response == "" {
			logger.Debug("Empty input, using default",
				zap.Bool("default", defaultYes))
			return defaultYes
		}

		// P0 FIX: Validate input and accept common variations
		switch response {
		case "y", "yes", "yeah", "yep", "sure", "ok", "true", "1":
			logger.Debug("User answered yes", zap.String("response", response))
			return true
		case "n", "no", "nope", "nah", "false", "0":
			logger.Debug("User answered no", zap.String("response", response))
			return false
		default:
			// P0 FIX: Invalid input - retry with guidance (was: silent wrong answer)
			logger.Warn("Invalid input. Please enter 'y' for yes or 'n' for no.",
				zap.String("input", response),
				zap.Int("attempt", attempt),
				zap.Int("remaining", maxAttempts-attempt))

			if attempt == maxAttempts {
				logger.Warn("Maximum attempts reached, using default",
					zap.Bool("default", defaultYes),
					zap.String("question", question))
				return defaultYes
			}

			// Prompt again
			logger.Info("terminal prompt: " + prompt)
		}
	}

	// Should never reach here, but handle gracefully
	logger.Error("Unexpected prompt state, using default",
		zap.Error(lastErr),
		zap.Bool("default", defaultYes))
	return defaultYes
}

// PromptSelect prompts the user to select from options
// Returns the selected option
func PromptSelect(args ...interface{}) string {
	var label string
	var options []string

	// Handle both (label, options) and (ctx, label, options) signatures
	if len(args) == 2 {
		label = args[0].(string)
		options = args[1].([]string)
	} else if len(args) >= 3 {
		// args[0] is context (ignored)
		label = args[1].(string)
		options = args[2].([]string)
	} else {
		return ""
	}
	logger := otelzap.L()
	logger.Info("terminal prompt: select from options",
		zap.String("label", label),
		zap.Int("option_count", len(options)))

	// Display options
	logger.Info(label)
	for i, opt := range options {
		logger.Info("option", zap.Int("number", i+1), zap.String("value", opt))
	}

	// Get selection
	reader := bufio.NewReader(getStdinReader())
	for {
		logger.Info("terminal prompt: enter selection number")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)

		// Try to find matching option
		for i, opt := range options {
			if text == opt || text == string(rune(i+1+'0')) {
				return opt
			}
		}

		logger.Warn("Invalid selection, please try again")
	}
}

// PromptUser prompts for a username/user input
// Accepts either (label) or (ctx, label) signatures
func PromptUser(args ...interface{}) (string, error) {
	var label string
	if len(args) == 1 {
		label = args[0].(string)
	} else if len(args) >= 2 {
		// args[0] is context (ignored), args[1] is label
		label = args[1].(string)
	}
	return PromptRequired(label), nil
}

// PromptSecret prompts for a secret (password, token, etc.) without echoing
// Accepts either (label) or (ctx, label) signatures
func PromptSecret(args ...interface{}) (string, error) {
	var label string
	if len(args) == 1 {
		label = args[0].(string)
	} else if len(args) >= 2 {
		// args[0] is context (ignored), args[1] is label
		label = args[1].(string)
	}

	logger := otelzap.L()
	logger.Info("terminal prompt: secret input (not echoed)", zap.String("label", label))

	// SECURITY: Use term.ReadPassword to hide input from terminal
	// Check if stdin is a terminal
	if !term.IsTerminal(int(syscall.Stdin)) {
		// Fallback for non-terminal (e.g., testing)
		logger.Warn("stdin is not a terminal, secret will be visible")

		// NOTE: Don't call PromptRequired here - it logs again causing duplicate output
		// Instead, inline the prompt logic without duplicate logging
		reader := bufio.NewReader(getStdinReader())
		for {
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
			if text != "" {
				return text, nil
			}
			logger.Warn("Input cannot be empty, retrying")
		}
	}

	// Print prompt without newline
	fmt.Printf("%s: ", label)

	// Read password without echoing
	secretBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add newline after hidden input

	if err != nil {
		return "", fmt.Errorf("failed to read secret: %w", err)
	}

	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}

	return secret, nil
}

// PromptSecrets prompts for one or more secret values.
//
// Supported call patterns:
//   - PromptSecrets(count int) - prompts "Secret 1", "Secret 2", etc.
//   - PromptSecrets(ctx context.Context, count int) - context currently unused, prompts "Secret 1", "Secret 2", etc.
//   - PromptSecrets(ctx context.Context, label string, count int) - prompts "label" (count=1) or "label 1", "label 2" (count>1)
//
// Returns error if:
//   - Invalid number of arguments
//   - Arguments have wrong types
//   - Count is zero or negative
//   - Failed to read secret input
//
// NOTE: Context is currently unused. Cancellation support is tracked as P2 issue.
func PromptSecrets(args ...interface{}) ([]string, error) {
	var count int
	var label string
	var hasLabel bool

	// Parse arguments based on count and types
	switch len(args) {
	case 1:
		// Pattern: PromptSecrets(count)
		var ok bool
		count, ok = args[0].(int)
		if !ok {
			return nil, fmt.Errorf("PromptSecrets: argument must be int, got %T", args[0])
		}

	case 2:
		// Pattern: PromptSecrets(ctx, count)
		// NOTE: Context ignored (see function comment for P2 issue)
		var ok bool
		count, ok = args[1].(int)
		if !ok {
			return nil, fmt.Errorf("PromptSecrets: args[1] must be int (count), got %T", args[1])
		}

	case 3:
		// Pattern: PromptSecrets(ctx, label, count)
		// NOTE: Context ignored (see function comment for P2 issue)
		var ok bool
		label, ok = args[1].(string)
		if !ok {
			return nil, fmt.Errorf("PromptSecrets: args[1] must be string (label), got %T", args[1])
		}
		count, ok = args[2].(int)
		if !ok {
			return nil, fmt.Errorf("PromptSecrets: args[2] must be int (count), got %T", args[2])
		}
		hasLabel = true

	default:
		return nil, fmt.Errorf("PromptSecrets: invalid number of arguments (%d), expected 1, 2, or 3", len(args))
	}

	// Validate count is positive
	if count <= 0 {
		return nil, fmt.Errorf("PromptSecrets: count must be positive, got %d", count)
	}

	// Collect secrets
	results := make([]string, count)
	for i := 0; i < count; i++ {
		var promptLabel string
		if hasLabel {
			// For single secret, use label as-is. For multiple, add index.
			if count == 1 {
				promptLabel = label
			} else {
				promptLabel = fmt.Sprintf("%s %d", label, i+1)
			}
		} else {
			// No label provided, use generic numbered label
			promptLabel = fmt.Sprintf("Secret %d", i+1)
		}

		// P1: Handle error instead of ignoring it
		secret, err := PromptSecret(promptLabel)
		if err != nil {
			return nil, fmt.Errorf("failed to prompt for %s: %w", promptLabel, err)
		}
		results[i] = secret
	}
	return results, nil
}

// Type-safe wrapper functions for compile-time safety
// These functions provide explicit signatures to prevent type errors at compile time.
// Existing code can continue using the variadic version; new code should prefer these.

// PromptSecretsSimple prompts for N secrets with default labels "Secret 1", "Secret 2", etc.
func PromptSecretsSimple(count int) ([]string, error) {
	return PromptSecrets(count)
}

// PromptSecretsLabeled prompts for N secrets with a custom label.
// For count=1, prompts "label". For count>1, prompts "label 1", "label 2", etc.
func PromptSecretsLabeled(ctx context.Context, label string, count int) ([]string, error) {
	return PromptSecrets(ctx, label, count)
}

// PromptInputWithReader prompts for input using a specific reader
// Accepts (reader, label) signature
func PromptInputWithReader(args ...interface{}) string {
	// For now, just ignore the reader and use stdin
	var label string
	if len(args) >= 2 {
		// args[0] is reader (ignored), args[1] is label
		label = args[1].(string)
	} else if len(args) == 1 {
		label = args[0].(string)
	}
	return PromptRequired(label)
}

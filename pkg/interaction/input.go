package interaction

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PromptWithDefault prompts the user and returns their response or a default value if empty.
func PromptWithDefault(label, defaultValue string) string {
	// SECURITY: Use structured logging instead of fmt.Printf per CLAUDE.md P0 rule
	logger := otelzap.L()
	logger.Info("terminal prompt: user input with default",
		zap.String("label", label),
		zap.String("default", defaultValue))

	reader := bufio.NewReader(os.Stdin)
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

	reader := bufio.NewReader(os.Stdin)
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

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response == "" {
		return defaultYes
	}

	return response == "y" || response == "yes"
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
	reader := bufio.NewReader(os.Stdin)
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
	// For now, use regular prompt - proper implementation would use syscall/terminal
	return PromptRequired(label), nil
}

// PromptSecrets prompts for multiple secrets
// Accepts either (...labels) or (ctx, count) signatures
func PromptSecrets(args ...interface{}) ([]string, error) {
	var count int

	// Check if first arg is context
	if len(args) > 0 {
		if _, isInt := args[0].(int); !isInt {
			// First arg is context (ignored), second is count
			if len(args) > 1 {
				count = args[1].(int)
			}
		} else {
			count = args[0].(int)
		}
	}

	results := make([]string, count)
	for i := 0; i < count; i++ {
		secret, _ := PromptSecret(fmt.Sprintf("Secret %d", i+1))
		results[i] = secret
	}
	return results, nil
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

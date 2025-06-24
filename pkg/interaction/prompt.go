// pkg/interaction/prompt.go

package interaction

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// PromptIfMissing returns the value of a CLI flag or prompts the user if it's unset.
// If `isSecret` is true, the input is hidden (e.g. passwords).
func PromptIfMissing(ctx context.Context, cmd *cobra.Command, flagName, prompt string, isSecret bool) (string, error) {
	val, err := cmd.Flags().GetString(flagName)
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to get CLI flag", zap.String("flag", flagName), zap.Error(err))
		return "", err
	}
	if val != "" {
		otelzap.Ctx(ctx).Debug(" CLI flag provided", zap.String("flag", flagName), zap.String("value", val))
		return val, nil
	}

	otelzap.Ctx(ctx).Info(" Prompting for missing flag", zap.String("flag", flagName), zap.Bool("is_secret", isSecret))

	if isSecret {
		secret, err := PromptSecret(ctx, prompt) // <-- capture both values
		if err != nil {
			otelzap.Ctx(ctx).Error(" Failed to read secret input", zap.Error(err))
			return "", err
		}
		if secret == "" {
			otelzap.Ctx(ctx).Warn("Empty input received for secret prompt")
		}
		return secret, nil
	}

	input := PromptInput(ctx, prompt, "")
	if input == "" {
		otelzap.Ctx(ctx).Warn("Empty input received for prompt", zap.String("prompt", prompt))
	}
	return input, nil
}

// PromptSecret asks the user for a hidden input (no terminal echo).
// Logs an error if reading fails, returns empty string on failure.
// Returns trimmed input or warns if no input is provided.
func PromptSecret(ctx context.Context, prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		otelzap.Ctx(ctx).Error(" Cannot prompt for secret input: not a TTY")
		return "", fmt.Errorf("secret prompt failed: no terminal available")
	}

	logger := otelzap.Ctx(ctx)
	logger.Info(" Prompting for secret input", zap.String("prompt", prompt))

	// Use os.Stderr for user-facing prompts to preserve stdout for automation
	_, _ = fmt.Fprint(os.Stderr, prompt+": ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		otelzap.Ctx(ctx).Error(" Failed to read secret input", zap.Error(err))
		return "", err
	}
	secret := strings.TrimSpace(string(bytePassword))
	if secret == "" {
		otelzap.Ctx(ctx).Warn("No input received for secret", zap.String("prompt", prompt))
	}
	return secret, nil
}

// PromptSecrets prompts the user for multiple hidden inputs (e.g., unseal keys).
func PromptSecrets(ctx context.Context, promptBase string, count int) ([]string, error) {

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		otelzap.Ctx(ctx).Error(" Cannot prompt for secret input: not a TTY")
		return nil, fmt.Errorf("secret prompt failed: no terminal available")
	}

	secrets := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		prompt := fmt.Sprintf("%s %d", promptBase, i)
		secret, err := PromptSecret(ctx, prompt)
		if err != nil {
			return nil, fmt.Errorf("error reading %s: %w", prompt, err)
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

// PromptSelect displays numbered options and returns the selected value by index.
func PromptSelect(ctx context.Context, prompt string, options []string) string {
	otelzap.Ctx(ctx).Info(" Prompting selection", zap.String("prompt", prompt), zap.Int("num_options", len(options)))

	logger := otelzap.Ctx(ctx)
	logger.Info(" Displaying selection menu", zap.String("prompt", prompt), zap.Strings("options", options))

	// Use os.Stderr for user-facing prompts to preserve stdout for automation
	_, _ = fmt.Fprintln(os.Stderr, prompt)
	for i, option := range options {
		_, _ = fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, option)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		choice, err := ReadLine(ctx, reader, EnterChoicePrompt)
		if err != nil {
			otelzap.Ctx(ctx).Error("Failed to read choice", zap.Error(err))
			continue
		}

		idx, err := strconv.Atoi(choice)
		if err == nil && idx >= 1 && idx <= len(options) {
			otelzap.Ctx(ctx).Info(" User selected option", zap.Int("index", idx), zap.String("value", options[idx-1]))
			return options[idx-1]
		}

		logger := otelzap.Ctx(ctx)
		logger.Warn(" Invalid selection", zap.String("input", choice))
		_, _ = fmt.Fprintln(os.Stderr, "Invalid selection. Please try again.")
	}
}

// PromptYesNo asks a yes/no question and returns true/false. Falls back to default if unknown.
func PromptYesNo(ctx context.Context, prompt string, defaultYes bool) bool {
	defPrompt := DefaultYesPrompt
	if !defaultYes {
		defPrompt = DefaultNoPrompt
	}
	label := fmt.Sprintf("%s [%s]", prompt, defPrompt)

	reader := bufio.NewReader(os.Stdin)
	input, err := ReadLine(ctx, reader, label)
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to read yes/no input", zap.Error(err))
		return defaultYes
	}

	if answer, ok := NormalizeYesNoInput(input); ok {
		otelzap.Ctx(ctx).Info(" User input parsed", zap.Bool("answer", answer))
		return answer
	}

	otelzap.Ctx(ctx).Info(" Default applied", zap.String("prompt", prompt), zap.Bool("default_yes", defaultYes))
	return defaultYes
}

// PromptConfirmOrValue asks the user to accept a default or enter a custom value.
func PromptConfirmOrValue(ctx context.Context, prompt, defaultValue string) string {
	if PromptYesNo(ctx, fmt.Sprintf("%s (default: %s)?", prompt, defaultValue), true) {
		otelzap.Ctx(ctx).Info(" Default value confirmed", zap.String("value", defaultValue))
		return defaultValue
	}

	reader := bufio.NewReader(os.Stdin)
	input, err := ReadLine(ctx, reader, "Enter value")
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to read custom value", zap.Error(err))
		return defaultValue
	}
	otelzap.Ctx(ctx).Info(" Custom value entered", zap.String("value", input))
	return input
}

// PromptInput asks for user input with an optional default fallback.
// Logs input events; falls back to default value if input is empty.
func PromptInput(ctx context.Context, prompt, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)
	input, err := ReadLine(ctx, reader, prompt)
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to read user input", zap.Error(err))
		return defaultVal
	}
	if input == "" {
		otelzap.Ctx(ctx).Debug(" Using default value", zap.String("default", defaultVal))
		return defaultVal
	}
	return input
}

// NormalizeYesNoInput returns true if the provided input string is an affirmative response like "y" or "yes".
// It trims whitespace and lowercases input before comparison.
func NormalizeYesNoInput(input string) (bool, bool) {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "y" || input == "yes" {
		return true, true
	}
	if input == "n" || input == "no" {
		return false, true
	}
	return false, false // unknown
}

func PromptInputWithReader(ctx context.Context, prompt, defaultVal string, reader *bufio.Reader) string {
	input, err := ReadLine(ctx, reader, prompt)
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to read user input", zap.Error(err))
		return defaultVal
	}
	if input == "" {
		otelzap.Ctx(ctx).Debug(" Using default value", zap.String("default", defaultVal))
		return defaultVal
	}
	return input
}

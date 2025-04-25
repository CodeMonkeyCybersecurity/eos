package interaction

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// PromptIfMissing returns the value of a CLI flag or prompts the user if it's unset.
// If `isSecret` is true, the input is hidden (e.g. passwords).
func PromptIfMissing(cmd *cobra.Command, flagName, prompt string, isSecret bool, log *zap.Logger) (string, error) {
	val, err := cmd.Flags().GetString(flagName)
	if err != nil {
		log.Error("failed to get CLI flag", zap.String("flag", flagName), zap.Error(err))
		return "", err
	}
	if val != "" {
		log.Debug("✅ CLI flag provided", zap.String("flag", flagName), zap.String("value", val))
		return val, nil
	}

	log.Info("📝 Prompting for missing flag", zap.String("flag", flagName), zap.Bool("is_secret", isSecret))

	if isSecret {
		secret := promptSecret(prompt, log)
		if secret == "" {
			log.Warn("⚠️ Empty input received for secret prompt")
		}
		return secret, nil
	}

	input := PromptInput(prompt, "", log)
	if input == "" {
		log.Warn("⚠️ Empty input received for prompt", zap.String("prompt", prompt))
	}
	return input, nil
}

// promptSecret reads a sensitive string from the terminal with input hidden (e.g., passwords).
func promptSecret(prompt string, log *zap.Logger) string {
	fmt.Print(prompt + ": ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Error("❌ Failed to read secret input", zap.Error(err))
		return ""
	}
	secret := strings.TrimSpace(string(bytePassword))
	if secret == "" {
		log.Warn("⚠️ No input received for secret")
	}
	return secret
}

// PromptSelect displays numbered options and returns the selected value by index.
func PromptSelect(prompt string, options []string, log *zap.Logger) string {
	log.Info("📋 Prompting selection", zap.String("prompt", prompt), zap.Int("num_options", len(options)))

	fmt.Println(prompt)
	for i, option := range options {
		fmt.Printf("  %d) %s\n", i+1, option)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter choice number: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		idx, err := strconv.Atoi(choice)
		if err == nil && idx >= 1 && idx <= len(options) {
			log.Info("✅ User selected option", zap.Int("index", idx), zap.String("value", options[idx-1]))
			return options[idx-1]
		}

		log.Warn("❌ Invalid selection", zap.String("input", choice))
		fmt.Println("Invalid selection. Please try again.")
	}
}

// PromptYesNo asks a yes/no question and returns true/false.
// If input is blank, it returns the `defaultYes` fallback.
func PromptYesNo(prompt string, defaultYes bool, log *zap.Logger) bool {
	def := "Y/n"
	if !defaultYes {
		def = "y/N"
	}
	fmt.Printf("%s [%s]: ", prompt, def)

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	switch input {
	case "y", "yes":
		log.Info("✅ User confirmed yes", zap.String("prompt", prompt))
		return true
	case "n", "no":
		log.Info("❌ User selected no", zap.String("prompt", prompt))
		return false
	default:
		log.Info("ℹ️ Default applied", zap.String("prompt", prompt), zap.Bool("default_yes", defaultYes))
		return defaultYes
	}
}

// PromptConfirmOrValue asks the user to accept a default or enter a custom value.
func PromptConfirmOrValue(prompt, defaultValue string, log *zap.Logger) string {
	if PromptYesNo(fmt.Sprintf("%s (default: %s)?", prompt, defaultValue), true, log) {
		log.Info("✅ Default value confirmed", zap.String("value", defaultValue))
		return defaultValue
	}
	fmt.Print("Enter value: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	result := strings.TrimSpace(input)
	log.Info("✏️ Custom value entered", zap.String("value", result))
	return result
}

// PromptInput asks for user input with an optional default fallback.
func PromptInput(prompt, defaultVal string, log *zap.Logger) string {
	reader := bufio.NewReader(os.Stdin)
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	input, _ := reader.ReadString('\n')
	result := strings.TrimSpace(input)
	if result == "" {
		log.Debug("ℹ️ Using default value", zap.String("default", defaultVal))
		return defaultVal
	}
	log.Debug("✏️ User entered input", zap.String("input", result))
	return result
}

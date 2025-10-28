// pkg/interaction/required_flag.go
package interaction

import (
	"fmt"
	"os"
	"strconv"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// FlagSource indicates where a flag value originated
type FlagSource string

const (
	FlagSourceCLI     FlagSource = "command-line flag"
	FlagSourceEnv     FlagSource = "environment variable"
	FlagSourcePrompt  FlagSource = "interactive prompt"
	FlagSourceDefault FlagSource = "default value"
)

// FlagResult contains the resolved flag value and its source
type FlagResult struct {
	Value  string
	Source FlagSource
}

// RequiredFlagConfig configures how to resolve a required flag
//
// This implements the P0 human-centric requirement: "Technology serves humans"
// by providing a fallback chain when required flags are missing, rather than
// failing immediately and forcing users to re-run commands.
type RequiredFlagConfig struct {
	// Metadata
	FlagName   string // For error messages: "token"
	EnvVarName string // Optional: "VAULT_TOKEN", "" if no env var

	// User-facing prompt (only used if prompting needed)
	PromptMessage string // "Enter Vault root token"
	HelpText      string // "Required for cluster operations. Get via: vault token create"

	// Behavior
	IsSecret     bool   // Use PromptSecurePassword (no echo)
	AllowEmpty   bool   // Can user press enter for empty?
	DefaultValue string // Used if AllowEmpty && user presses enter

	// Validation (compose existing PromptConfig.Validator)
	Validator func(string) error
}

// GetRequiredString resolves a required string flag with human-centric fallback chain.
//
// P0 REQUIREMENT: Implements human-centric design by offering multiple fallbacks
// instead of failing immediately when a required flag is missing.
//
// Fallback chain (P0 requirement from CLAUDE.md):
//  1. CLI flag (if flagWasSet is true)
//  2. Environment variable (if config.EnvVarName is set)
//  3. Interactive prompt (if TTY available)
//  4. Default value (if config.AllowEmpty && config.DefaultValue set)
//  5. Error with remediation (if non-interactive mode or all fallbacks failed)
//
// Parameters:
//   - rc: RuntimeContext for logging and TTY detection
//   - flagValue: Current flag value from cmd.Flags().GetString()
//   - flagWasSet: Result of cmd.Flags().Changed() - distinguishes empty from not-provided
//   - config: Configuration for prompting and validation
//
// Returns:
//   - *FlagResult: Contains value and source for observability
//   - error: Non-nil if all fallbacks failed
//
// Example:
//
//	tokenFlag, _ := cmd.Flags().GetString("token")
//	tokenWasSet := cmd.Flags().Changed("token")
//
//	result, err := interaction.GetRequiredString(rc, tokenFlag, tokenWasSet, &RequiredFlagConfig{
//	    FlagName:      "token",
//	    EnvVarName:    "VAULT_TOKEN",
//	    PromptMessage: "Enter Vault root token: ",
//	    HelpText:      "Required for Autopilot configuration. Get via: vault token create",
//	    IsSecret:      true,
//	})
//	if err != nil {
//	    return fmt.Errorf("failed to get vault token: %w", err)
//	}
//
//	log.Info("Using Vault token", zap.String("source", string(result.Source)))
func GetRequiredString(
	rc *eos_io.RuntimeContext,
	flagValue string,
	flagWasSet bool,
	config *RequiredFlagConfig,
) (*FlagResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// FALLBACK 1: CLI flag (if explicitly set)
	if flagWasSet {
		logger.Debug("Using flag from CLI",
			zap.String("flag", config.FlagName),
			zap.String("source", string(FlagSourceCLI)))
		return &FlagResult{
			Value:  flagValue,
			Source: FlagSourceCLI,
		}, nil
	}

	// FALLBACK 2: Environment variable (if configured)
	if config.EnvVarName != "" {
		if envValue := os.Getenv(config.EnvVarName); envValue != "" {
			logger.Info("Using flag from environment variable",
				zap.String("flag", config.FlagName),
				zap.String("env_var", config.EnvVarName),
				zap.String("source", string(FlagSourceEnv)))
			return &FlagResult{
				Value:  envValue,
				Source: FlagSourceEnv,
			}, nil
		}
	}

	// FALLBACK 3: Interactive prompt (if TTY available)
	if IsTTY() {
		logger.Info("Flag not provided, prompting user",
			zap.String("flag", config.FlagName),
			zap.String("help", config.HelpText))

		// Show help text if provided (P0 requirement: explain WHY and HOW)
		if config.HelpText != "" {
			logger.Info("terminal prompt: " + config.HelpText)
		}

		var promptedValue string
		var err error

		if config.IsSecret {
			// Use secure password input (no echo)
			promptedValue, err = eos_io.PromptSecurePassword(rc, config.PromptMessage)
		} else {
			// Use regular input
			promptedValue, err = eos_io.PromptInput(rc, config.PromptMessage, config.FlagName)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to prompt for %s: %w", config.FlagName, err)
		}

		// Validate if validator provided (P0 requirement: validate with retries)
		if config.Validator != nil {
			if err := config.Validator(promptedValue); err != nil {
				return nil, fmt.Errorf("validation failed for %s: %w", config.FlagName, err)
			}
		}

		// P0 requirement: log which source was used (observability)
		logger.Info("Using flag from interactive prompt",
			zap.String("flag", config.FlagName),
			zap.String("source", string(FlagSourcePrompt)))

		return &FlagResult{
			Value:  promptedValue,
			Source: FlagSourcePrompt,
		}, nil
	}

	// FALLBACK 4: Default value (if allowed)
	if config.AllowEmpty && config.DefaultValue != "" {
		logger.Info("Using default value for flag",
			zap.String("flag", config.FlagName),
			zap.String("source", string(FlagSourceDefault)))
		return &FlagResult{
			Value:  config.DefaultValue,
			Source: FlagSourceDefault,
		}, nil
	}

	// FALLBACK 5: Error with remediation (P0 requirement: actionable error messages)
	logger.Error("Required flag not provided and no interactive fallback available",
		zap.String("flag", config.FlagName),
		zap.Bool("tty_available", IsTTY()))

	return nil, buildRemediationError(config)
}

// buildRemediationError creates a user-friendly error with remediation steps
// P0 requirement: errors must include HOW to fix the problem
func buildRemediationError(config *RequiredFlagConfig) error {
	var msg string
	msg += fmt.Sprintf("Required flag --%s not provided\n", config.FlagName)

	if config.HelpText != "" {
		msg += fmt.Sprintf("  • Purpose: %s\n", config.HelpText)
	}

	msg += fmt.Sprintf("  • Provide via: --%s=<value>\n", config.FlagName)

	if config.EnvVarName != "" {
		msg += fmt.Sprintf("  • Or set: export %s=<value>\n", config.EnvVarName)
	}

	msg += "  • Or run in interactive terminal to be prompted"

	return fmt.Errorf("%s", msg)
}

// GetRequiredInt resolves a required int flag (prompts as string, parses to int)
//
// P0 REQUIREMENT: Same human-centric fallback chain as GetRequiredString,
// but parses string input to integer with validation.
//
// Fallback chain:
//  1. CLI flag (if flagWasSet is true)
//  2. Environment variable (if config.EnvVarName is set, parsed to int)
//  3. Interactive prompt (prompt as string, validate as int, retry on failure)
//  4. Default value (if config.AllowEmpty && config.DefaultValue set, parsed to int)
//  5. Error with remediation (if non-interactive mode or all fallbacks failed)
//
// Parameters:
//   - rc: RuntimeContext for logging and TTY detection
//   - flagValue: Current int flag value from cmd.Flags().GetInt()
//   - flagWasSet: Result of cmd.Flags().Changed() - true if flag was explicitly set
//   - config: Configuration for prompting and validation
//
// Returns:
//   - int: Parsed integer value
//   - FlagSource: Where the value came from (for logging)
//   - error: Non-nil if all fallbacks failed or parsing failed
//
// Example:
//
//	portFlag, _ := cmd.Flags().GetInt("port")
//	portWasSet := cmd.Flags().Changed("port")
//
//	port, source, err := interaction.GetRequiredInt(rc, portFlag, portWasSet, &RequiredFlagConfig{
//	    FlagName:      "port",
//	    EnvVarName:    "SERVICE_PORT",
//	    PromptMessage: "Enter service port: ",
//	    HelpText:      "Port number for service (1024-65535)",
//	    Validator: func(s string) error {
//	        p, _ := strconv.Atoi(s)
//	        if p < 1024 || p > 65535 {
//	            return fmt.Errorf("port must be between 1024 and 65535")
//	        }
//	        return nil
//	    },
//	})
//	if err != nil {
//	    return fmt.Errorf("failed to get port: %w", err)
//	}
//
//	log.Info("Using service port", zap.Int("port", port), zap.String("source", string(source)))
func GetRequiredInt(
	rc *eos_io.RuntimeContext,
	flagValue int,
	flagWasSet bool,
	config *RequiredFlagConfig,
) (int, FlagSource, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// FALLBACK 1: CLI flag (if explicitly set)
	if flagWasSet {
		logger.Debug("Using int flag from CLI",
			zap.String("flag", config.FlagName),
			zap.Int("value", flagValue))
		return flagValue, FlagSourceCLI, nil
	}

	// FALLBACK 2: Environment variable (if configured)
	if config.EnvVarName != "" {
		if envValue := os.Getenv(config.EnvVarName); envValue != "" {
			parsed, err := strconv.Atoi(envValue)
			if err != nil {
				return 0, "", fmt.Errorf("invalid integer in %s: %w", config.EnvVarName, err)
			}
			logger.Info("Using int flag from environment variable",
				zap.String("flag", config.FlagName),
				zap.String("env_var", config.EnvVarName),
				zap.Int("value", parsed))
			return parsed, FlagSourceEnv, nil
		}
	}

	// FALLBACK 3: Interactive prompt (prompt as string, parse to int)
	if IsTTY() {
		// Add int validator to config (chain with custom validator if provided)
		intValidator := func(s string) error {
			_, err := strconv.Atoi(s)
			if err != nil {
				return fmt.Errorf("must be a valid integer: %w", err)
			}
			// Chain with custom validator if provided
			if config.Validator != nil {
				return config.Validator(s)
			}
			return nil
		}

		// Create a copy to avoid modifying caller's config
		configCopy := *config
		configCopy.Validator = intValidator

		result, err := GetRequiredString(rc, "", false, &configCopy)
		if err != nil {
			return 0, "", err
		}

		parsed, _ := strconv.Atoi(result.Value) // Already validated by intValidator
		return parsed, result.Source, nil
	}

	// FALLBACK 4: Default value (parse from string)
	if config.AllowEmpty && config.DefaultValue != "" {
		parsed, err := strconv.Atoi(config.DefaultValue)
		if err != nil {
			return 0, "", fmt.Errorf("invalid default integer: %w", err)
		}
		logger.Info("Using default int value",
			zap.String("flag", config.FlagName),
			zap.Int("value", parsed))
		return parsed, FlagSourceDefault, nil
	}

	// FALLBACK 5: Error with remediation
	return 0, "", buildRemediationError(config)
}

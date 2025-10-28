package eos_io

import (
	"fmt"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// PromptForConsent asks the user for yes/no consent with a custom prompt
func PromptForConsent(rc *RuntimeContext, prompt string, defaultNo bool) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Format the prompt with [y/N] or [Y/n] based on default
	var fullPrompt string
	if defaultNo {
		fullPrompt = fmt.Sprintf("%s [y/N]: ", prompt)
	} else {
		fullPrompt = fmt.Sprintf("%s [Y/n]: ", prompt)
	}

	logger.Info("terminal prompt: " + fullPrompt)

	// Read user input
	response, err := ReadInput(rc)
	if err != nil {
		return false, fmt.Errorf("failed to read user input: %w", err)
	}

	// Normalize response
	response = strings.ToLower(strings.TrimSpace(response))

	// Handle empty response (use default)
	if response == "" {
		return !defaultNo, nil
	}

	// STRICT VALIDATION: Only accept y/yes/n/no (aligns with interaction/input.go and standard CLI tools)
	// BREAKING CHANGE (2025-01-28): Removed "yeah", "ok", "sure", "nope", "nah" for consistency
	// Rationale: Matches git/apt/npm behavior, aligns with documented policy (input_test.go:170)
	switch response {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		// Invalid response, ask again
		logger.Info("terminal prompt: Please answer 'yes' or 'no'")
		return PromptForConsent(rc, prompt, defaultNo)
	}
}

// PromptForInstallation asks for consent to install a specific software
func PromptForInstallation(rc *RuntimeContext, software, description string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Build detailed prompt
	var prompt strings.Builder
	prompt.WriteString(fmt.Sprintf("\nAbout to install %s", software))
	if description != "" {
		prompt.WriteString(fmt.Sprintf(" (%s)", description))
	}
	prompt.WriteString("\n\nThis will:")
	prompt.WriteString("\n  • Download and install the latest version")
	prompt.WriteString("\n  • Create necessary system users and directories")
	prompt.WriteString("\n  • Configure systemd services")
	prompt.WriteString("\n  • May modify system configuration files")
	prompt.WriteString("\n\nDo you want to proceed?")

	logger.Info("terminal prompt: " + prompt.String())

	return PromptForConsent(rc, "Install "+software+"?", true)
}

// PromptForDependency asks for consent to install a missing dependency
func PromptForDependency(rc *RuntimeContext, dependency, description, requiredBy string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Build detailed prompt
	var prompt strings.Builder
	prompt.WriteString(fmt.Sprintf("\n%s is required by %s but not installed", dependency, requiredBy))
	if description != "" {
		prompt.WriteString(fmt.Sprintf("\n%s: %s", dependency, description))
	}
	prompt.WriteString(fmt.Sprintf("\n\nWould you like to install %s now?", dependency))

	logger.Info("terminal prompt: " + prompt.String())

	return PromptForConsent(rc, fmt.Sprintf("Install %s?", dependency), true)
}

// PromptForServiceAction asks for consent to start/stop/restart a service
func PromptForServiceAction(rc *RuntimeContext, service, action string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	prompt := fmt.Sprintf("\nThe %s service needs to be %sed", service, action)

	logger.Info("terminal prompt: " + prompt)

	// Capitalize first letter only (strings.Title is deprecated)
	actionCapitalized := action
	if len(action) > 0 && action[0] >= 'a' && action[0] <= 'z' {
		actionCapitalized = string(action[0]-32) + action[1:]
	}
	return PromptForConsent(rc, fmt.Sprintf("%s %s service?", actionCapitalized, service), false)
}

// PromptToContinueDespiteErrors asks if user wants to continue despite errors
func PromptToContinueDespiteErrors(rc *RuntimeContext, errorCount int, context string) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var prompt strings.Builder
	if errorCount == 1 {
		prompt.WriteString("\n  An error occurred")
	} else {
		prompt.WriteString(fmt.Sprintf("\n  %d errors occurred", errorCount))
	}

	if context != "" {
		prompt.WriteString(fmt.Sprintf(" during %s", context))
	}

	prompt.WriteString("\n\nContinuing may result in an incomplete or non-functional installation")

	logger.Info("terminal prompt: " + prompt.String())

	return PromptForConsent(rc, "Continue anyway?", true)
}

// pkg/bionicgpt_nomad/interactive.go
package bionicgpt_nomad

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PromptForMissingConfig interactively prompts for missing configuration values
// Returns updated config or error if user cancels or non-interactive mode
func PromptForMissingConfig(rc *eos_io.RuntimeContext, config *EnterpriseConfig) (*EnterpriseConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if interactive mode is possible
	if !interaction.IsTTY() {
		return nil, fmt.Errorf("cannot prompt in non-interactive mode")
	}

	logger.Info("Starting interactive configuration")
	printHeader(rc)

	// Prompt for each missing field
	if config.Domain == "" {
		domain, err := promptForDomain(rc)
		if err != nil {
			return nil, fmt.Errorf("domain prompt failed: %w", err)
		}
		config.Domain = domain
	}

	if config.CloudNode == "" {
		cloudNode, err := promptForCloudNode(rc)
		if err != nil {
			return nil, fmt.Errorf("cloud node prompt failed: %w", err)
		}
		config.CloudNode = cloudNode
	}

	if config.AuthURL == "" {
		authURL, err := promptForAuthURL(rc)
		if err != nil {
			return nil, fmt.Errorf("auth URL prompt failed: %w", err)
		}
		config.AuthURL = authURL
	}

	// Show summary and confirm
	confirmed, err := showConfigurationSummary(rc, config)
	if err != nil {
		return nil, fmt.Errorf("confirmation failed: %w", err)
	}

	if !confirmed {
		return nil, fmt.Errorf("deployment cancelled by user")
	}

	logger.Info("Interactive configuration completed successfully",
		zap.String("domain", config.Domain),
		zap.String("cloud_node", config.CloudNode))

	return config, nil
}

// printHeader displays the interactive mode header
func printHeader(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	// P0 COMPLIANCE: Use structured logging instead of fmt.Print*
	// Use ASCII art instead of emojis for compatibility
	logger.Info("")
	logger.Info("┌────────────────────────────────────────┐")
	logger.Info("│  BionicGPT Configuration               │")
	logger.Info("└────────────────────────────────────────┘")
	logger.Info("")
	logger.Info("Missing required configuration. Let's set it up!")
	logger.Info("")
}

// promptForDomain prompts for the public domain
func promptForDomain(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// P0 COMPLIANCE: Use structured logging instead of fmt.Print*
	logger.Info("=== Public Domain ===")
	logger.Info("Where users will access BionicGPT")
	logger.Info("Example: chat.example.com")
	logger.Info("")

	result, err := interaction.PromptString(rc, &interaction.PromptConfig{
		Message:   "Domain",
		HelpText:  "Public FQDN where BionicGPT will be accessible",
		Validator: interaction.ValidateDomainStrict,
	})

	if err != nil {
		return "", err
	}

	if result.Cancelled || result.TimedOut {
		return "", fmt.Errorf("domain prompt cancelled")
	}

	logger.Info("")
	return result.Value, nil
}

// promptForCloudNode prompts for the cloud node hostname
func promptForCloudNode(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// P0 COMPLIANCE: Use structured logging instead of fmt.Print*
	logger.Info("=== Cloud Node ===")
	logger.Info("Tailscale hostname where Hecate/Authentik run")

	// Try to get current hostname as suggestion (NOT default)
	currentHostname, _ := os.Hostname()
	if currentHostname != "" {
		logger.Info(fmt.Sprintf("Current hostname: %s (suggestion, not auto-selected)", currentHostname))
	}
	logger.Info("")

	// NOTE: Do NOT use currentHostname as default - user must explicitly choose
	result, err := interaction.PromptString(rc, &interaction.PromptConfig{
		Message:   "Cloud node",
		HelpText:  "Tailscale hostname for Hecate reverse proxy",
		Validator: interaction.ValidateHostnameStrict,
	})

	if err != nil {
		return "", err
	}

	if result.Cancelled || result.TimedOut {
		return "", fmt.Errorf("cloud node prompt cancelled")
	}

	logger.Info("")
	return result.Value, nil
}

// promptForAuthURL prompts for the Authentik URL
func promptForAuthURL(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// P0 COMPLIANCE: Use structured logging instead of fmt.Print*
	logger.Info("=== Authentik URL ===")
	logger.Info("Your SSO authentication server")
	logger.Info("Example: https://auth.example.com")
	logger.Info("")

	result, err := interaction.PromptString(rc, &interaction.PromptConfig{
		Message:   "Authentik URL",
		HelpText:  "HTTPS URL of your Authentik instance",
		Validator: interaction.ValidateURL,
	})

	if err != nil {
		return "", err
	}

	if result.Cancelled || result.TimedOut {
		return "", fmt.Errorf("auth URL prompt cancelled")
	}

	logger.Info("")
	return result.Value, nil
}

// showConfigurationSummary displays the configuration and asks for confirmation
func showConfigurationSummary(rc *eos_io.RuntimeContext, config *EnterpriseConfig) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// P0 COMPLIANCE: Use structured logging instead of fmt.Print* (fixes P0 violation)
	logger.Info("=== Configuration Summary ===")
	logger.Info("────────────────────────────────")
	logger.Info(fmt.Sprintf("  Domain:      %s", config.Domain))
	logger.Info(fmt.Sprintf("  Cloud Node:  %s", config.CloudNode))
	logger.Info(fmt.Sprintf("  Auth URL:    %s", config.AuthURL))
	logger.Info(fmt.Sprintf("  Embeddings:  Local (Ollama %s)", config.LocalEmbeddingsModel))
	logger.Info("")

	// Confirm deployment with user
	proceed, err := interaction.PromptYesNoSafe(rc, "Deploy with this configuration?", true)
	if err != nil {
		return false, fmt.Errorf("failed to get user confirmation: %w", err)
	}

	return proceed, nil
}

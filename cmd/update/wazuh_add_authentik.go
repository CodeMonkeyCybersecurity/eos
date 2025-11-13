// cmd/update/wazuh_add_authentik.go - Command handler for 'eos update wazuh --add authentik'
// ORCHESTRATION ONLY - all business logic in pkg/wazuh/sso/

package update

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/sso"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WazuhAddAuthentikCmd configures Wazuh SSO with Authentik SAML
var WazuhAddAuthentikCmd = &cobra.Command{
	Use:   "authentik",
	Short: "Configure Wazuh SSO with Authentik SAML (run on Wazuh server)",
	Long: `Configure Wazuh SSO with Authentik SAML authentication.

This command configures the Wazuh side (Service Provider) of the SAML integration.
It should be run ON THE WAZUH SERVER after running 'eos update hecate add wazuh' on the reverse proxy.

What this command does:
  1. Retrieves SAML metadata from Consul KV (or directly from Authentik API)
  2. Generates/retrieves SAML exchange key
  3. Configures OpenSearch Security for SAML authentication
  4. Maps Authentik groups to Wazuh roles
  5. Restarts Wazuh services

Prerequisites:
  - Wazuh installed and running (eos create wazuh)
  - Authentik SAML provider configured (eos update hecate add wazuh --dns wazuh.domain.com)
  - Consul agent running (for metadata retrieval)

Examples:
  # Using metadata from Consul KV (recommended):
  eos update wazuh --add authentik \
    --wazuh-url https://wazuh.codemonkey.ai

  # Fetching metadata directly from Authentik API:
  eos update wazuh --add authentik \
    --authentik-url https://hera.codemonkey.ai \
    --wazuh-url https://wazuh.codemonkey.ai

  # Dry run (show what would be done):
  eos update wazuh --add authentik \
    --wazuh-url https://wazuh.codemonkey.ai \
    --dry-run

Role mappings created:
  - wazuh-admin    → all_access (full administrator)
  - wazuh-analysts → kibana_user (read/analyze)
  - wazuh-readonly → readall (read-only access)

For more information: https://docs.codemonkey.ai/eos/wazuh-sso`,
	RunE: eos_cli.Wrap(runWazuhAddAuthentik),
}

func init() {
	// Register as subcommand of 'eos update wazuh --add'
	// This will be called via: eos update wazuh --add authentik

	// Flags
	WazuhAddAuthentikCmd.Flags().String("authentik-url", "", "Authentik base URL (e.g., https://hera.codemonkey.ai)")
	WazuhAddAuthentikCmd.Flags().String("wazuh-url", "", "Public Wazuh dashboard URL (e.g., https://wazuh.codemonkey.ai)")
	WazuhAddAuthentikCmd.Flags().String("entity-id", "wazuh-saml", "SAML entity ID (default: wazuh-saml)")
	WazuhAddAuthentikCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
}

func runWazuhAddAuthentik(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring Wazuh SSO with Authentik SAML")
	logger.Info("This command runs ON THE WAZUH SERVER to configure the Service Provider (SP) side")
	logger.Info("")

	// Parse flags into options struct
	opts, err := parseWazuhAddAuthentikFlags(rc, cmd)
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	// Delegate to business logic
	if err := sso.Configure(rc, opts); err != nil {
		return fmt.Errorf("SSO configuration failed: %w", err)
	}

	return nil
}

// parseWazuhAddAuthentikFlags parses command flags into ConfigureOptions
// Uses interaction.GetRequiredString() for human-centric flag handling
func parseWazuhAddAuthentikFlags(rc *eos_io.RuntimeContext, cmd *cobra.Command) (*sso.ConfigureOptions, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get dry-run flag
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Get entity ID (optional, has default)
	entityID, _ := cmd.Flags().GetString("entity-id")
	if entityID == "" {
		entityID = "wazuh-saml"
	}

	// Get Authentik URL (optional - can be fetched from Consul KV)
	authentikURL, _ := cmd.Flags().GetString("authentik-url")
	authentikURLWasSet := cmd.Flags().Changed("authentik-url")

	// If not set, try environment variable
	if !authentikURLWasSet {
		if envURL := os.Getenv("AUTHENTIK_URL"); envURL != "" {
			logger.Info("Using AUTHENTIK_URL from environment", zap.String("url", envURL))
			authentikURL = envURL
		}
	}

	// If still not set, try Consul KV
	if authentikURL == "" {
		logger.Info("Authentik URL not provided - will attempt to use metadata from Consul KV")
		logger.Info("If Consul KV lookup fails, you'll be prompted for the URL")
	}

	// Get Wazuh URL (required - P0 human-centric pattern)
	wazuhURL, _ := cmd.Flags().GetString("wazuh-url")
	wazuhURLWasSet := cmd.Flags().Changed("wazuh-url")

	// Use interaction.GetRequiredString() with fallback chain
	wazuhURLResult, err := interaction.GetRequiredString(rc, wazuhURL, wazuhURLWasSet, &interaction.RequiredFlagConfig{
		FlagName:      "wazuh-url",
		EnvVarName:    "WAZUH_URL",
		PromptMessage: "Enter public Wazuh dashboard URL (e.g., https://wazuh.codemonkey.ai): ",
		HelpText:      "This is the public URL where users access Wazuh dashboard. Used for SAML configuration.",
		IsSecret:      false,
		AllowEmpty:    false,
		Validator: func(value string) error {
			// Basic URL validation
			if value == "" {
				return fmt.Errorf("Wazuh URL cannot be empty")
			}
			// TODO: Add more URL validation if needed
			return nil
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get Wazuh URL: %w\n\n"+
			"Provide via:\n"+
			"  1. Flag: --wazuh-url https://wazuh.codemonkey.ai\n"+
			"  2. Environment variable: export WAZUH_URL=https://wazuh.codemonkey.ai\n"+
			"  3. Interactive prompt (if TTY available)", err)
	}

	wazuhURL = wazuhURLResult.Value
	logger.Info("Using Wazuh URL",
		zap.String("url", wazuhURL),
		zap.String("source", string(wazuhURLResult.Source)))

	return &sso.ConfigureOptions{
		AuthentikURL: authentikURL, // May be empty - will fetch from Consul KV
		WazuhURL:     wazuhURL,
		EntityID:     entityID,
		DryRun:       dryRun,
	}, nil
}

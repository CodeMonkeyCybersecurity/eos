package update

import (
	"bytes"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/sso"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	// Add subcommands to wazuh parent command (DEPRECATED - use --add flag instead)
	// This creates the structure: eos update wazuh [subcommand]
	SecureWazuhCmd.AddCommand(wazuhAddCmd)
	wazuhAddCmd.AddCommand(WazuhAddAuthentikCmd)

	// Add flag-based operations (PREFERRED)
	SecureWazuhCmd.Flags().String("add", "", "Add integration with another service (e.g., authentik)")

	// Flags for --add authentik
	SecureWazuhCmd.Flags().String("authentik-url", "", "Authentik base URL (e.g., https://hera.codemonkey.ai)")
	SecureWazuhCmd.Flags().String("wazuh-url", "", "Public Wazuh dashboard URL (e.g., https://wazuh.codemonkey.ai)")
	SecureWazuhCmd.Flags().String("entity-id", "wazuh-saml", "SAML entity ID (default: wazuh-saml)")
	SecureWazuhCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
}

// wazuhAddCmd is the parent command for 'eos update wazuh add [service]'
var wazuhAddCmd = &cobra.Command{
	Use:        "add [service]",
	Short:      "Add integration with another service (e.g., authentik for SSO)",
	Deprecated: "Use 'eos update wazuh --add [service]' instead. Subcommand syntax will be removed in v2.0 (approximately 6 months).",
	Long: `Add integration between Wazuh and another service.

Available integrations:
  authentik  - Configure Wazuh SSO with Authentik SAML

DEPRECATED: This subcommand syntax is deprecated. Use 'eos update wazuh --add [service]' instead.

Examples (DEPRECATED - use flag syntax instead):
  # Configure Wazuh SSO with Authentik
  eos update wazuh add authentik \
    --wazuh-url https://wazuh.codemonkey.ai

  # PREFERRED FLAG-BASED SYNTAX:
  eos update wazuh --add authentik \
    --wazuh-url https://wazuh.codemonkey.ai`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// DEPRECATION WARNING: Soft deprecation phase (v1.X)
		rc.Log.Warn("DEPRECATED: Subcommand syntax is deprecated and will be removed in v2.0",
			zap.String("current_syntax", "eos update wazuh add [service]"),
			zap.String("preferred_syntax", "eos update wazuh --add [service]"),
			zap.String("removal_version", "v2.0.0"),
			zap.String("timeline", "approximately 6 months"))

		// If no subcommand, show help
		_ = cmd.Help()
		return nil
	}),
}

// SecureWazuhCmd rotates Wazuh passwords & restarts services.
var SecureWazuhCmd = &cobra.Command{
	Use:   "wazuh",
	Short: "Harden Wazuh (Wazuh) by rotating passwords & updating configs",
	Long: `Harden Wazuh by rotating passwords and updating configurations.

Operations:
  --add     - Add integration with another service (flag-based, preferred)

Examples:
  # Rotate passwords
  eos update wazuh

  # Add Authentik SSO (PREFERRED FLAG SYNTAX)
  eos update wazuh --add authentik --wazuh-url https://wazuh.codemonkey.ai

  # Legacy subcommand syntax (DEPRECATED)
  eos update wazuh add authentik --wazuh-url https://wazuh.codemonkey.ai`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, _ []string) (err error) {
		// Check if --add flag is explicitly set
		addService, _ := cmd.Flags().GetString("add")
		addWasSet := cmd.Flags().Changed("add")

		if addWasSet {
			if addService == "" {
				return fmt.Errorf("--add requires a service name\nExample: eos update wazuh --add authentik --wazuh-url https://wazuh.codemonkey.ai")
			}
			// Delegate to add service flow
			return runWazuhAddFromFlag(rc, cmd, addService)
		}
		// ensure rc.End sees our err
		defer rc.End(&err)

		// 1) Download the rotation tool
		if err = wazuh.RotateWithTool(rc); err != nil {
			return
		}

		// 2) Fetch current Wazuh API password
		rc.Log.Info(" Extracting current Wazuh API password")
		var apiPass string
		if apiPass, err = wazuh.ExtractWazuhUserPassword(rc); err != nil {
			err = cerr.Wrapf(err, "extract Wazuh API password")
			return
		}

		// 3) Try primary rotation, else fallback
		out, rotateErr := wazuh.RunPrimary(rc, apiPass)
		if rotateErr != nil {
			rc.Log.Warn("Primary rotation failed, falling back", zap.Error(rotateErr))
			var newPass string
			if newPass, err = wazuh.RunFallback(rc); err != nil {
				return
			}
			out = bytes.NewBufferString(fmt.Sprintf(
				"The password for user wazuh is %s\n", newPass,
			))
		}

		// 4) Parse secrets & restart services
		secrets := wazuh.ParseSecrets(rc, out)
		if err = wazuh.RestartServices(rc, []string{
			"filebeat", "wazuh-manager", "wazuh-dashboard", "wazuh-indexer",
		}); err != nil {
			return
		}

		// 5) Store to Vault (non-fatal on failure)
		if storeErr := vault.HandleFallbackOrStore(rc, "wazuh", secrets); storeErr != nil {
			rc.Log.Warn("Failed to store secrets in Vault; continuing", zap.Error(storeErr))
		}

		rc.Log.Info(" Wazuh hardening complete")
		return
	}),
}

// runWazuhAddFromFlag handles adding integrations when --add flag is used
func runWazuhAddFromFlag(rc *eos_io.RuntimeContext, cmd *cobra.Command, service string) error {
	// Currently only "authentik" is supported
	if service != "authentik" {
		return fmt.Errorf("unsupported service: %s\nCurrently supported: authentik\nExample: eos update wazuh --add authentik --wazuh-url https://wazuh.codemonkey.ai", service)
	}

	// Parse flags - reuse the same logic as wazuh_add_authentik.go
	opts, err := parseWazuhAddAuthentikFlagsFromParent(rc, cmd)
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	// Delegate to business logic
	if err := sso.Configure(rc, opts); err != nil {
		return fmt.Errorf("SSO configuration failed: %w", err)
	}

	return nil
}

// parseWazuhAddAuthentikFlagsFromParent parses flags from parent command (flag-based invocation)
// This is nearly identical to parseWazuhAddAuthentikFlags in wazuh_add_authentik.go but reads from parent command
func parseWazuhAddAuthentikFlagsFromParent(rc *eos_io.RuntimeContext, cmd *cobra.Command) (*sso.ConfigureOptions, error) {
	logger := rc.Log

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

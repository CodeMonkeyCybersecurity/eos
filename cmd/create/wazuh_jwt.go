// cmd/wazuh/create/jwt.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// jwtCmd generates and stores a JWT token for Wazuh (Wazuh) API access
var jwtCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate and store a JWT token for Wazuh (Wazuh) API access",
	Long: `Generate and store a JWT token for Wazuh (Wazuh) API access.

This command authenticates with the Wazuh API and stores the JWT token
for subsequent API calls. The token is stored in the configuration file
for reuse.

Examples:
  eos create jwt                         # Generate JWT token
  eos create jwt --interactive           # Interactive mode with prompts`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		cfg, err := wazuh.ReadConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Config not found, prompting for values", zap.Error(err))
			cfg.FQDN = interaction.PromptInput(rc.Ctx, "Enter the Wazuh domain (eg. wazuh.domain.com)", "")
			cfg.APIUser = interaction.PromptInput(rc.Ctx, "Enter the API username (eg. wazuh-wui)", "")
			pw, err := crypto.PromptPassword(rc, "Enter the API password")
			if err != nil {
				otelzap.Ctx(rc.Ctx).Fatal("Failed to read password", zap.Error(err))
			}
			cfg.APIPassword = pw
			if err := wazuh.WriteConfig(rc, cfg); err != nil {
				otelzap.Ctx(rc.Ctx).Fatal("Error saving configuration", zap.Error(err))
			}
			otelzap.Ctx(rc.Ctx).Info("Configuration file created.")
		}

		cfg, err = wazuh.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Wazuh config", zap.Error(err))
		}

		if cfg.Protocol == "" {
			cfg.Protocol = "https"
		}
		if cfg.Port == "" {
			cfg.Port = "55000"
		}

		if err := wazuh.WriteConfig(rc, cfg); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to write config", zap.Error(err))
		}

		otelzap.Ctx(rc.Ctx).Info("Retrieving JWT token...")
		token, err := wazuh.Authenticate(rc, cfg)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Authentication failed", zap.Error(err))
		}
		cfg.Token = token
		if err := wazuh.WriteConfig(rc, cfg); err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to save token", zap.Error(err))
		}

		// SECURITY: Don't log full JWT token - only log confirmation and prefix
		tokenPrefix := "***"
		if len(token) > 8 {
			tokenPrefix = token[:8] + "..."
		}
		otelzap.Ctx(rc.Ctx).Info("JWT token retrieved successfully", zap.String("token_prefix", tokenPrefix))
		return nil
	}),
}

func init() {
	// Register jwtCmd with CreateCmd
	CreateCmd.AddCommand(jwtCmd)
}

// cmd/delphi/create/jwt.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate and store a JWT token for Delphi (Wazuh) API access",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		cfg, err := delphi.ReadConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Config not found, prompting for values", zap.Error(err))
			cfg.FQDN = interaction.PromptInput(rc.Ctx, "Enter the Wazuh domain (eg. delphi.domain.com)", "")
			cfg.APIUser = interaction.PromptInput(rc.Ctx, "Enter the API username (eg. wazuh-wui)", "")
			pw, err := crypto.PromptPassword(rc, "Enter the API password")
			if err != nil {
				otelzap.Ctx(rc.Ctx).Fatal("Failed to read password", zap.Error(err))
			}
			cfg.APIPassword = pw
			if err := delphi.WriteConfig(rc, cfg); err != nil {
				otelzap.Ctx(rc.Ctx).Fatal("Error saving configuration", zap.Error(err))
			}
			otelzap.Ctx(rc.Ctx).Info("Configuration file created.")
		}

		cfg, err = delphi.ResolveConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Delphi config", zap.Error(err))
		}

		if cfg.Protocol == "" {
			cfg.Protocol = "https"
		}
		if cfg.Port == "" {
			cfg.Port = "55000"
		}

		if err := delphi.WriteConfig(rc, cfg); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to write config", zap.Error(err))
		}

		otelzap.Ctx(rc.Ctx).Info("Retrieving JWT token...")
		token, err := delphi.Authenticate(rc, cfg)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Authentication failed", zap.Error(err))
		}
		cfg.Token = token
		if err := delphi.WriteConfig(rc, cfg); err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to save token", zap.Error(err))
		}

		otelzap.Ctx(rc.Ctx).Info("JWT token retrieved successfully", zap.String("token", token))
		return nil
	}),
}

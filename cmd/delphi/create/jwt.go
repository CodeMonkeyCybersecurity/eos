// cmd/delphi/create/jwt.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate and store a JWT token for Delphi (Wazuh) API access",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		cfg, err := delphi.ReadConfig()
		if err != nil {
			zap.L().Warn("Config not found, prompting for values", zap.Error(err))
			cfg.FQDN = interaction.PromptInput("Enter the Wazuh domain (eg. delphi.domain.com)", "")
			cfg.APIUser = interaction.PromptInput("Enter the API username (eg. wazuh-wui)", "")
			pw, err := crypto.PromptPassword("Enter the API password")
			if err != nil {
				zap.L().Fatal("Failed to read password", zap.Error(err))
			}
			cfg.APIPassword = pw
			if err := delphi.WriteConfig(cfg); err != nil {
				zap.L().Fatal("Error saving configuration", zap.Error(err))
			}
			zap.L().Info("Configuration file created.")
		}

		cfg, err = delphi.ResolveConfig()
		if err != nil {
			zap.L().Fatal("Failed to resolve Delphi config", zap.Error(err))
		}

		if cfg.Protocol == "" {
			cfg.Protocol = "https"
		}
		if cfg.Port == "" {
			cfg.Port = "55000"
		}

		if err := delphi.WriteConfig(cfg); err != nil {
			zap.L().Warn("Failed to write config", zap.Error(err))
		}

		zap.L().Info("Retrieving JWT token...")
		token, err := delphi.Authenticate(cfg)
		if err != nil {
			zap.L().Fatal("Authentication failed", zap.Error(err))
		}
		cfg.Token = token
		if err := delphi.WriteConfig(cfg); err != nil {
			zap.L().Fatal("Failed to save token", zap.Error(err))
		}

		zap.L().Info("JWT token retrieved successfully", zap.String("token", token))
		return nil
	}),
}

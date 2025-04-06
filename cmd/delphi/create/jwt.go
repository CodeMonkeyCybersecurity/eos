// cmd/delphi/create/jwt.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate and store a JWT token for Delphi (Wazuh) API access",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := delphi.LoadDelphiConfig()
		if err != nil {
			log.Warn("Config not found, prompting for values", zap.Error(err))
			cfg.FQDN = interaction.PromptInput("Enter the Wazuh domain (eg. delphi.domain.com)", "")
			cfg.APIUser = interaction.PromptInput("Enter the API username (eg. wazuh-wui)", "")
			pw, err := interaction.PromptPassword("Enter the API password")
			if err != nil {
				log.Fatal("Failed to read password", zap.Error(err))
			}
			cfg.APIPassword = pw
			if err := delphi.SaveDelphiConfig(cfg); err != nil {
				log.Fatal("Error saving configuration", zap.Error(err))
			}
			log.Info("Configuration file created.")
		}

		cfg = delphi.ConfirmDelphiConfig(cfg)

		if cfg.Protocol == "" {
			cfg.Protocol = "https"
		}
		if cfg.Port == "" {
			cfg.Port = "55000"
		}

		delphi.SaveDelphiConfig(cfg)

		log.Info("Retrieving JWT token...")
		token, err := delphi.Authenticate(cfg)
		if err != nil {
			log.Fatal("Authentication failed", zap.Error(err))
		}
		cfg.Token = token
		if err := delphi.SaveDelphiConfig(cfg); err != nil {
			log.Fatal("Failed to save token", zap.Error(err))
		}

		log.Info("JWT token retrieved successfully", zap.String("token", token))
	},
}

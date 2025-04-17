// cmd/delphi/create/jwt.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate and store a JWT token for Delphi (Wazuh) API access",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		cfg, err := delphi.ReadConfig(log)
		if err != nil {
			log.Warn("Config not found, prompting for values", zap.Error(err))
			cfg.FQDN = interaction.PromptInput("Enter the Wazuh domain (eg. delphi.domain.com)", "")
			cfg.APIUser = interaction.PromptInput("Enter the API username (eg. wazuh-wui)", "")
			pw, err := interaction.PromptPassword("Enter the API password", log)
			if err != nil {
				log.Fatal("Failed to read password", zap.Error(err))
			}
			cfg.APIPassword = pw
			if err := delphi.WriteConfig(cfg, log); err != nil {
				log.Fatal("Error saving configuration", zap.Error(err))
			}
			log.Info("Configuration file created.")
		}

		cfg, err = delphi.ResolveConfig(log)
		if err != nil {
			log.Fatal("Failed to resolve Delphi config", zap.Error(err))
		}

		if cfg.Protocol == "" {
			cfg.Protocol = "https"
		}
		if cfg.Port == "" {
			cfg.Port = "55000"
		}

		delphi.WriteConfig(cfg, log)

		log.Info("Retrieving JWT token...")
		token, err := delphi.Authenticate(cfg)
		if err != nil {
			log.Fatal("Authentication failed", zap.Error(err))
		}
		cfg.Token = token
		if err := delphi.WriteConfig(cfg, log); err != nil {
			log.Fatal("Failed to save token", zap.Error(err))
		}

		log.Info("JWT token retrieved successfully", zap.String("token", token))
		return nil
	}),
}

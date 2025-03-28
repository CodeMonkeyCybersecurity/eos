// cmd/delphi/create/jwt.go

package create

import (
	"eos/pkg/delphi"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate and store a JWT token for Delphi (Wazuh) API access",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := delphi.LoadConfig()
		if err != nil {
			log.Warn("Config not found, prompting for values", zap.Error(err))
			cfg.FQDN = delphi.PromptInput("Enter the Wazuh domain (eg. wazuh.domain.com)", "")
			cfg.API_User = delphi.PromptInput("Enter the API username (eg. wazuh-wui)", "")
			cfg.API_Password = delphi.PromptPassword("Enter the API password", "")
			if err := delphi.SaveConfig(cfg); err != nil {
				log.Fatal("Error saving configuration", zap.Error(err))
			}
			log.Info("Configuration file created.")
		}

		cfg = delphi.ConfirmConfig(cfg)

		if cfg.Protocol == "" {
			cfg.Protocol = "https"
		}
		if cfg.Port == "" {
			cfg.Port = "55000"
		}

		delphi.SaveConfig(cfg)

		log.Info("Retrieving JWT token...")
		token, err := delphi.Authenticate(cfg)
		if err != nil {
			log.Fatal("Authentication failed", zap.Error(err))
		}
		cfg.Token = token
		if err := delphi.SaveConfig(cfg); err != nil {
			log.Fatal("Failed to save token", zap.Error(err))
		}

		log.Info("JWT token retrieved successfully", zap.String("token", token))
	},
}

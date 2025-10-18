/* pkg/wazuh/interaction.go */

package wazuh

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfirmConfig allows the user to review and optionally edit the current config.
func ConfirmConfig(rc *eos_io.RuntimeContext, cfg *Config) *Config {
	logger := otelzap.Ctx(rc.Ctx)

	// Log configuration for review
	logger.Info("Current configuration",
		zap.String("protocol", cfg.Protocol),
		zap.String("fqdn", cfg.FQDN),
		zap.String("port", cfg.Port),
		zap.String("api_user", cfg.APIUser),
		zap.Bool("show_secrets", ShowSecrets),
		zap.String("latest_version", cfg.LatestVersion))

	logger.Info("terminal prompt: Are these values correct? (y/n)")
	answer := strings.ToLower(interaction.PromptInput(rc.Ctx, "Are these values correct? (y/n)", "y"))
	if answer != "y" {
		logger.Info("terminal prompt: Enter new values (press Enter to keep current)")

		newVal := interaction.PromptInput(rc.Ctx, fmt.Sprintf("Protocol [%s]", cfg.Protocol), cfg.Protocol)
		if newVal != "" {
			cfg.Protocol = newVal
		}

		newVal = interaction.PromptInput(rc.Ctx, fmt.Sprintf("FQDN [%s]", cfg.FQDN), cfg.FQDN)
		if newVal != "" {
			cfg.FQDN = newVal
		}

		newVal = interaction.PromptInput(rc.Ctx, fmt.Sprintf("Port [%s]", cfg.Port), cfg.Port)
		if newVal != "" {
			cfg.Port = newVal
		}

		newVal = interaction.PromptInput(rc.Ctx, fmt.Sprintf("API Username [%s]", cfg.APIUser), cfg.APIUser)
		if newVal != "" {
			cfg.APIUser = newVal
		}

		pw, err := crypto.PromptPassword(rc, "API Password")
		if err != nil {
			logger.Error("Failed to read password", zap.Error(err))
			os.Exit(1)
		}
		if pw != "" {
			cfg.APIPassword = pw
		}

		newVal = interaction.PromptInput(rc.Ctx, fmt.Sprintf("Latest Version [%s]", cfg.LatestVersion), cfg.LatestVersion)
		if newVal != "" {
			cfg.LatestVersion = newVal
		}

		if err := WriteConfig(rc, cfg); err != nil {
			logger.Error("Error saving configuration", zap.Error(err))
			os.Exit(1)
		}
		logger.Info("Configuration updated successfully")
	}
	return cfg
}

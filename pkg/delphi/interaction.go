/* pkg/delphi/interaction.go */

package delphi

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

// ConfirmConfig allows the user to review and optionally edit the current config.
func ConfirmConfig(cfg *Config, log *zap.Logger) *Config {
	fmt.Println("Current configuration:")
	fmt.Printf("  Protocol:      %s\n", cfg.Protocol)
	fmt.Printf("  FQDN:          %s\n", cfg.FQDN)
	fmt.Printf("  Port:          %s\n", cfg.Port)
	fmt.Printf("  APIUser:       %s\n", cfg.APIUser)

	if ShowSecrets {
		fmt.Printf("  APIPassword:   %s\n", cfg.APIPassword)
	} else {
		fmt.Printf("  APIPassword:   ********\n")
	}

	fmt.Printf("  LatestVersion: %s\n", cfg.LatestVersion)

	answer := strings.ToLower(interaction.PromptInput("Are these values correct? (y/n)", "y", log))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")

		newVal := interaction.PromptInput(fmt.Sprintf("Protocol [%s]", cfg.Protocol), cfg.Protocol, log)
		if newVal != "" {
			cfg.Protocol = newVal
		}

		newVal = interaction.PromptInput(fmt.Sprintf("FQDN [%s]", cfg.FQDN), cfg.FQDN, log)
		if newVal != "" {
			cfg.FQDN = newVal
		}

		newVal = interaction.PromptInput(fmt.Sprintf("Port [%s]", cfg.Port), cfg.Port, log)
		if newVal != "" {
			cfg.Port = newVal
		}

		newVal = interaction.PromptInput(fmt.Sprintf("API Username [%s]", cfg.APIUser), cfg.APIUser, log)
		if newVal != "" {
			cfg.APIUser = newVal
		}

		pw, err := crypto.PromptPassword("API Password", log)
		if err != nil {
			fmt.Printf("❌ Failed to read password: %v\n", err)
			os.Exit(1)
		}
		if pw != "" {
			cfg.APIPassword = pw
		}

		newVal = interaction.PromptInput(fmt.Sprintf("Latest Version [%s]", cfg.LatestVersion), cfg.LatestVersion, log)
		if newVal != "" {
			cfg.LatestVersion = newVal
		}

		if err := WriteConfig(cfg, log); err != nil {
			fmt.Printf("❌ Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Configuration updated.")
	}
	return cfg
}

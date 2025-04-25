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

// ConfirmConfig allows the user to review and optionally edit the current config
func ConfirmConfig(cfg *Config, log *zap.Logger) *Config {
	fmt.Println("Current configuration:")
	fmt.Printf("  FQDN:         %s\n", cfg.FQDN)
	fmt.Printf("  API_User:     %s\n", cfg.APIUser)

	if ShowSecrets {
		fmt.Printf("  API_Password: %s\n", cfg.APIPassword)
	} else {
		fmt.Printf("  API_Password: ********\n")
	}

	answer := strings.ToLower(interaction.PromptInput("Are these values correct? (y/n)", "y", log))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		cfg.FQDN = interaction.PromptInput("FQDN", cfg.FQDN, log)
		cfg.APIUser = interaction.PromptInput("API Username", cfg.APIUser, log)

		pw, err := crypto.PromptPassword("API Password", log)
		if err != nil {
			fmt.Printf("❌ Failed to read password: %v\n", err)
			os.Exit(1)
		}
		cfg.APIPassword = pw

		if err := WriteConfig(cfg, log); err != nil {
			fmt.Printf("❌ Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Configuration updated.")
	}
	return cfg
}

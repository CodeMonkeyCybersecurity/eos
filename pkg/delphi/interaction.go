/* pkg/delphi/interaction.go */

package delphi

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

// ConfirmConfig allows the user to review and optionally edit the current config.
func ConfirmConfig(rc *eos_io.RuntimeContext, cfg *Config) *Config {
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

	answer := strings.ToLower(interaction.PromptInput(rc.Ctx, "Are these values correct? (y/n)", "y"))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")

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
			fmt.Printf("❌ Failed to read password: %v\n", err)
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
			fmt.Printf("❌ Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Configuration updated.")
	}
	return cfg
}

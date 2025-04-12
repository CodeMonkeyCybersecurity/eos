// pkg/delphi/config.go
package delphi

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

const (
	DelphiPasswdToolURL  = "https://packages.wazuh.com/4.11/wazuh-passwords-tool.sh"
	DelphiPasswdToolPath = "/usr/local/bin/wazuh-passwords-tool.sh"
)

var (
	delphiConfigPath = xdg.XDGConfigPath("eos", "delphi.json")
	ShowSecrets      bool // toggle to display password in ConfirmDelphiConfig
)

// DelphiConfig represents the configuration stored in delphi.json
type DelphiConfig struct {
	APIUser            string `json:"API_User"`
	APIPassword        string `json:"API_Password"`
	Endpoint           string `json:"endpoint"`
	FQDN               string `json:"FQDN"`
	LatestVersion      string `json:"LatestVersion,omitempty"`
	Port               string `json:"port"`
	Protocol           string `json:"protocol"`
	Token              string `json:"token,omitempty"`
	VerifyCertificates bool   `json:"verify_certificates"`
}

// LoadDelphiConfig reads Delphi config from the XDG path or prompts for values if missing
func LoadDelphiConfig() (*DelphiConfig, error) {
	cfg := &DelphiConfig{}
	data, err := os.ReadFile(delphiConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("⚠️  Delphi config not found. Let's set it up.")

			cfg.FQDN = interaction.PromptInput("Enter the Wazuh FQDN", "delphi.domain.com")
			cfg.Port = interaction.PromptInput("Enter the port", "55000")
			cfg.Protocol = interaction.PromptInput("Enter the protocol (http or https)", "https")
			cfg.APIUser = interaction.PromptInput("Enter the API username", "wazuh-wui")

			pw, err := interaction.PromptPassword("Enter the API password")
			if err != nil {
				return nil, fmt.Errorf("failed to read password: %w", err)
			}
			cfg.APIPassword = pw
			cfg.VerifyCertificates = false

			cfg.Endpoint = fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)

			if err := SaveDelphiConfig(cfg); err != nil {
				return cfg, fmt.Errorf("unable to save new config: %w", err)
			}
			fmt.Printf("✅ Config saved to %s\n", delphiConfigPath)
			return cfg, nil
		}
		return cfg, fmt.Errorf("unable to read config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return cfg, fmt.Errorf("unable to parse config: %w", err)
	}
	return cfg, nil
}

// SaveDelphiConfig writes Delphi config to the XDG path
func SaveDelphiConfig(cfg *DelphiConfig) error {
	if err := xdg.EnsureDir(delphiConfigPath); err != nil {
		return fmt.Errorf("unable to create config path: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal config: %w", err)
	}
	return os.WriteFile(delphiConfigPath, data, 0644)
}

// BaseURL returns the root API endpoint for the configured Delphi instance
func BaseURL(cfg *DelphiConfig) string {
	return fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
}

func LoadAndConfirmConfig() (*DelphiConfig, error) {
	var cfg DelphiConfig
	err := vault.ReadFromVault("secret/delphi/config", &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load Delphi config: %w", err)
	}
	return &cfg, nil
}

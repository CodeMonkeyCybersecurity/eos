// pkg/config/delphi.go

package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

var delphiConfigPath = xdg.XDGConfigPath("eos", "delphi.json")

// Config represents the configuration stored in .delphi.json.
type DelphiConfig struct {
	API_User           string `json:"API_User"`
	API_Password       string `json:"API_Password"`
	Endpoint           string `json:"endpoint"`
	FQDN               string `json:"FQDN"`
	LatestVersion      string `json:"LatestVersion,omitempty"`
	Port               string `json:"port"`
	Protocol           string `json:"protocol"`
	Token              string `json:"token,omitempty"`
	VerifyCertificates bool   `json:"verify_certificates"`
}

// LoadDelphiConfig reads the Delphi config file from the XDG path.
func LoadDelphiConfig() (DelphiConfig, error) {
	var cfg DelphiConfig
	data, err := os.ReadFile(delphiConfigPath)
	if err != nil {
		return cfg, fmt.Errorf("unable to read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("unable to parse config: %w", err)
	}
	return cfg, nil
}

// SaveDelphiConfig writes the Delphi config to the XDG path.
func SaveDelphiConfig(cfg DelphiConfig) error {
	if err := utils.EnsureDir(delphiConfigPath); err != nil {
		return fmt.Errorf("unable to create config path: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to marshal config: %w", err)
	}
	return os.WriteFile(delphiConfigPath, data, 0644)
}

// ConfirmDelphiConfig displays the current configuration and allows
func ConfirmDelphiConfig(cfg DelphiConfig) DelphiConfig {
	fmt.Println("Current configuration:")
	fmt.Printf("  FQDN:         %s\n", cfg.FQDN)
	fmt.Printf("  API_User:     %s\n", cfg.API_User)
	fmt.Printf("  API_Password: %s\n", "********")

	answer := strings.ToLower(interaction.PromptInput("Are these values correct? (y/n)", "y"))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		cfg.FQDN = interaction.PromptInput("Enter the Wazuh domain (e.g. delphi.domain.com)", cfg.FQDN)
		cfg.API_User = interaction.PromptInput("Enter the API username (e.g. wazuh-wui)", cfg.API_User)
		cfg.API_Password = interaction.PromptPassword("Enter the API password", cfg.API_Password)

		if err := SaveDelphiConfig(cfg); err != nil {
			fmt.Printf("❌ Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Configuration updated.")
	}
	return cfg
}

// Authenticate connects to the Wazuh API using Basic Auth and returns a JWT token.
func Authenticate(apiURL, username, password string) (string, error) {
	authURL := fmt.Sprintf("%s/security/user/authenticate?raw=true", strings.TrimRight(apiURL, "/"))
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(username, password)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed (%d): %s", resp.StatusCode, string(body))
	}

	return strings.TrimSpace(string(body)), nil
}

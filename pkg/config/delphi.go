// pkg/config/delphi.go

package config

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

const delphiConfigFile = ".delphi.json"

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

func LoadDelphiConfig() (DelphiConfig, error) {
	var cfg DelphiConfig
	data, err := os.ReadFile(delphiConfigFile)
	if err != nil {
		return cfg, fmt.Errorf("unable to read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("unable to parse config: %w", err)
	}
	return cfg, nil
}

func SaveDelphiConfig(cfg DelphiConfig) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to marshal config: %w", err)
	}
	return os.WriteFile(delphiConfigFile, data, 0644)
}

// ConfirmDelphiConfig displays the current configuration and allows the user to update values.
func ConfirmDelphiConfig(cfg DelphiConfig) DelphiConfig {
	fmt.Println("Current configuration:")
	fmt.Printf("  FQDN:          %s\n", cfg.FQDN)
	fmt.Printf("  API_User:      %s\n", cfg.API_User)
	fmt.Printf("  API_Password:  %s\n", "********")

	answer := strings.ToLower(PromptInput("Are these values correct? (y/n)", "y"))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		cfg.FQDN = PromptInput("Enter the Wazuh domain (eg. wazuh.domain.com)", cfg.FQDN)
		cfg.API_User = PromptInput("Enter the API username (eg. wazuh-wui)", cfg.API_User)
		cfg.API_Password = PromptPassword("Enter the API password", cfg.API_Password)
		if err := SaveDelphiConfig(cfg); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
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

// PromptInput displays a prompt and reads user input.
func PromptInput(prompt, defaultVal string) string {
	reader := bufio.NewReader(os.Stdin)
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// promptPassword displays a prompt and reads a password without echoing.
func PromptPassword(prompt, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, "********")
	} else {
		fmt.Printf("%s: ", prompt)
	}
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	fmt.Println("")
	pass := strings.TrimSpace(string(bytePassword))
	if pass == "" {
		return defaultVal
	}
	return pass
}

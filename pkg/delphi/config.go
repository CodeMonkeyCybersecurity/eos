// pkg/delphi/config.go

package delphi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

const configFile = ".delphi.json"

// Config represents the configuration stored in .delphi.json.
type DelphiConfig struct {
	Protocol           string `json:"protocol"`
	FQDN               string `json:"FQDN"`
	Port               string `json:"port"`
	API_User           string `json:"API_User"`
	API_Password       string `json:"API_Password"`
	Endpoint           string `json:"endpoint"`
	Token              string `json:"TOKEN,omitempty"`
	VerifyCertificates bool   `json:"verify_certificates"`
}

// LoadConfig reads the configuration from .delphi.json.
func LoadConfig() (DelphiConfig, error) {
	var cfg DelphiConfig
	data, err := os.ReadFile(configFile)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

// SaveConfig writes the configuration back to .delphi.json.
func SaveConfig(cfg DelphiConfig) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
}

// ConfirmConfig displays the current configuration and allows the user to update values.
func ConfirmConfig(cfg DelphiConfig) DelphiConfig {
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
		if err := SaveConfig(cfg); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration updated.")
	}
	return cfg
}

// promptInput displays a prompt and reads user input.
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

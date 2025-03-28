// pkg/delphi/config.go

package delphi

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

	"eos/pkg/config"
)

const configFile = ".delphi.json"

// Config represents the configuration stored in .delphi.json.
type Config struct {
	Protocol     string `json:"protocol"`
	FQDN         string `json:"FQDN"`
	Port         string `json:"port"`
	API_User     string `json:"API_User"`
	API_Password string `json:"API_Password"`
	Endpoint     string `json:"endpoint"`
	Token        string `json:"TOKEN,omitempty"`
}

// LoadConfig reads the configuration from .delphi.json.
func LoadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(configFile)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

// SaveConfig writes the configuration back to .delphi.json.
func SaveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
}

// ConfirmConfig displays the current configuration and allows the user to update values.
func ConfirmConfig(cfg Config) Config {
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

// Authenticate logs in to the Wazuh API using basic auth and returns the JWT token.
func Authenticate(cfg config.DelphiConfig) (string, error) {
	url := fmt.Sprintf("https://%s:55000/security/user/authenticate?raw=true", cfg.FQDN)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(cfg.API_User, cfg.API_Password)

	// Create an HTTP client that skips certificate verification.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("no token received")
	}
	return token, nil
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

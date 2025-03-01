package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"golang.org/x/term"
	"syscall"
)

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

const configFile = ".delphi.json"

// loadConfig reads the configuration from .delphi.json.
func loadConfig() (Config, error) {
	var cfg Config
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

// saveConfig writes the configuration back to .delphi.json.
func saveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFile, data, 0644)
}

// promptInput displays a prompt and reads user input.
func promptInput(prompt, defaultVal string) string {
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
func promptPassword(prompt, defaultVal string) string {
	// If there's a default, show a masked value.
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", prompt, "********")
	} else {
		fmt.Printf("%s: ", prompt)
	}
	// ReadPassword disables input echoing.
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nError reading password:", err)
		os.Exit(1)
	}
	fmt.Println("") // add newline after password input
	pass := strings.TrimSpace(string(bytePassword))
	if pass == "" {
		return defaultVal
	}
	return pass
}

// confirmConfig displays the current configuration and allows the user to update values.
// The API_Password is masked when displayed.
func confirmConfig(cfg Config) Config {
	fmt.Println("Current configuration:")
	fmt.Printf("  FQDN:          %s\n", cfg.FQDN)
	fmt.Printf("  API_User:      %s\n", cfg.API_User)
	fmt.Printf("  API_Password:  %s\n", "********")

	answer := strings.ToLower(promptInput("Are these values correct? (y/n)", "y"))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		cfg.FQDN = promptInput("Enter the Wazuh domain (eg. wazuh.domain.com)", cfg.FQDN)
		cfg.API_User = promptInput("Enter the API username (eg. wazuh-wui)", cfg.API_User)
		// Use promptPassword for the password.
		cfg.API_Password = promptPassword("Enter the API password", cfg.API_Password)
		if err := saveConfig(cfg); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration updated.\n")
	}
	return cfg
}

// authenticate logs in to the Wazuh API using basic auth and returns the JWT token.
func authenticate(cfg Config) (string, error) {
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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("no token received")
	}
	return token, nil
}

func main() {
	// Load configuration from .delphi.json.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		// File not found or error reading? Prompt for new values.
		fmt.Println("Configuration file not found or incomplete. Please enter new configuration values:")
		cfg.FQDN = promptInput("Enter the Wazuh domain (eg. wazuh.domain.com)", "")
		cfg.API_User = promptInput("Enter the API username (eg. wazuh-wui)", "")
		cfg.API_Password = promptPassword("Enter the API password", "")
		if err := saveConfig(cfg); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration file created.")
	}

	// Confirm or update the configuration.
	cfg = confirmConfig(cfg)

	// Set default values for protocol and port if empty.
	if cfg.Protocol == "" {
		cfg.Protocol = "https"
	}
	if cfg.Port == "" {
		cfg.Port = "55000"
	}
	// Save configuration if defaults were set.
	saveConfig(cfg)

	// Authenticate to get the JWT token.
	fmt.Println("\nRetrieving JWT token...")
	token, err := authenticate(cfg)
	if err != nil {
		fmt.Printf("Error during authentication: %v\n", err)
		os.Exit(1)
	}
	cfg.Token = token
	if err := saveConfig(cfg); err != nil {
		fmt.Printf("Error saving configuration: %v\n", err)
	}

	fmt.Println("\nYour JWT auth token is:")
	fmt.Println(token)
	fmt.Println("\nFINIS")
}

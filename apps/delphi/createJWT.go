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
)

// Config represents the configuration stored in .delphi.json.
type Config struct {
	WZFQDN    string `json:"WZ_FQDN"`
	WZAPIUSR  string `json:"WZ_API_USR"`
	WZAPIPASS string `json:"WZ_API_PASSWD"`
	Token     string `json:"TOKEN,omitempty"`
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

// saveConfig writes the configuration to .delphi.json.
func saveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFile, data, 0644)
}

// promptInput displays a prompt and reads user input; returns the default if input is empty.
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

// confirmConfig displays the current configuration and allows the user to update values.
func confirmConfig(cfg Config) Config {
	fmt.Println("Current configuration:")
	fmt.Printf("  WZ_FQDN:     %s\n", cfg.WZFQDN)
	fmt.Printf("  WZ_API_USR:  %s\n", cfg.WZAPIUSR)
	fmt.Printf("  WZ_API_PASSWD: %s\n", cfg.WZAPIPASS)
	
	answer := strings.ToLower(promptInput("Are these values correct? (y/n)", "y"))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		cfg.WZFQDN = promptInput("Enter the Wazuh domain (eg. wazuh.domain.com)", cfg.WZFQDN)
		cfg.WZAPIUSR = promptInput("Enter the API username (eg. wazuh-wui)", cfg.WZAPIUSR)
		cfg.WZAPIPASS = promptInput("Enter the API password", cfg.WZAPIPASS)
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
	url := fmt.Sprintf("https://%s:55000/security/user/authenticate?raw=true", cfg.WZFQDN)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(cfg.WZAPIUSR, cfg.WZAPIPASS)
	
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
		os.Exit(1)
	}

	// Confirm or update the configuration.
	cfg = confirmConfig(cfg)

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

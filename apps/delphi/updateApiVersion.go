package main

import (
	"bufio"
	"bytes"
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
	Protocol      string `json:"Protocol"`
	FQDN          string `json:"FQDN"`
	Port          string `json:"Port"`
	API_User      string `json:"API_User"`
	API_Password  string `json:"API_Password"`
	Endpoint      string `json:"Endpoint"`
	Token         string `json:"Token,omitempty"`
	LatestVersion string `json:"LatestVersion,omitempty"`
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

// confirmConfig displays the current configuration and allows the user to update values.
// The API_Password is masked when displayed.
func confirmConfig(cfg Config) Config {
	fmt.Println("Current configuration:")
	fmt.Printf("  Protocol:      %s\n", cfg.Protocol)
	fmt.Printf("  FQDN:          %s\n", cfg.FQDN)
	fmt.Printf("  Port:          %s\n", cfg.Port)
	fmt.Printf("  API_User:      %s\n", cfg.API_User)
	if cfg.API_Password != "" {
		fmt.Printf("  API_Password:  %s\n", "********")
	} else {
		fmt.Printf("  API_Password:  \n")
	}
	fmt.Printf("  LatestVersion: %s\n", cfg.LatestVersion)

	answer := strings.ToLower(promptInput("Are these values correct? (y/n)", "y"))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		newVal := promptInput(fmt.Sprintf("  Protocol [%s]: ", cfg.Protocol), cfg.Protocol)
		if newVal != "" {
			cfg.Protocol = newVal
		}
		newVal = promptInput(fmt.Sprintf("  FQDN [%s]: ", cfg.FQDN), cfg.FQDN)
		if newVal != "" {
			cfg.FQDN = newVal
		}
		newVal = promptInput(fmt.Sprintf("  Port [%s]: ", cfg.Port), cfg.Port)
		if newVal != "" {
			cfg.Port = newVal
		}
		newVal = promptInput(fmt.Sprintf("  API_User [%s]: ", cfg.API_User), cfg.API_User)
		if newVal != "" {
			cfg.API_User = newVal
		}
		newVal = promptPassword("  API_Password", cfg.API_Password)
		if newVal != "" {
			cfg.API_Password = newVal
		}
		newVal = promptInput(fmt.Sprintf("  LatestVersion [%s]: ", cfg.LatestVersion), cfg.LatestVersion)
		if newVal != "" {
			cfg.LatestVersion = newVal
		}
		if err := saveConfig(cfg); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration updated.\n")
	}
	return cfg
}

// authenticate logs in to the Wazuh API using HTTP Basic Authentication and returns a JWT token.
func authenticate(apiURL, username, password string) (string, error) {
	authURL := fmt.Sprintf("%s/security/user/authenticate?raw=true", apiURL)
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password)

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	token := strings.TrimSpace(string(bodyBytes))
	return token, nil
}

// upgradeAgent sends a PUT request to the /agents/{agent_id}/upgrade endpoint to update the agent.
func upgradeAgent(apiURL, token, agentID string) error {
	upgradeURL := fmt.Sprintf("%s://%s:%d/agents/%s/upgrade", Protocol, FQDN, Port, agentID)
	fmt.Printf("Requesting upgrade for agent %s at %s\n", agentID, upgradeURL)
	payload := map[string]interface{}{}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", upgradeURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent %s upgrade failed (%d): %s", agentID, resp.StatusCode, string(bodyBytes))
	}

	fmt.Printf("Agent %s upgraded successfully: %s\n", agentID, string(bodyBytes))
	return nil
}

// promptInputShort displays a prompt and reads input from stdin.
func promptInputShort(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func main() {
	// Gather input details for agent upgrade.
	// First, try to load configuration from .delphi.json.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}
	cfg = confirmConfig(cfg)

	// Construct API URL from config.
	apiURL := fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
	// Remove any trailing slash.
	apiURL = strings.TrimRight(apiURL, "/")

	username := cfg.API_User
	password := cfg.API_Password
	agentsInput := promptInput("Enter the agent IDs to upgrade (comma separated): ", "")

	// Authenticate to obtain the JWT token.
	fmt.Println("\nAuthenticating to the Wazuh API...")
	token, err := authenticate(apiURL, username, password)
	if err != nil {
		fmt.Printf("Error during authentication: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Authentication successful. JWT token acquired.")

	// Process the list of agent IDs.
	agentIDs := strings.Split(agentsInput, ",")
	for i, agentID := range agentIDs {
		agentIDs[i] = strings.TrimSpace(agentID)
	}

	// Upgrade each agent.
	for _, agentID := range agentIDs {
		if agentID == "" {
			continue
		}
		fmt.Printf("\nUpgrading agent %s...\n", agentID)
		if err := upgradeAgent(apiURL, token, agentID); err != nil {
			fmt.Printf("Error upgrading agent %s: %v\n", agentID, err)
		}
	}

	fmt.Println("\nAgent upgrade process completed.")
}

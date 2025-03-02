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
	"os/exec"
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

// authenticate logs in to the Wazuh API using basic auth and returns a JWT token.
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

// upgradeAgent sends a PUT request to the upgrade endpoint with the required agents_list parameter.
func upgradeAgent(apiURL, token string, agentIDs []string, payload []byte) error {
	// Join agentIDs as a comma-separated string.
	agentsQuery := strings.Join(agentIDs, ",")
	upgradeURL := fmt.Sprintf("%s/agents/upgrade?agents_list=%s&pretty=true", apiURL, agentsQuery)
	fmt.Printf("DEBUG: Requesting upgrade at %s\n", upgradeURL)
	req, err := http.NewRequest("PUT", upgradeURL, bytes.NewBuffer(payload))
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
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("DEBUG: HTTP Response Status: %s\n", resp.Status)
	fmt.Printf("DEBUG: HTTP Response Body: %s\n", string(respBody))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upgrade request failed (%d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func main() {
	// Load and confirm configuration.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}
	cfg = confirmConfig(cfg)
	if cfg.Protocol == "" {
		cfg.Protocol = "https"
	}
	if cfg.Port == "" {
		cfg.Port = "55000"
	}
	apiURL := fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
	apiURL = strings.TrimRight(apiURL, "/")

	// Authenticate to obtain the JWT token.
	fmt.Println("\nAuthenticating to the Wazuh API...")
	token, err := authenticate(apiURL, cfg.API_User, cfg.API_Password)
	if err != nil {
		fmt.Printf("Error during authentication: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Authentication successful. JWT token acquired.")

	// Prompt for agent IDs to upgrade as strings.
	agentIDsInput := promptInput("Enter agent IDs to upgrade (comma separated)", "")
	agentIDsSlice := strings.Split(agentIDsInput, ",")
	var agentIDs []string
	for _, s := range agentIDsSlice {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Preserve the string (e.g., "001" stays "001")
		agentIDs = append(agentIDs, s)
	}
	if len(agentIDs) == 0 {
		fmt.Println("No agent IDs provided.")
		os.Exit(1)
	}

	// Prompt for upgrade parameters.
	defaultRepo := "packages.wazuh.com/wpk/"
	wpkRepo := promptInput("Enter WPK repository", defaultRepo)
	defaultVersion := cfg.LatestVersion
	if defaultVersion != "" && !strings.HasPrefix(defaultVersion, "v") {
		defaultVersion = "v" + defaultVersion
	}
	version := promptInput("Enter upgrade version", defaultVersion)
	useHTTPStr := promptInput("Use HTTP instead of HTTPS? (true/false)", "false")
	useHTTP := strings.ToLower(useHTTPStr) == "true"
	forceStr := promptInput("Force upgrade? (true/false)", "false")
	forceUpgrade := strings.ToLower(forceStr) == "true"
	packageType := promptInput("Enter package type (rpm/deb)", "rpm")

	// Build the upgrade request payload.
	payloadMap := map[string]interface{}{
		"origin": map[string]string{
			"module": "api",
		},
		"command": "upgrade",
		"parameters": map[string]interface{}{
			"agents":        agentIDs,
			"wpk_repo":      wpkRepo,
			"version":       version,
			"use_http":      useHTTP,
			"force_upgrade": forceUpgrade,
			"package_type":  packageType,
		},
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		fmt.Printf("Error marshaling payload: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nPayload:\n%s\n", string(payloadBytes))

	// Send the upgrade request.
	err = upgradeAgent(apiURL, token, agentIDs, payloadBytes)
	if err != nil {
		fmt.Printf("Error upgrading agents: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\nAgent upgrade process completed.")
}

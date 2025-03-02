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

// queryUpgradeResult sends a PUT request to query upgrade task results.
func queryUpgradeResult(apiURL, token string, agentIDs []string) error {
	// Build query parameter as comma-separated list.
	agentsQuery := strings.Join(agentIDs, ",")
	queryURL := fmt.Sprintf("%s/agents/upgrade_result?agents_list=%s&pretty=true", apiURL, agentsQuery)
	fmt.Printf("DEBUG: Requesting upgrade result at %s\n", queryURL)
	
	// Build payload for upgrade_result request.
	payloadMap := map[string]interface{}{
		"origin": map[string]string{
			"module": "api",
		},
		"command": "upgrade_result",
		"parameters": map[string]interface{}{
			"agents": agentIDs,
		},
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return err
	}
	fmt.Printf("DEBUG: Payload: %s\n", string(payloadBytes))
	
	req, err := http.NewRequest("PUT", queryURL, bytes.NewBuffer(payloadBytes))
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
		return fmt.Errorf("upgrade result query failed (%d): %s", resp.StatusCode, string(respBody))
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
	
	// Authenticate.
	fmt.Println("\nAuthenticating to the Wazuh API...")
	token, err := authenticate(apiURL, cfg.API_User, cfg.API_Password)
	if err != nil {
		fmt.Printf("Error during authentication: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Authentication successful. JWT token acquired.")
	
	// Prompt for agent IDs (as strings).
	agentIDsInput := promptInput("Enter agent IDs to query upgrade result (comma separated)", "")
	agentIDsSlice := strings.Split(agentIDsInput, ",")
	var agentIDs []string
	for _, s := range agentIDsSlice {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		agentIDs = append(agentIDs, s)
	}
	if len(agentIDs) == 0 {
		fmt.Println("No agent IDs provided.")
		os.Exit(1)
	}
	
	// Query upgrade result.
	err = queryUpgradeResult(apiURL, token, agentIDs)
	if err != nil {
		fmt.Printf("Error querying upgrade result: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("\nUpgrade result query completed.")
}

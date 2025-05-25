// pkg/delphi/agent.go
package delphi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"golang.org/x/term"
)

func DeleteAgent(agentID string, token string, config *Config) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s://%s:%s/agents/%s?pretty=true", config.Protocol, config.FQDN, config.Port, agentID)

	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer shared.SafeClose(resp.Body)

	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

// UpgradeAgents calls the Wazuh API to upgrade a list of agent IDs.
func UpgradeAgents(cfg *Config, token string, agentIDs []string, payload map[string]interface{}) error {
	url := fmt.Sprintf("%s://%s:%s/agents/upgrade?agents_list=%s&pretty=true",
		cfg.Protocol, cfg.FQDN, cfg.Port, strings.Join(agentIDs, ","))

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyCertificates},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer shared.SafeClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upgrade failed: %s", resp.Status)
	}

	return nil
}

// loadConfig reads the configuration from .delphi.json.
func LoadConfig() (*Config, error) {
	var cfg Config
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// saveConfig writes the configuration back to .delphi.json.
func SaveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
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

	req, err := http.NewRequest("POST", queryURL, bytes.NewBuffer(payloadBytes))
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
	defer shared.SafeClose(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
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

func InspectAgentUpgradeResult(ctx context.Context) {
	cfg, err := LoadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}
	cfg = ConfirmConfig(ctx, cfg)
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
	token, err := Authenticate(cfg)
	if err != nil {
		fmt.Printf("Error during authentication: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Authentication successful. JWT token acquired.")

	// Prompt for agent IDs (as strings).
	agentIDsInput := PromptInput("Enter agent IDs to query upgrade result (comma separated)", "")
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

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
)

// authenticate logs in to the Wazuh API using HTTP Basic Authentication
// and returns a JWT token.
func authenticate(apiURL, username, password string) (string, error) {
	authURL := fmt.Sprintf("%s/security/user/authenticate?raw=true", apiURL)
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password)

	// Create an HTTP client that skips TLS verification (useful for self-signed certs)
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
	upgradeURL := fmt.Sprintf("%s/agents/%s/upgrade", apiURL, agentID)
	// Create an empty JSON payload (adjust if parameters are needed)
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

// promptInput displays a prompt and reads input from stdin.
func promptInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func main() {
	// Gather input details.
	apiURL := promptInput("Enter the Wazuh API URL (e.g., https://wazuh.domain.com:55000): ")
	username := promptInput("Enter the API username: ")
	password := promptInput("Enter the API password: ")
	agentsInput := promptInput("Enter the agent IDs to upgrade (comma separated): ")

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

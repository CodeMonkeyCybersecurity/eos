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

// authenticate calls the Wazuh API to authenticate the user and returns a JWT token.
// It makes a POST request to /security/user/authenticate?raw=true using basic auth.
func authenticate(apiURL, username, password string) (string, error) {
	authURL := fmt.Sprintf("%s/security/user/authenticate?raw=true", apiURL)
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(username, password)

	// Skip TLS verification (useful if using self-signed certs)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
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

	// The API returns the token as plain text.
	token := strings.TrimSpace(string(bodyBytes))
	return token, nil
}

// updatePassword updates the password for the specified API user (wazuh-wui)
// by making a PUT request to /security/users/{username} with a JSON payload.
func updatePassword(apiURL, token, username, newPassword string) error {
	updateURL := fmt.Sprintf("%s/security/users/%s", apiURL, username)
	payload := map[string]string{
		"password": newPassword,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", updateURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("password update failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// promptInput reads a line from standard input with a prompt.
func promptInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func main() {
	// Prompt for configuration details.
	apiURL := promptInput("Enter the Wazuh API URL (e.g., https://wazuh.domain.com:55000): ")
	authUser := promptInput("Enter the API username (e.g., wazuh-wui): ")
	authPass := promptInput("Enter the current API password: ")
	newPass := promptInput("Enter the NEW API password: ")

	// Authenticate to get a JWT token.
	fmt.Println("\nAuthenticating to the Wazuh API...")
	token, err := authenticate(apiURL, authUser, authPass)
	if err != nil {
		fmt.Printf("Error during authentication: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Authentication successful.")

	// Update the password.
	fmt.Println("\nUpdating password...")
	if err := updatePassword(apiURL, token, authUser, newPass); err != nil {
		fmt.Printf("Error updating password: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Password updated successfully.")
}

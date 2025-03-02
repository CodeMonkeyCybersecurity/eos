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
	Protocol     string `json:"Protocol"`
	FQDN         string `json:"FQDN"`
	Port         string `json:"Port"`
	API_User     string `json:"API_User"`
	API_Password string `json:"API_Password"`
	Endpoint     string `json:"Endpoint"`
	Token        string `json:"Token,omitempty"`
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

// authenticate logs in to the Wazuh API using basic auth and returns the JWT token.
func authenticate(cfg Config) (string, error) {
	url := fmt.Sprintf("https://%s:%s/security/user/authenticate?raw=true", cfg.FQDN, cfg.Port)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(cfg.API_User, cfg.API_Password)

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

// getResponse makes an HTTP request and returns the parsed JSON response.
func getResponse(method, url string, headers map[string]string, verify bool) map[string]interface{} {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(strings.ToUpper(method), url, nil)
	if err != nil {
		fmt.Printf("Error creating %s request to %s: %v\n", method, url, err)
		os.Exit(1)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making %s request to %s: %v\n", method, url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response from %s: %v\n", url, err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error obtaining response (%d): %s\n", resp.StatusCode, string(respData))
		os.Exit(1)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respData, &result); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		os.Exit(1)
	}
	return result
}

// Agent represents an individual agent returned by the API.
type Agent struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// AgentsResponse represents the API response for the agents query.
type AgentsResponse struct {
	Data struct {
		AffectedItems []Agent `json:"affected_items"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

func main() {
	// Define the expected version (if not provided by configuration, user will be prompted).
	// We'll later update configuration with the LatestVersion entered by the user.
	
	// Load configuration from .delphi.json.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Confirm or update the configuration.
	cfg = confirmConfig(cfg)

	// Set default values for Protocol and Port if empty.
	if cfg.Protocol == "" {
		cfg.Protocol = "https"
	}
	if cfg.Port == "" {
		cfg.Port = "55000"
	}

	// Authenticate to get the JWT token if not already present.
	if cfg.Token == "" {
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
		fmt.Println("\nJWT token retrieved.")
	}

	// Set the endpoint for querying agent id and version if not provided.
	if cfg.Endpoint == "" {
		cfg.Endpoint = "/agents?select=id,version"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
	fullURL := baseURL + cfg.Endpoint

	fmt.Printf("\nRequesting agent information from %s ...\n\n", fullURL)
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", cfg.Token),
	}
	result := getResponse("GET", fullURL, headers, false)

	// Decode response into our AgentsResponse structure.
	var agentsResp AgentsResponse
	respBytes, err := json.Marshal(result)
	if err != nil {
		fmt.Printf("Error encoding response: %v\n", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(respBytes, &agentsResp); err != nil {
		fmt.Printf("Error decoding response: %v\n", err)
		os.Exit(1)
	}

	// Ask the user for the expected (latest) API version.
	expectedVersion := promptInput("Enter the latest API version", cfg.LatestVersion)
	if expectedVersion != "" {
	    cfg.LatestVersion = expectedVersion
	}
	saveConfig(cfg)
	if err := saveConfig(cfg); err != nil {
		fmt.Printf("Error saving configuration with latest version: %v\n", err)
		os.Exit(1)
	}

	// Inspect agents and print those that are out of date.
	fmt.Printf("\nInspecting agents for version mismatch (expected version: %s):\n", expectedVersion)
	foundOutdated := false
	for _, agent := range agentsResp.Data.AffectedItems {
		// Remove "Wazuh v" prefix if present.
		actualVersion := strings.TrimPrefix(agent.Version, "Wazuh v")
		if actualVersion != expectedVersion {
			fmt.Printf("Agent %s is out of date (version: %s)\n", agent.ID, agent.Version)
			foundOutdated = true
		}
	}
	if !foundOutdated {
		fmt.Println("All agents are up to date.")
	}
}

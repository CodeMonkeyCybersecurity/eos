package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
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

// OSInfo holds OS details for an agent.
type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

// Agent represents an individual agent returned by the API.
type Agent struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	OS      OSInfo `json:"os"`
}

// AgentsResponse represents the API response for the agents query.
type AgentsResponse struct {
	Data struct {
		AffectedItems []Agent `json:"affected_items"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

// PackageMapping holds the criteria and corresponding package.
type PackageMapping struct {
	Distribution string // e.g., "centos", "debian", "ubuntu"
	MinVersion   int    // minimum major version number
	Arch         string // e.g., "x86_64", "i386", "aarch64", "armhf"
	Package      string // package filename
}

func getMappings(distribution string) []PackageMapping {
	switch strings.ToLower(distribution) {
	case "centos":
		return []PackageMapping{
			{Distribution: "centos", MinVersion: 7, Arch: "x86_64", Package: "wazuh-agent-4.11.0-1.x86_64.rpm"},
			{Distribution: "centos", MinVersion: 7, Arch: "i386", Package: "wazuh-agent-4.11.0-1.i386.rpm"},
			{Distribution: "centos", MinVersion: 7, Arch: "aarch64", Package: "wazuh-agent-4.11.0-1.aarch64.rpm"},
			{Distribution: "centos", MinVersion: 7, Arch: "armhf", Package: "wazuh-agent-4.11.0-1.armv7hl.rpm"},
		}
	case "debian":
		return []PackageMapping{
			{Distribution: "debian", MinVersion: 8, Arch: "amd64", Package: "wazuh-agent_4.11.0-1_amd64.deb"},
			{Distribution: "debian", MinVersion: 8, Arch: "i386", Package: "wazuh-agent_4.11.0-1_i386.deb"},
		}
	case "ubuntu":
		return []PackageMapping{
			{Distribution: "ubuntu", MinVersion: 13, Arch: "amd64", Package: "wazuh-agent_4.11.0-1_amd64.deb"},
			{Distribution: "ubuntu", MinVersion: 13, Arch: "i386", Package: "wazuh-agent_4.11.0-1_i386.deb"},
		}
	default:
		return nil
	}
}

// getMajorVersion extracts the major version number from a version string.
func getMajorVersion(versionStr string) (int, error) {
	parts := strings.Split(versionStr, ".")
	return strconv.Atoi(parts[0])
}

func main() {
	// Load configuration.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Confirm or update the configuration.
	cfg = confirmConfig(cfg)

	// Set default values.
	if cfg.Protocol == "" {
		cfg.Protocol = "https"
	}
	if cfg.Port == "" {
		cfg.Port = "55000"
	}

	// Construct the API URL.
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

	// Query agent details (OS information included).
	agentsEndpoint := fmt.Sprintf("%s/agents?select=id,os,version", apiURL)
	req, err := http.NewRequest("GET", agentsEndpoint, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error obtaining response (%d): %s\n", resp.StatusCode, string(bodyBytes))
		os.Exit(1)
	}
	var agentsResp AgentsResponse
	if err := json.Unmarshal(bodyBytes, &agentsResp); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		os.Exit(1)
	}

	// For each agent, determine the appropriate package.
	for _, agent := range agentsResp.Data.AffectedItems {
		fmt.Printf("\nAgent %s:\n", agent.ID)
		fmt.Printf("  OS Name: %s\n", agent.OS.Name)
		fmt.Printf("  OS Version: %s\n", agent.OS.Version)
		fmt.Printf("  Architecture: %s\n", agent.OS.Architecture)
		mappings := getMappings(agent.OS.Name)
		if mappings == nil {
			fmt.Printf("  No package mapping available for distribution: %s\n", agent.OS.Name)
			continue
		}
		majorVer, err := getMajorVersion(agent.OS.Version)
		if err != nil {
			fmt.Printf("  Error parsing OS version: %v\n", err)
			continue
		}
		var found *PackageMapping
		archLower := strings.ToLower(agent.OS.Architecture)
		for _, m := range mappings {
			if archLower == m.Arch && majorVer >= m.MinVersion {
				found = &m
				break
			}
		}
		if found == nil {
			fmt.Printf("  No package mapping found for %s %s (%s)\n", agent.OS.Name, agent.OS.Version, agent.OS.Architecture)
		} else {
			fmt.Printf("  Appropriate package: %s\n", found.Package)
		}
	}
}

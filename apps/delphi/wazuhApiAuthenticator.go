package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Config represents the configuration file structure.
type Config struct {
	Protocol      string `json:"protocol"`
	Host          string `json:"host"`
	Port          string `json:"port"`
	User          string `json:"user"`
	Password      string `json:"password"`
	LoginEndpoint string `json:"login_endpoint"`
	JWTToken      string `json:"jwt_token,omitempty"`
}

const configFile = "config.json"

// loadConfig loads configuration settings from config.json.
func loadConfig() Config {
	var cfg Config
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("Error parsing configuration: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// saveConfig writes updated configuration settings back to config.json.
func saveConfig(cfg Config) {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		fmt.Printf("Error encoding configuration: %v\n", err)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(configFile, data, 0644); err != nil {
		fmt.Printf("Error saving configuration: %v\n", err)
		os.Exit(1)
	}
}

// promptInput prompts the user for a value and returns the new value or the current one if nothing is entered.
func promptInput(prompt, current string) string {
	reader := bufio.NewReader(os.Stdin)
	if current != "" {
		fmt.Printf("  %s [%s]: ", prompt, current)
	} else {
		fmt.Printf("  %s: ", prompt)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return current
	}
	return input
}

// confirmConfig displays the current configuration and allows the user to update values.
func confirmConfig(cfg Config) Config {
	keys := []string{"protocol", "host", "port", "user", "password", "login_endpoint"}
	fmt.Println("Current configuration:")
	fmt.Printf("  protocol:      %s\n", cfg.Protocol)
	fmt.Printf("  host:          %s\n", cfg.Host)
	fmt.Printf("  port:          %s\n", cfg.Port)
	fmt.Printf("  user:          %s\n", cfg.User)
	fmt.Printf("  password:      %s\n", cfg.Password)
	fmt.Printf("  login_endpoint:%s\n", cfg.LoginEndpoint)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Are these values correct? (y/n): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		cfg.Protocol = promptInput("protocol", cfg.Protocol)
		cfg.Host = promptInput("host", cfg.Host)
		cfg.Port = promptInput("port", cfg.Port)
		cfg.User = promptInput("user", cfg.User)
		cfg.Password = promptInput("password", cfg.Password)
		cfg.LoginEndpoint = promptInput("login_endpoint", cfg.LoginEndpoint)
		saveConfig(cfg)
		fmt.Println("Configuration updated.\n")
	}
	return cfg
}

// AuthResponse models the JSON response from the login endpoint.
type AuthResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

// authenticate performs a login request using Basic Authentication to retrieve the JWT token.
func authenticate(cfg Config) string {
	// Build the URL.
	url := fmt.Sprintf("%s://%s:%s/%s", cfg.Protocol, cfg.Host, cfg.Port, cfg.LoginEndpoint)

	// Create the basic auth header.
	authStr := fmt.Sprintf("%s:%s", cfg.User, cfg.Password)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authStr))
	loginHeaders := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Basic %s", encodedAuth),
	}

	fmt.Println("\nLogin request ...\n")
	// Create a custom HTTP client that skips certificate verification.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		fmt.Printf("Error creating login request: %v\n", err)
		os.Exit(1)
	}
	for k, v := range loginHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Login request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading login response: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Login failed (%d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		fmt.Printf("Error parsing login response: %v\n", err)
		os.Exit(1)
	}

	token := authResp.Data.Token
	if token == "" {
		fmt.Println("Error: token not found in login response")
		os.Exit(1)
	}

	fmt.Println("Token received:\n", token)
	return token
}

// getAPIInfo retrieves API information from the Wazuh API.
func getAPIInfo(cfg Config, token string) {
	url := fmt.Sprintf("%s://%s:%s/?pretty=true", cfg.Protocol, cfg.Host, cfg.Port)
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
	fmt.Println("\nGetting API information:\n")
	makeGetRequest(url, headers)
}

// getAgentsStatus retrieves the agents status summary from the Wazuh API.
func getAgentsStatus(cfg Config, token string) {
	url := fmt.Sprintf("%s://%s:%s/agents/summary/status?pretty=true", cfg.Protocol, cfg.Host, cfg.Port)
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
	fmt.Println("\nGetting agents status summary:\n")
	makeGetRequest(url, headers)
}

// makeGetRequest is a helper to perform GET requests and print the response.
func makeGetRequest(url string, headers map[string]string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating GET request: %v\n", err)
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error retrieving data: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}
	fmt.Println(string(body))
}

func main() {
	// Load and confirm configuration.
	cfg := loadConfig()
	cfg = confirmConfig(cfg)

	// Authenticate and get a JWT token.
	token := authenticate(cfg)
	cfg.JWTToken = token
	saveConfig(cfg)

	// Perform API calls using the token.
	getAPIInfo(cfg, token)
	getAgentsStatus(cfg, token)

	fmt.Println("\nEnd of the script.\n")
}

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Config holds configuration data.
type Config struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	JWTToken string `json:"jwt_token,omitempty"`
}

const configFile = "config.json"

// loadConfig reads and unmarshals the config file.
func loadConfig() Config {
	var cfg Config
	file, err := os.Open(configFile)
	if err != nil {
		fmt.Printf("Error: %s not found.\n", configFile)
		os.Exit(1)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		fmt.Printf("Error parsing %s: %v\n", configFile, err)
		os.Exit(1)
	}
	return cfg
}

// saveConfig writes the configuration back to the file.
func saveConfig(cfg Config) {
	f, err := os.Create(configFile)
	if err != nil {
		fmt.Printf("Error writing to %s: %v\n", configFile, err)
		os.Exit(1)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "    ")
	if err := enc.Encode(cfg); err != nil {
		fmt.Printf("Error encoding config: %v\n", err)
		os.Exit(1)
	}
}

// promptInput prompts the user for input, with an optional default value.
func promptInput(prompt, currentVal string) string {
	reader := bufio.NewReader(os.Stdin)
	if currentVal != "" {
		fmt.Printf("  %s [%s]: ", prompt, currentVal)
	} else {
		fmt.Printf("  %s: ", prompt)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return currentVal
	}
	return input
}

// confirmConfig displays the current configuration and prompts for changes.
func confirmConfig(cfg Config) Config {
	fmt.Println("Current configuration:")
	fmt.Printf("  protocol: %s\n", cfg.Protocol)
	fmt.Printf("  host:     %s\n", cfg.Host)
	fmt.Printf("  port:     %s\n", cfg.Port)
	fmt.Printf("  user:     %s\n", cfg.User)
	fmt.Printf("  password: %s\n", cfg.Password)

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
		saveConfig(cfg)
		fmt.Println("Configuration updated.\n")
	}
	return cfg
}

// authenticate sends credentials to the API and returns the JWT token.
func authenticate(cfg Config) string {
	url := fmt.Sprintf("%s://%s:%s/security/user/auth", cfg.Protocol, cfg.Host, cfg.Port)
	payload := map[string]string{
		"username": cfg.User,
		"password": cfg.Password,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshalling payload: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Authenticating...")
	// Create a custom HTTP client that skips certificate verification.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Authentication request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Authentication failed (%d): %s\n", resp.StatusCode, string(bodyBytes))
		os.Exit(1)
	}

	var respData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &respData); err != nil {
		fmt.Printf("Error parsing authentication response: %v\n", err)
		os.Exit(1)
	}

	token, ok := respData["data"].(string)
	if !ok || token == "" {
		fmt.Println("Failed to retrieve token from authentication response.")
		os.Exit(1)
	}
	fmt.Println("Authentication successful. Retrieved new token.\n")
	return token
}

// getUserDetails retrieves user details from the API.
func getUserDetails(cfg Config, token string) (*http.Response, []byte) {
	url := fmt.Sprintf("%s://%s:%s/security/users/%s", cfg.Protocol, cfg.Host, cfg.Port, cfg.User)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating user details request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("User details request failed: %v\n", err)
		os.Exit(1)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading user details response: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	return resp, body
}

func main() {
	// Load configuration.
	cfg := loadConfig()

	// Confirm or update configuration.
	cfg = confirmConfig(cfg)

	// Check if a JWT token already exists.
	if cfg.JWTToken == "" {
		cfg.JWTToken = authenticate(cfg)
		saveConfig(cfg)
	}

	// Retrieve user details using the stored token.
	resp, body := getUserDetails(cfg, cfg.JWTToken)
	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("Token is invalid or expired. Re-authenticating...")
		cfg.JWTToken = authenticate(cfg)
		saveConfig(cfg)
		resp, body = getUserDetails(cfg, cfg.JWTToken)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error (%d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var userInfo interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		fmt.Printf("Error parsing user details: %v\n", err)
		os.Exit(1)
	}

	prettyUserInfo, err := json.MarshalIndent(userInfo, "", "    ")
	if err != nil {
		fmt.Printf("Error formatting user details: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("User Information:")
	fmt.Println(string(prettyUserInfo))
}

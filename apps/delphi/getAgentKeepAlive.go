package main

import (
	"bufio"
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

const configFile = "config.json"

// Config represents the configuration settings.
type Config struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Endpoint string `json:"endpoint"`
	JwtToken string `json:"jwt_token,omitempty"`
}

// loadConfig reads the configuration from config.json.
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

// saveConfig writes the configuration back to config.json.
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

// promptInput displays a prompt and reads user input.
func promptInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// confirmConfig displays the current configuration and allows the user to update values.
func confirmConfig(cfg Config) Config {
	fmt.Println("Current configuration:")
	fmt.Printf("  protocol: %s\n", cfg.Protocol)
	fmt.Printf("  host:     %s\n", cfg.Host)
	fmt.Printf("  port:     %s\n", cfg.Port)
	fmt.Printf("  user:     %s\n", cfg.User)
	fmt.Printf("  password: %s\n", cfg.Password)

	answer := strings.ToLower(promptInput("Are these values correct? (y/n): "))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		newVal := promptInput(fmt.Sprintf("  protocol [%s]: ", cfg.Protocol))
		if newVal != "" {
			cfg.Protocol = newVal
		}
		newVal = promptInput(fmt.Sprintf("  host [%s]: ", cfg.Host))
		if newVal != "" {
			cfg.Host = newVal
		}
		newVal = promptInput(fmt.Sprintf("  port [%s]: ", cfg.Port))
		if newVal != "" {
			cfg.Port = newVal
		}
		newVal = promptInput(fmt.Sprintf("  user [%s]: ", cfg.User))
		if newVal != "" {
			cfg.User = newVal
		}
		newVal = promptInput(fmt.Sprintf("  password [%s]: ", cfg.Password))
		if newVal != "" {
			cfg.Password = newVal
		}
		saveConfig(cfg)
		fmt.Println("Configuration updated.\n")
	}
	return cfg
}

// getResponse makes an HTTP request and returns the parsed JSON response.
func getResponse(method, url string, headers map[string]string, verify bool, body io.Reader) map[string]interface{} {
	// Create a custom HTTP client.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(strings.ToUpper(method), url, body)
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

// authenticate logs in to the Wazuh API using Basic Authentication and returns the JWT token.
func authenticate(cfg Config) string {
	protocol := cfg.Protocol
	host := cfg.Host
	port := cfg.Port
	user := cfg.User
	password := cfg.Password

	baseURL := fmt.Sprintf("%s://%s:%s", protocol, host, port)
	loginURL := baseURL + "/security/user/authenticate"

	// Create the Basic Auth header.
	authStr := fmt.Sprintf("%s:%s", user, password)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authStr))
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Basic " + encodedAuth,
	}

	fmt.Println("\nLogin request ...\n")
	result := getResponse("POST", loginURL, headers, false, nil)
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		fmt.Println("Error: no data found in authentication response.")
		os.Exit(1)
	}
	token, ok := data["token"].(string)
	if !ok || token == "" {
		fmt.Println("Error: No token found in authentication response.")
		os.Exit(1)
	}

	fmt.Println("Authentication successful. Token received.")
	return token
}

func main() {
	// Load and confirm configuration.
	cfg := loadConfig()
	cfg = confirmConfig(cfg)

	// Set default endpoint if not provided.
	if cfg.Endpoint == "" {
		cfg.Endpoint = "/agents?select=lastKeepAlive&select=id&status=disconnected"
	}

	protocol := cfg.Protocol
	host := cfg.Host
	port := cfg.Port
	baseURL := fmt.Sprintf("%s://%s:%s", protocol, host, port)

	// Authenticate to get the JWT token.
	token := authenticate(cfg)
	cfg.JwtToken = token
	saveConfig(cfg)

	// Setup headers for further API requests.
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}

	fullURL := baseURL + cfg.Endpoint
	fmt.Printf("\nRequesting data from %s ...\n\n", fullURL)
	response := getResponse("GET", fullURL, headers, false, nil)

	// Pretty-print the JSON response.
	pretty, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		fmt.Printf("Error formatting response: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Response:")
	fmt.Println(string(pretty))
}

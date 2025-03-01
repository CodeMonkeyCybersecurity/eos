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
)

// Config represents the configuration stored in .delphi.json.
type Config struct {
	Protocol  string `json:"protocol"`
	FQDN    string `json:"FQDN"`
	Port      string `json:"port"`
	API_User  string `json:"API_User"`
	API_Password string `json:"API_Password"`
	Endpoint  string `json:"endpoint"`
	Token     string `json:"TOKEN,omitempty"`
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

// confirmConfig displays the current configuration and allows the user to update values.
func confirmConfig(cfg Config) Config {
	fmt.Println("Current configuration:")
	fmt.Printf("  protocol: %s\n", cfg.Protocol)
	fmt.Printf("  FQDN:  %s\n", cfg.FQDN)
	fmt.Printf("  port:     %s\n", cfg.Port)
	fmt.Printf("  WZ_API_USR:  %s\n", cfg.API_User)
	fmt.Printf("  WZ_API_PASSWD: %s\n", cfg.API_Password)

	answer := strings.ToLower(promptInput("Are these values correct? (y/n): ", "y"))
	if answer != "y" {
		fmt.Println("Enter new values (press Enter to keep the current value):")
		newVal := promptInput(fmt.Sprintf("  protocol [%s]: ", cfg.Protocol), cfg.Protocol)
		if newVal != "" {
			cfg.Protocol = newVal
		}
		newVal = promptInput(fmt.Sprintf("  FQDN [%s]: ", cfg.FQDN), cfg.FQDN)
		if newVal != "" {
			cfg.FQDN = newVal
		}
		newVal = promptInput(fmt.Sprintf("  port [%s]: ", cfg.Port), cfg.Port)
		if newVal != "" {
			cfg.Port = newVal
		}
		newVal = promptInput(fmt.Sprintf("  WZ_API_USR [%s]: ", cfg.API_User), cfg.API_User)
		if newVal != "" {
			cfg.API_User = newVal
		}
		newVal = promptInput(fmt.Sprintf("  WZ_API_PASSWD [%s]: ", cfg.API_Password), cfg.API_Password)
		if newVal != "" {
			cfg.API_Password = newVal
		}
		// Optionally save the updated config
		if err := saveConfig(cfg); err != nil {
			fmt.Printf("Error saving configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration updated.\n")
	}
	return cfg
}

// saveConfig writes the configuration back to .delphi.json.
func saveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFile, data, 0644)
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

func main() {
	// Load configuration from .delphi.json.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Confirm or update the configuration.
	cfg = confirmConfig(cfg)

	// Set default values for protocol and port if empty.
	if cfg.Protocol == "" {
		cfg.Protocol = "https"
	}
	if cfg.Port == "" {
		cfg.Port = "55000"
	}
	// Optionally, save the configuration if defaults were set.
	saveConfig(cfg)

	// Use the configuration values.
	baseURL := fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
	if cfg.Endpoint == "" {
		cfg.Endpoint = "/agents?select=lastKeepAlive&select=id&status=disconnected"
	}
	fullURL := baseURL + cfg.Endpoint

	fmt.Printf("\nRequesting data from %s ...\n\n", fullURL)
	headers := map[string]string{
	    "Content-Type":  "application/json",
	    "Authorization": fmt.Sprintf("Bearer %s", cfg.Token),
	}
	response := getResponse("GET", fullURL, headers, false)

	// Pretty-print the JSON response.
	pretty, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		fmt.Printf("Error formatting response: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Response:")
	fmt.Println(string(pretty))
}

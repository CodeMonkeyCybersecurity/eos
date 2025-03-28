// pkg/config/delphi.go
package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type DelphiConfig struct {
	Protocol      string `json:"Protocol"`
	FQDN          string `json:"FQDN"`
	Port          string `json:"Port"`
	API_User      string `json:"API_User"`
	API_Password  string `json:"API_Password"`
	Endpoint      string `json:"Endpoint"`
	Token         string `json:"Token,omitempty"`
	LatestVersion string `json:"LatestVersion,omitempty"`
}

const delphiConfigFile = ".delphi.json"

func LoadDelphiConfig() (DelphiConfig, error) {
	var cfg DelphiConfig
	data, err := os.ReadFile(delphiConfigFile)
	if err != nil {
		return cfg, fmt.Errorf("unable to read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("unable to parse config: %w", err)
	}
	return cfg, nil
}

func SaveDelphiConfig(cfg DelphiConfig) error {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to marshal config: %w", err)
	}
	return os.WriteFile(delphiConfigFile, data, 0644)
}

// Authenticate connects to the Wazuh API using Basic Auth and returns a JWT token.
func Authenticate(apiURL, username, password string) (string, error) {
	authURL := fmt.Sprintf("%s/security/user/authenticate?raw=true", strings.TrimRight(apiURL, "/"))
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(username, password)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed (%d): %s", resp.StatusCode, string(body))
	}

	return strings.TrimSpace(string(body)), nil
}

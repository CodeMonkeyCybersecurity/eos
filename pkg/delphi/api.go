// pkg/delphi/api.go
package delphi

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"net/http"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

func LoadAndConfirmConfig() (*config.DelphiConfig, error) {
	raw, err := os.ReadFile("config.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read config.json: %w", err)
	}

	var cfg config.DelphiConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config.json: %w", err)
	}

	fmt.Println("Loaded configuration:")
	fmt.Printf("  Protocol: %s\n  Host: %s\n  Port: %s\n  User: %s\n", cfg.Protocol, cfg.FQDN, cfg.Port, cfg.API_User)
	fmt.Print("Are these values correct? (y/N): ")
	if !utils.YesOrNo() {
		fields := []string{"protocol", "host", "port", "user", "password"}
		for _, field := range fields {
			fmt.Printf("  %s [%v]: ", field, GetFieldValue(cfg, field))
			if v := utils.ReadLine(); v != "" {
				SetFieldValue(&cfg, field, v)
			}
		}
		newConfig, _ := json.MarshalIndent(cfg, "", "  ")
		_ = os.WriteFile("config.json", newConfig, 0644)
	}

	return &cfg, nil
}

func DeleteAgent(agentID string, token string, config *config.DelphiConfig) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s://%s:%s/agents/%s?pretty=true", config.Protocol, config.FQDN, config.Port, agentID)

	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func GetFieldValue(config config.DelphiConfig, field string) string {
	switch field {
	case "protocol":
		return config.Protocol
	case "host":
		return config.FQDN
	case "port":
		return config.Port
	case "user":
		return config.API_User
	case "password":
		return config.API_Password
	default:
		return ""
	}
}

func SetFieldValue(config *config.DelphiConfig, field, value string) {
	switch field {
	case "protocol":
		config.Protocol = value
	case "host":
		config.FQDN = value
	case "port":
		config.Port = value
	case "user":
		config.API_User = value
	case "password":
		config.API_Password = value
	}
}

// Authenticate logs in to the Wazuh API using basic auth and returns the JWT token.
func Authenticate(cfg config.DelphiConfig) (string, error) {
	url := fmt.Sprintf("https://%s:55000/security/user/authenticate?raw=true", cfg.FQDN)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(cfg.API_User, cfg.API_Password)

	// Create an HTTP client that skips certificate verification.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyCertificates},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("no token received")
	}
	return token, nil
}

// GetUserDetails queries Wazuh API for user info using a valid token.
func GetUserDetails(cfg config.DelphiConfig) ([]byte, int) {
	resp, err := AuthenticatedGet(cfg, fmt.Sprintf("/security/users/%s", cfg.API_User))
	if err != nil {
		fmt.Printf("❌ Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode
}


func AuthenticatedGet(cfg config.DelphiConfig, path string) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", BaseURL(cfg), strings.TrimPrefix(path, "/"))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyCertificates},
		},
	}
	return client.Do(req)
}

func AuthenticatedPost(cfg config.DelphiConfig, path string, body io.Reader) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", BaseURL(cfg), strings.TrimPrefix(path, "/"))
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyCertificates},
		},
	}
	return client.Do(req)
}


func BaseURL(cfg config.DelphiConfig) string {
	return fmt.Sprintf("%s://%s:%s", cfg.Protocol, cfg.FQDN, cfg.Port)
}

func AuthenticatedGetJSON(cfg config.DelphiConfig, path string) ([]byte, int) {
	resp, err := AuthenticatedGet(cfg, path)
	if err != nil {
		fmt.Printf("❌ Request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode
}

func HandleAPIResponse(label string, body []byte, code int) {
	if code != http.StatusOK {
		fmt.Printf("❌ Failed to retrieve %s (%d): %s\n", label, code, string(body))
		os.Exit(1)
	}
	var prettyJSON map[string]interface{}
	if err := json.Unmarshal(body, &prettyJSON); err != nil {
		fmt.Printf("❌ Failed to parse JSON: %v\n", err)
		os.Exit(1)
	}
	output, _ := json.MarshalIndent(prettyJSON, "", "  ")
	fmt.Printf("✅ %s:\n%s\n", label, string(output))
}
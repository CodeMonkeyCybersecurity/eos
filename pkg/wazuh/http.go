// pkg/wazuh/http.go
package wazuh

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// GetJSON performs an unauthenticated GET request and returns parsed JSON.
func GetJSON(rc *eos_io.RuntimeContext, url string, headers map[string]string) (map[string]any, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: getHTTPTLSConfig(),
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("wazuh API returned %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return result, nil
}

// AuthenticatedGet sends a GET request using a Bearer token.
func AuthenticatedGet(cfg *Config, path string) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", BaseURL(cfg), strings.TrimPrefix(path, "/"))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: getWazuhTLSConfig(),
		},
	}

	return client.Do(req)
}

// AuthenticatedPost sends a POST request using a Bearer token.
func AuthenticatedPost(cfg *Config, path string, body io.Reader) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", BaseURL(cfg), strings.TrimPrefix(path, "/"))

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: getWazuhTLSConfig(),
		},
	}

	return client.Do(req)
}

// AuthenticatedPut sends a PUT request with a JSON payload using a Bearer token.
func AuthenticatedPut(cfg *Config, path string, payload any) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", BaseURL(cfg), strings.TrimPrefix(path, "/"))

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: getWazuhTLSConfig(),
		},
	}

	return client.Do(req)
}

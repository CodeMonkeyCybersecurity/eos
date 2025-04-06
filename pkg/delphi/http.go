// pkg/delphi/http.go
package delphi

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GetJSON performs an unauthenticated GET request and returns parsed JSON.
func GetJSON(url string, headers map[string]string) (map[string]interface{}, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // for unauthenticated GETs
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Delphi API returned %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return result, nil
}

// AuthenticatedGet sends a GET request using a Bearer token.
func AuthenticatedGet(cfg *DelphiConfig, path string) (*http.Response, error) {
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

// AuthenticatedPost sends a POST request using a Bearer token.
func AuthenticatedPost(cfg *DelphiConfig, path string, body io.Reader) (*http.Response, error) {
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

// AuthenticatedPut sends a PUT request with a JSON payload using a Bearer token.
func AuthenticatedPut(cfg *DelphiConfig, path string, payload interface{}) (*http.Response, error) {
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyCertificates},
		},
	}

	return client.Do(req)
}

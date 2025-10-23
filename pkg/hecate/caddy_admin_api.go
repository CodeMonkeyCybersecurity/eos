// pkg/hecate/caddy_admin_api.go - Caddy Admin API integration

package hecate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CaddyAdminClient represents a client for the Caddy Admin API
type CaddyAdminClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewCaddyAdminClient creates a new Caddy Admin API client
// host should be the hostname or IP (without protocol), e.g., "localhost" or "192.168.1.100"
func NewCaddyAdminClient(host string) *CaddyAdminClient {
	// Caddy Admin API typically runs on port 2019
	baseURL := fmt.Sprintf("http://%s:2019", host)

	return &CaddyAdminClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// LoadConfig loads a new configuration to Caddy via the Admin API
// The config should be a Caddy JSON configuration
func (c *CaddyAdminClient) LoadConfig(ctx context.Context, config interface{}) error {
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	url := fmt.Sprintf("%s/load", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonConfig))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("config load request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("config load failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// AdaptCaddyfile converts a Caddyfile to Caddy JSON format using the adapt API
func (c *CaddyAdminClient) AdaptCaddyfile(ctx context.Context, caddyfile string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/adapt", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(caddyfile)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "text/caddyfile")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("adapt request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("adapt failed with status %d: %s", resp.StatusCode, string(body))
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode adapted config: %w", err)
	}

	return config, nil
}

// LoadCaddyfile loads a Caddyfile by first adapting it to JSON, then loading
func (c *CaddyAdminClient) LoadCaddyfile(ctx context.Context, caddyfile string) error {
	// Step 1: Adapt Caddyfile to JSON
	config, err := c.AdaptCaddyfile(ctx, caddyfile)
	if err != nil {
		return fmt.Errorf("failed to adapt Caddyfile: %w", err)
	}

	// Step 2: Load the JSON config
	if err := c.LoadConfig(ctx, config); err != nil {
		return fmt.Errorf("failed to load adapted config: %w", err)
	}

	return nil
}

// GetConfig retrieves the current Caddy configuration
func (c *CaddyAdminClient) GetConfig(ctx context.Context) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/config/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get config request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("get config failed with status %d: %s", resp.StatusCode, string(body))
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return config, nil
}

// Health checks if the Caddy Admin API is responsive
func (c *CaddyAdminClient) Health(ctx context.Context) error {
	url := fmt.Sprintf("%s/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("caddy admin API not responding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("caddy admin API returned status %d", resp.StatusCode)
	}

	return nil
}

// Stop gracefully stops the Caddy server
func (c *CaddyAdminClient) Stop(ctx context.Context) error {
	url := fmt.Sprintf("%s/stop", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("stop request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("stop failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// PatchConfig patches a specific path in the Caddy configuration
func (c *CaddyAdminClient) PatchConfig(ctx context.Context, path string, value interface{}) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	url := fmt.Sprintf("%s/config/%s", c.BaseURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonValue))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("patch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("patch failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteConfig deletes a specific path in the Caddy configuration
func (c *CaddyAdminClient) DeleteConfig(ctx context.Context, path string) error {
	url := fmt.Sprintf("%s/config/%s", c.BaseURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("delete failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// pkg/hecate/caddy_admin_api.go - Caddy Admin API integration

package hecate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CaddyAdminClient represents a client for the Caddy Admin API
type CaddyAdminClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewCaddyAdminClient creates a new Caddy Admin API client
// Connects to Caddy Admin API via HTTP on localhost:2019
// RATIONALE: Unix sockets don't work for host-to-container communication with Docker
// SECURITY: Port only exposed on localhost (127.0.0.1:2019), not accessible from network
// ARCHITECTURE: Eos runs on host, Caddy runs in container - requires TCP, not Unix socket
func NewCaddyAdminClient(host string) *CaddyAdminClient {
	// P0 FIX (2025-10-31): Add connection pooling to prevent "connection reset by peer" errors
	// RATIONALE: Docker networking can reset idle connections in default Go HTTP transport
	// EVIDENCE: https://stackoverflow.com/questions/37774624 (56 upvotes, accepted answer)
	// VENDOR BEST PRACTICE: Caddy documentation recommends MaxIdleConnsPerHost=10 for high-traffic
	// LOCALHOST OPTIMIZATION: Using lower limits (2) since this is single-host localhost API
	// SECURITY: Connection limits prevent resource exhaustion on Caddy Admin API
	transport := &http.Transport{
		MaxIdleConns:        10,               // Total idle connections across all hosts
		MaxIdleConnsPerHost: 2,                // Low for single-host localhost API (not multi-host proxy)
		IdleConnTimeout:     30 * time.Second, // Match Caddy's default keep-alive
	}

	httpClient := &http.Client{
		Timeout:   CaddyAdminAPITimeout,
		Transport: transport,
	}

	// Connect to Admin API on localhost:2019
	// SECURITY: Port only exposed as 127.0.0.1:2019 in docker-compose (not 0.0.0.0)
	baseURL := fmt.Sprintf("http://%s:%d", host, CaddyAdminAPIPort)

	return &CaddyAdminClient{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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

// GetConfig retrieves the current Caddy configuration with retry logic
// Retries transient errors (connection reset) but fails fast on deterministic errors (404, 500)
func (c *CaddyAdminClient) GetConfig(ctx context.Context) (map[string]interface{}, error) {
	var config map[string]interface{}
	var lastErr error

	// Retry configuration
	maxAttempts := 3
	initialDelay := 500 * time.Millisecond
	maxDelay := 5 * time.Second
	delay := initialDelay

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		url := fmt.Sprintf("%s/config/", c.BaseURL)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			// Request creation failure is deterministic - don't retry
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err

			// Check if error is transient (connection reset, timeout, etc.)
			errStr := err.Error()
			isTransient := strings.Contains(errStr, "connection reset") ||
				strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "broken pipe") ||
				strings.Contains(errStr, "connection refused")

			if !isTransient {
				// Deterministic error - don't retry
				return nil, fmt.Errorf("get config request failed: %w", err)
			}

			// Transient error - retry with backoff
			if attempt < maxAttempts {
				time.Sleep(delay)
				delay = time.Duration(float64(delay) * 2)
				if delay > maxDelay {
					delay = maxDelay
				}
				continue
			}

			// Max attempts reached
			return nil, fmt.Errorf("get config request failed after %d attempts: %w", maxAttempts, lastErr)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			// HTTP errors are deterministic - don't retry
			return nil, fmt.Errorf("get config failed with status %d: %s", resp.StatusCode, string(body))
		}

		if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
			// Decode errors are deterministic - don't retry
			return nil, fmt.Errorf("failed to decode config: %w", err)
		}

		// Success
		return config, nil
	}

	return nil, fmt.Errorf("get config failed after %d attempts: %w", maxAttempts, lastErr)
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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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

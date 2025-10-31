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

	"go.uber.org/zap"
)

// CaddyAdminClient represents a client for the Caddy Admin API
type CaddyAdminClient struct {
	BaseURL    string
	HTTPClient *http.Client
	logger     *zap.Logger // Optional logger for structured logging (nil = use stderr)
}

// NewCaddyAdminClient creates a new Caddy Admin API client
// AUTO-DETECTS container IP via Docker SDK to bypass localhost IPv4/IPv6 resolution issues
//
// ARCHITECTURE: Three-tier fallback strategy
//   1. Use provided host if explicitly given (e.g., "192.168.1.100")
//   2. Auto-detect Caddy container IP via Docker SDK (bypasses localhost issues)
//   3. Fall back to localhost:2019 (legacy behavior, may fail with IPv6)
//
// ROOT CAUSE FIXED: Caddy binds to 127.0.0.1 (IPv4) inside container
//                    Host's `localhost` resolves to ::1 (IPv6) first → connection refused
//                    Docker SDK provides container's bridge IP (172.x.x.x) → direct connection
//
// SECURITY: Docker SDK requires socket access (same as `docker ps`)
//           Connection pooling prevents resource exhaustion
func NewCaddyAdminClient(host string) *CaddyAdminClient {
	// Connection pooling configuration
	// RATIONALE: Explicit transport for HTTP/1.1 connection reuse
	// NOTE: MaxIdleConnsPerHost=2 matches Go default (sufficient for single-container API)
	// FUTURE: Increase to 10-20 if Admin API performance becomes bottleneck
	transport := &http.Transport{
		MaxIdleConns:        10,               // Total idle connections across all hosts
		MaxIdleConnsPerHost: 2,                // Sufficient for localhost/container-IP API
		IdleConnTimeout:     30 * time.Second, // Match Caddy's default keep-alive
	}

	httpClient := &http.Client{
		Timeout:   CaddyAdminAPITimeout,
		Transport: transport,
	}

	// Determine which host to use (three-tier fallback)
	var targetHost string
	var strategyUsed string

	if host != "" && host != "localhost" {
		// Tier 1: Explicit host provided (e.g., from env var CADDY_ADMIN_HOST)
		targetHost = host
		strategyUsed = "explicit_host"
	} else {
		// Tier 2: Auto-detect container IP via Docker SDK (best approach)
		// RATIONALE: Bypasses localhost IPv4/IPv6 resolution issues
		// NON-FATAL: If Docker SDK fails, fall back to localhost
		ctx := context.Background()
		if containerIP, err := GetCaddyContainerIP(ctx); err == nil {
			targetHost = containerIP
			strategyUsed = "docker_sdk"
		} else {
			// Tier 3: Fall back to localhost (legacy behavior)
			// WARNING: May fail with IPv6 resolution issues

			// P1 FIX #9: Use structured logging for Docker SDK fallback
			// RATIONALE: Observability is critical for production troubleshooting (CLAUDE.md Rule #1)
			// NOTE: Use global logger if no RuntimeContext available (backward compatibility)
			logger := zap.L()
			logger.Warn("Caddy Admin API - Docker SDK container IP detection failed, falling back to localhost",
				zap.Error(err),
				zap.String("strategy", "localhost_fallback"),
				zap.String("remediation", "Run 'eos debug hecate --caddy' to diagnose Docker SDK issues"),
				zap.String("warning", "localhost may fail with IPv6 resolution issues"))

			targetHost = "localhost"
			strategyUsed = "localhost_fallback"
		}
	}

	baseURL := fmt.Sprintf("http://%s:%d", targetHost, CaddyAdminAPIPort)

	// Log which strategy was used for observability
	logger := zap.L()
	logger.Debug("Caddy Admin API client created",
		zap.String("strategy", strategyUsed),
		zap.String("url", baseURL))

	return &CaddyAdminClient{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		logger:     nil, // Will use zap.L() by default
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

	if result, ok := config["result"]; ok {
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			return fmt.Errorf("adapted config result has unexpected type %T", result)
		}
		// Caddy /adapt wraps the real config under "result"; unwrap so /load sees the root apps/logging keys.
		config = resultMap
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

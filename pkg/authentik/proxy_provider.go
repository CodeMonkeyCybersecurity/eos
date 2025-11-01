// pkg/authentik/proxy_provider.go - Proxy Provider management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ProxyProviderConfig represents the configuration for creating a proxy provider
type ProxyProviderConfig struct {
	Name                string // Provider name
	Mode                string // "forward_single", "forward_domain", or "proxy"
	ExternalHost        string // External URL (e.g., https://app.example.com)
	InternalHost        string // Internal URL (not used in forward auth mode, but required by API)
	AuthorizationFlow   string // Authorization flow slug or UUID
	InvalidationFlow    string // Invalidation flow slug or UUID (required by Authentik API)
	BasicAuthEnabled    *bool  // Whether to enable HTTP basic authentication
	InterceptHeaderAuth *bool  // Whether to accept authentication from upstream headers
	CookieDomain        string // Cookie domain scope (e.g., .example.com)
	AccessTokenValidity string // Token validity duration string (e.g., "hours=1")
}

// ProxyProviderResponse represents a proxy provider from Authentik
type ProxyProviderResponse struct {
	PK                int    `json:"pk"`
	Name              string `json:"name"`
	Mode              string `json:"mode"`
	ExternalHost      string `json:"external_host"`
	InternalHost      string `json:"internal_host"`
	AuthorizationFlow string `json:"authorization_flow"`
	InvalidationFlow  string `json:"invalidation_flow"`
}

// CreateProxyProvider creates a new proxy provider in Authentik
func (c *APIClient) CreateProxyProvider(ctx context.Context, config *ProxyProviderConfig) (*ProxyProviderResponse, error) {
	reqBody := map[string]interface{}{
		"name":               config.Name,
		"authorization_flow": config.AuthorizationFlow,
		"invalidation_flow":  config.InvalidationFlow,
		"mode":               config.Mode,
		"external_host":      config.ExternalHost,
		"internal_host":      config.InternalHost,
	}

	if config.BasicAuthEnabled != nil {
		reqBody["basic_auth_enabled"] = *config.BasicAuthEnabled
	}
	if config.InterceptHeaderAuth != nil {
		reqBody["intercept_header_auth"] = *config.InterceptHeaderAuth
	}
	if config.CookieDomain != "" {
		reqBody["cookie_domain"] = config.CookieDomain
	}
	if config.AccessTokenValidity != "" {
		reqBody["access_token_validity"] = config.AccessTokenValidity
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proxy provider request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/providers/proxy/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxy provider creation request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log but don't override the main error
			_ = closeErr
		}
	}()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy provider creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var provider ProxyProviderResponse
	if err := json.Unmarshal(body, &provider); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proxy provider response: %w", err)
	}

	return &provider, nil
}

// ListProxyProviders lists all proxy providers
func (c *APIClient) ListProxyProviders(ctx context.Context) ([]ProxyProviderResponse, error) {
	url := fmt.Sprintf("%s/api/v3/providers/proxy/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxy providers list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("proxy providers list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []ProxyProviderResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode proxy providers list response: %w", err)
	}

	return result.Results, nil
}

// GetProxyProvider retrieves a proxy provider by PK
func (c *APIClient) GetProxyProvider(ctx context.Context, pk int) (*ProxyProviderResponse, error) {
	url := fmt.Sprintf("%s/api/v3/providers/proxy/%d/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxy provider fetch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("proxy provider fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var provider ProxyProviderResponse
	if err := json.NewDecoder(resp.Body).Decode(&provider); err != nil {
		return nil, fmt.Errorf("failed to decode proxy provider response: %w", err)
	}

	return &provider, nil
}

// DeleteProxyProvider deletes a proxy provider by PK
func (c *APIClient) DeleteProxyProvider(ctx context.Context, pk int) error {
	url := fmt.Sprintf("%s/api/v3/providers/proxy/%d/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("proxy provider deletion request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("proxy provider deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// UpdateProxyProvider updates a proxy provider's configuration
func (c *APIClient) UpdateProxyProvider(ctx context.Context, pk int, config *ProxyProviderConfig) error {
	reqBody := map[string]interface{}{
		"name":               config.Name,
		"authorization_flow": config.AuthorizationFlow,
		"invalidation_flow":  config.InvalidationFlow,
		"mode":               config.Mode,
		"external_host":      config.ExternalHost,
		"internal_host":      config.InternalHost,
	}

	if config.BasicAuthEnabled != nil {
		reqBody["basic_auth_enabled"] = *config.BasicAuthEnabled
	}
	if config.InterceptHeaderAuth != nil {
		reqBody["intercept_header_auth"] = *config.InterceptHeaderAuth
	}
	if config.CookieDomain != "" {
		reqBody["cookie_domain"] = config.CookieDomain
	}
	if config.AccessTokenValidity != "" {
		reqBody["access_token_validity"] = config.AccessTokenValidity
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/providers/proxy/%d/", c.BaseURL, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("proxy provider update request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("proxy provider update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

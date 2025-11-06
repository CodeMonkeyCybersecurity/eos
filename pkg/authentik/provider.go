// pkg/authentik/provider.go - OAuth2/OIDC provider management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// OAuth2ProviderRequest represents the request body for creating an OAuth2 provider
type OAuth2ProviderRequest struct {
	Name              string   `json:"name"`
	AuthorizationFlow string   `json:"authorization_flow"`
	ClientType        string   `json:"client_type"`   // "confidential" or "public"
	RedirectURIs      string   `json:"redirect_uris"` // newline-separated URIs
	PropertyMappings  []string `json:"property_mappings,omitempty"`
	SigningKey        string   `json:"signing_key,omitempty"`
}

// OAuth2ProviderResponse represents the response when creating/fetching an OAuth2 provider
type OAuth2ProviderResponse struct {
	PK                int    `json:"pk"`
	Name              string `json:"name"`
	AuthorizationFlow string `json:"authorization_flow"`
	ClientType        string `json:"client_type"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	RedirectURIs      string `json:"redirect_uris"`
	PropertyMappings  []int  `json:"property_mappings,omitempty"`
	SigningKey        string `json:"signing_key,omitempty"`
}

// CreateOAuth2Provider creates a new OAuth2/OIDC provider in Authentik
func (c *APIClient) CreateOAuth2Provider(ctx context.Context, name string, redirectURIs []string, flow string) (*OAuth2ProviderResponse, error) {
	// Join redirect URIs with newline (Authentik's format)
	uris := strings.Join(redirectURIs, "\n")

	reqBody := OAuth2ProviderRequest{
		Name:              name,
		AuthorizationFlow: flow,
		ClientType:        "confidential", // Confidential client with client secret
		RedirectURIs:      uris,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal provider request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/providers/oauth2/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provider creation request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var provider OAuth2ProviderResponse
	if err := json.Unmarshal(body, &provider); err != nil {
		return nil, fmt.Errorf("failed to unmarshal provider response: %w", err)
	}

	return &provider, nil
}

// GetOAuth2Provider retrieves an OAuth2 provider by PK
func (c *APIClient) GetOAuth2Provider(ctx context.Context, pk int) (*OAuth2ProviderResponse, error) {
	url := fmt.Sprintf("%s/api/v3/providers/oauth2/%d/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provider fetch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("provider fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var provider OAuth2ProviderResponse
	if err := json.NewDecoder(resp.Body).Decode(&provider); err != nil {
		return nil, fmt.Errorf("failed to decode provider response: %w", err)
	}

	return &provider, nil
}

// ListOAuth2Providers lists all OAuth2 providers
func (c *APIClient) ListOAuth2Providers(ctx context.Context) ([]OAuth2ProviderResponse, error) {
	url := fmt.Sprintf("%s/api/v3/providers/oauth2/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("providers list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("providers list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []OAuth2ProviderResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode providers list response: %w", err)
	}

	return result.Results, nil
}

// DeleteOAuth2Provider deletes an OAuth2 provider by PK
func (c *APIClient) DeleteOAuth2Provider(ctx context.Context, pk int) error {
	url := fmt.Sprintf("%s/api/v3/providers/oauth2/%d/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("provider deletion request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("provider deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

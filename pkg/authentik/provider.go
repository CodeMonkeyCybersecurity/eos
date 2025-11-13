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
	ClientType        string   `json:"client_type"` // "confidential" or "public"
	RedirectURIs      string   `json:"redirect_uris"` // newline-separated URIs
	PropertyMappings  []string `json:"property_mappings,omitempty"`
	SubMode           string   `json:"sub_mode,omitempty"` // "user_uuid" for stable identity, "hashed_user_id" (default), "user_id", "user_username"
	SigningKey        string   `json:"signing_key,omitempty"`
}

// OAuth2ProviderResponse represents the response when creating/fetching an OAuth2 provider
type OAuth2ProviderResponse struct {
	PK                int      `json:"pk"`
	Name              string   `json:"name"`
	AuthorizationFlow string   `json:"authorization_flow"`
	ClientType        string   `json:"client_type"`
	ClientID          string   `json:"client_id"`
	ClientSecret      string   `json:"client_secret"`
	RedirectURIs      string   `json:"redirect_uris"`
	PropertyMappings  []string `json:"property_mappings,omitempty"` // FIXED: PKs are UUIDs (strings), not ints
	SigningKey        string   `json:"signing_key,omitempty"`
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

// CreateOAuth2ProviderWithMappings creates a new OAuth2/OIDC provider with property mappings (claims)
// This is the recommended function for creating OIDC providers with custom scopes and claims
// IDEMPOTENCY: Checks if provider already exists by name before creating
// P0-4 FIX: Validate existing provider configuration matches request, fail fast if drift detected
func (c *APIClient) CreateOAuth2ProviderWithMappings(ctx context.Context, name string, redirectURIs []string, flow string, propertyMappingPKs []string) (*OAuth2ProviderResponse, error) {
	// Join redirect URIs for comparison
	uris := strings.Join(redirectURIs, "\n")

	// Check if provider already exists
	existing, err := c.findOAuth2ProviderByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing providers: %w", err)
	}

	if existing != nil {
		// P0-4 FIX: Validate configuration matches
		var configMismatches []string

		// Check redirect URIs
		if existing.RedirectURIs != uris {
			configMismatches = append(configMismatches,
				fmt.Sprintf("redirect URIs differ (existing: %s, requested: %s)",
					strings.TrimSpace(existing.RedirectURIs), strings.TrimSpace(uris)))
		}

		// Check authorization flow
		if existing.AuthorizationFlow != flow {
			configMismatches = append(configMismatches,
				fmt.Sprintf("authorization flow differs (existing: %s, requested: %s)",
					existing.AuthorizationFlow, flow))
		}

		// Check property mappings count (rough check, full comparison complex)
		if len(existing.PropertyMappings) != len(propertyMappingPKs) {
			configMismatches = append(configMismatches,
				fmt.Sprintf("property mapping count differs (existing: %d, requested: %d)",
					len(existing.PropertyMappings), len(propertyMappingPKs)))
		}

		if len(configMismatches) > 0 {
			return nil, fmt.Errorf("OAuth2 provider '%s' already exists with different configuration:\n"+
				"  %s\n\n"+
				"To fix:\n"+
				"  1. Delete existing provider in Authentik UI (Providers → OAuth2)\n"+
				"  2. Re-run this command\n\n"+
				"OR manually update the provider configuration to match",
				name, strings.Join(configMismatches, "\n  "))
		}

		// Configuration matches, return existing provider (idempotent)
		return existing, nil
	}

	// Create new provider (uris already joined above for comparison)

	reqBody := OAuth2ProviderRequest{
		Name:              name,
		AuthorizationFlow: flow,
		ClientType:        "confidential", // Confidential client with client secret (supports PKCE)
		RedirectURIs:      uris,
		PropertyMappings:  propertyMappingPKs, // Attach custom claims
		SubMode:           "user_uuid",        // CRITICAL: Use UUID for stable identity (not hashed_user_id)
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

// findOAuth2ProviderByName searches for an existing OAuth2 provider by name
// Returns nil if not found (not an error condition)
func (c *APIClient) findOAuth2ProviderByName(ctx context.Context, name string) (*OAuth2ProviderResponse, error) {
	providers, err := c.ListOAuth2Providers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list providers: %w", err)
	}

	for _, provider := range providers {
		if provider.Name == name {
			return &provider, nil
		}
	}

	return nil, nil // Not found (not an error)
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

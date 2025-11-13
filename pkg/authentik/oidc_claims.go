// pkg/authentik/oidc_claims.go - OIDC property mapping (scope/claim) management

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OIDCPropertyMappingRequest represents a request to create an OIDC property mapping
// OIDC property mappings define how user attributes map to JWT claims
type OIDCPropertyMappingRequest struct {
	Name       string `json:"name"`        // Human-readable name (e.g., "OIDC Email")
	Expression string `json:"expression"`  // Python expression (e.g., "return request.user.email")
	Scope      string `json:"scope_name"`  // Scope this mapping belongs to (e.g., "email", "profile", "groups")
}

// OIDCPropertyMappingResponse represents an OIDC property mapping from Authentik
type OIDCPropertyMappingResponse struct {
	PK         string `json:"pk"`          // Primary key (UUID)
	Name       string `json:"name"`
	Expression string `json:"expression"`
	Scope      string `json:"scope_name"`
	Managed    string `json:"managed,omitempty"` // Authentik-managed mappings (e.g., "goauthentik.io/providers/oauth2/scope-email")
}

// OIDCScopeMapping defines standard OIDC scopes and their claims
// Based on OpenID Connect Core 1.0 specification: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
type OIDCScopeMapping struct {
	ScopeName string   // Scope name (openid, profile, email, groups)
	Claims    []string // Claims included in this scope
}

var (
	// StandardOIDCScopes defines the standard OIDC scopes per spec
	StandardOIDCScopes = []OIDCScopeMapping{
		{
			ScopeName: "openid",
			Claims:    []string{"sub"}, // Subject identifier (stable user ID)
		},
		{
			ScopeName: "profile",
			Claims:    []string{"name", "preferred_username", "given_name", "family_name"},
		},
		{
			ScopeName: "email",
			Claims:    []string{"email", "email_verified"},
		},
	}

	// DEPRECATED: MoniRequiredMappings - We now use Authentik's managed default scope mappings instead
	// RATIONALE: Authentik provides pre-configured scope mappings for openid, profile, email scopes
	// These managed mappings are maintained by Authentik and follow OIDC specifications
	// We only create a custom "groups" scope mapping since it's not included by default
	//
	// What Authentik provides by default:
	// - goauthentik.io/providers/oauth2/scope-openid: sub claim (uses provider's sub_mode setting)
	// - goauthentik.io/providers/oauth2/scope-email: email, email_verified claims
	// - goauthentik.io/providers/oauth2/scope-profile: name, preferred_username, nickname, groups
	//
	// What we add custom:
	// - groups scope: Returns {"groups": ["group1", "group2"]} for authorization
	//
	// SECURITY: Stable identity (sub=UUID) is configured via OAuth2Provider.SubMode="user_uuid"
	_ = []OIDCPropertyMappingRequest{} // Kept for reference, not used
)

// CreateOIDCPropertyMapping creates a single OIDC property mapping in Authentik
// IDEMPOTENCY: Checks if mapping already exists by name before creating
func (c *APIClient) CreateOIDCPropertyMapping(ctx context.Context, mapping OIDCPropertyMappingRequest) (*OIDCPropertyMappingResponse, error) {
	// Check if mapping already exists
	existing, err := c.findOIDCPropertyMapping(ctx, mapping.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing mappings: %w", err)
	}

	if existing != nil {
		// Already exists, return it (idempotent)
		return existing, nil
	}

	// Create new mapping
	jsonBody, err := json.Marshal(mapping)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal mapping request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/propertymappings/scope/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("property mapping creation request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("property mapping creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result OIDCPropertyMappingResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal property mapping response: %w", err)
	}

	return &result, nil
}

// findOIDCPropertyMapping searches for an existing OIDC property mapping by name
// Returns nil if not found (not an error condition)
func (c *APIClient) findOIDCPropertyMapping(ctx context.Context, name string) (*OIDCPropertyMappingResponse, error) {
	url := fmt.Sprintf("%s/api/v3/propertymappings/scope/?search=%s", c.BaseURL, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("property mapping search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("property mapping search failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []OIDCPropertyMappingResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode property mapping search response: %w", err)
	}

	// Look for exact name match
	for _, mapping := range result.Results {
		if mapping.Name == name {
			return &mapping, nil
		}
	}

	return nil, nil // Not found (not an error)
}

// ListOIDCPropertyMappings lists all OIDC property mappings
func (c *APIClient) ListOIDCPropertyMappings(ctx context.Context) ([]OIDCPropertyMappingResponse, error) {
	url := fmt.Sprintf("%s/api/v3/propertymappings/scope/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("property mappings list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("property mappings list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []OIDCPropertyMappingResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode property mappings list response: %w", err)
	}

	return result.Results, nil
}

// CreateMoniOIDCMappings creates all required OIDC property mappings for Moni integration
// STRATEGY: Use Authentik's managed default scopes (openid, profile, email) + create custom groups scope
// Returns the PKs of all mappings (managed + custom) to attach to OAuth2 provider
func (c *APIClient) CreateMoniOIDCMappings(ctx context.Context) ([]string, error) {
	var pks []string

	// Step 1: Get Authentik's managed default scope mappings
	// These are pre-configured by Authentik and provide openid, profile, email scopes
	allMappings, err := c.ListOIDCPropertyMappings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list existing scope mappings: %w", err)
	}

	// Step 2: Find managed mappings for openid, profile, email scopes
	// Managed mappings have names like "goauthentik.io/providers/oauth2/scope-email"
	managedScopes := []string{"openid", "email", "profile"}
	for _, scope := range managedScopes {
		managedName := fmt.Sprintf("goauthentik.io/providers/oauth2/scope-%s", scope)
		found := false
		for _, mapping := range allMappings {
			if mapping.Managed == managedName || mapping.Name == managedName {
				pks = append(pks, mapping.PK)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("managed scope mapping not found: %s (Authentik may not be properly configured)", managedName)
		}
	}

	// Step 3: Create custom "groups" scope mapping (not included in Authentik defaults)
	// This scope mapping returns a dictionary with a "groups" claim containing array of group names
	groupsMapping := OIDCPropertyMappingRequest{
		Name:       "OIDC Groups Scope",
		Expression: "return {'groups': [group.name for group in request.user.ak_groups.all()]}", // Returns dict
		Scope:      "groups", // Custom scope name
	}

	groupsResult, err := c.CreateOIDCPropertyMapping(ctx, groupsMapping)
	if err != nil {
		return nil, fmt.Errorf("failed to create groups scope mapping: %w", err)
	}
	pks = append(pks, groupsResult.PK)

	return pks, nil
}

// DeleteOIDCPropertyMapping deletes an OIDC property mapping by PK
// SECURITY: Only delete custom mappings, NEVER delete managed Authentik mappings
// P0-3 FIX: Implement deletion for rollback cleanup
func (c *APIClient) DeleteOIDCPropertyMapping(ctx context.Context, pk string) error {
	url := fmt.Sprintf("%s/api/v3/propertymappings/scope/%s/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("property mapping deletion request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("property mapping deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	// 404 Not Found is OK - mapping may have been manually deleted
	return nil
}

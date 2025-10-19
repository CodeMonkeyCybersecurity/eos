// Package authentik provides SAML SSO integration helpers
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// SAMLClient handles SAML-specific Authentik API operations
type SAMLClient struct {
	*APIClient
}

// NewSAMLClient creates a new SAML client wrapping the base API client
func NewSAMLClient(baseURL, token string) *SAMLClient {
	return &SAMLClient{
		APIClient: NewClient(baseURL, token),
	}
}

// PropertyMappingConfig represents a SAML property mapping
type PropertyMappingConfig struct {
	PK         string `json:"pk,omitempty"`
	Name       string `json:"name"`
	SAMLName   string `json:"saml_name"`
	Expression string `json:"expression"`
}

// SAMLProviderConfig represents a SAML provider configuration
type SAMLProviderConfig struct {
	PK                string   `json:"pk,omitempty"`
	Name              string   `json:"name"`
	AuthorizationFlow string   `json:"authorization_flow"`
	PropertyMappings  []string `json:"property_mappings"`
	ACSUrl            string   `json:"acs_url"`
	Issuer            string   `json:"issuer"`
	SPBinding         string   `json:"sp_binding"`
	Audience          string   `json:"audience"`
}

// ApplicationConfig represents an Authentik application
type ApplicationConfig struct {
	PK               string `json:"pk,omitempty"`
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	Provider         string `json:"provider"`
	MetaLaunchURL    string `json:"meta_launch_url"`
	PolicyEngineMode string `json:"policy_engine_mode"`
}

// CheckHealth verifies the Authentik API is accessible
func (c *SAMLClient) CheckHealth(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v3/admin/workers/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("authentik API not accessible: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentik API authentication failed: invalid token")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentik API unhealthy: status %d", resp.StatusCode)
	}

	return nil
}

// CreatePropertyMappings creates the required SAML property mappings
func (c *SAMLClient) CreatePropertyMappings(ctx context.Context) ([]string, error) {
	mappings := []PropertyMappingConfig{
		{
			Name:       "SAML Username",
			SAMLName:   "username",
			Expression: "return request.user.username",
		},
		{
			Name:       "SAML Roles",
			SAMLName:   "Roles", // CRITICAL: Capital R for Wazuh
			Expression: "return [group.name for group in request.user.ak_groups.all()]",
		},
		{
			Name:       "SAML Email",
			SAMLName:   "email",
			Expression: "return request.user.email",
		},
	}

	var pks []string
	for _, mapping := range mappings {
		pk, err := c.createOrUpdatePropertyMapping(ctx, mapping)
		if err != nil {
			return nil, err
		}
		pks = append(pks, pk)
	}

	return pks, nil
}

// CreateSAMLProvider creates or updates a SAML provider
func (c *SAMLClient) CreateSAMLProvider(ctx context.Context, config SAMLProviderConfig) (string, error) {
	// Check if provider exists
	existingPK, err := c.findProvider(ctx, config.Name)
	if err != nil {
		return "", err
	}

	if existingPK != "" {
		config.PK = existingPK
		return c.updateProvider(ctx, config)
	}

	return c.createProvider(ctx, config)
}

// CreateApplication creates or updates an application
func (c *SAMLClient) CreateApplication(ctx context.Context, config ApplicationConfig) (string, error) {
	existingPK, err := c.findApplication(ctx, config.Slug)
	if err != nil {
		return "", err
	}

	if existingPK != "" {
		config.PK = existingPK
		return c.updateApplication(ctx, config)
	}

	return c.createApplication(ctx, config)
}

// GetDefaultAuthFlow gets the default authorization flow
func (c *SAMLClient) GetDefaultAuthFlow(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/api/v3/flows/instances/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			PK   string `json:"pk"`
			Slug string `json:"slug"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Look for default auth flow
	for _, flow := range result.Results {
		if flow.Slug == "default-provider-authorization-implicit-consent" {
			return flow.PK, nil
		}
	}

	if len(result.Results) > 0 {
		return result.Results[0].PK, nil
	}

	return "", fmt.Errorf("no authorization flow found")
}

// DownloadMetadata downloads SAML metadata for an application
func (c *SAMLClient) DownloadMetadata(ctx context.Context, appSlug string) ([]byte, error) {
	url := fmt.Sprintf("%s/application/saml/%s/metadata/", c.BaseURL, appSlug)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download metadata: status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// Private helper methods

func (c *SAMLClient) createOrUpdatePropertyMapping(ctx context.Context, mapping PropertyMappingConfig) (string, error) {
	// Check if exists
	url := fmt.Sprintf("%s/api/v3/propertymappings/saml/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Results []PropertyMappingConfig `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Check if mapping exists
	for _, m := range result.Results {
		if m.SAMLName == mapping.SAMLName {
			return m.PK, nil // Already exists
		}
	}

	// Create new mapping
	body, _ := json.Marshal(mapping)
	req, err = http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err = c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create mapping: %d - %s", resp.StatusCode, string(body))
	}

	var created PropertyMappingConfig
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", err
	}

	return created.PK, nil
}

func (c *SAMLClient) findProvider(ctx context.Context, name string) (string, error) {
	url := fmt.Sprintf("%s/api/v3/providers/saml/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Results []SAMLProviderConfig `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	for _, p := range result.Results {
		if p.Name == name {
			return p.PK, nil
		}
	}

	return "", nil
}

func (c *SAMLClient) createProvider(ctx context.Context, config SAMLProviderConfig) (string, error) {
	url := fmt.Sprintf("%s/api/v3/providers/saml/", c.BaseURL)
	body, _ := json.Marshal(config)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create provider: %d - %s", resp.StatusCode, string(body))
	}

	var created SAMLProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", err
	}

	return created.PK, nil
}

func (c *SAMLClient) updateProvider(ctx context.Context, config SAMLProviderConfig) (string, error) {
	url := fmt.Sprintf("%s/api/v3/providers/saml/%s/", c.BaseURL, config.PK)
	body, _ := json.Marshal(config)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to update provider: %d - %s", resp.StatusCode, string(body))
	}

	return config.PK, nil
}

func (c *SAMLClient) findApplication(ctx context.Context, slug string) (string, error) {
	url := fmt.Sprintf("%s/api/v3/core/applications/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Results []ApplicationConfig `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	for _, a := range result.Results {
		if a.Slug == slug {
			return a.PK, nil
		}
	}

	return "", nil
}

func (c *SAMLClient) createApplication(ctx context.Context, config ApplicationConfig) (string, error) {
	url := fmt.Sprintf("%s/api/v3/core/applications/", c.BaseURL)
	body, _ := json.Marshal(config)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create application: %d - %s", resp.StatusCode, string(body))
	}

	var created ApplicationConfig
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", err
	}

	return created.PK, nil
}

func (c *SAMLClient) updateApplication(ctx context.Context, config ApplicationConfig) (string, error) {
	url := fmt.Sprintf("%s/api/v3/core/applications/%s/", c.BaseURL, config.PK)
	body, _ := json.Marshal(config)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to update application: %d - %s", resp.StatusCode, string(body))
	}

	return config.PK, nil
}

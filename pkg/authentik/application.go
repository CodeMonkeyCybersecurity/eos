// pkg/authentik/application.go - Application management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ApplicationRequest represents the request body for creating an application
type ApplicationRequest struct {
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	Provider         int    `json:"provider,omitempty"` // Provider PK
	Group            string `json:"group,omitempty"`
	MetaLaunchURL    string `json:"meta_launch_url,omitempty"`
	MetaIcon         string `json:"meta_icon,omitempty"`
	MetaDescription  string `json:"meta_description,omitempty"`
	PolicyEngineMode string `json:"policy_engine_mode,omitempty"` // "all" or "any"
}

// ApplicationResponse represents the response when creating/fetching an application
type ApplicationResponse struct {
	PK          string `json:"pk"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Provider    int    `json:"provider,omitempty"`
	Group       string `json:"group,omitempty"`
	ProviderObj struct {
		PK   int    `json:"pk"`
		Name string `json:"name"`
	} `json:"provider_obj,omitempty"`
	MetaLaunchURL    string `json:"meta_launch_url,omitempty"`
	MetaIcon         string `json:"meta_icon,omitempty"`
	MetaDescription  string `json:"meta_description,omitempty"`
	PolicyEngineMode string `json:"policy_engine_mode,omitempty"`
}

// CreateApplication creates a new application in Authentik
func (c *APIClient) CreateApplication(ctx context.Context, name, slug string, providerPK int, launchURL string) (*ApplicationResponse, error) {
	reqBody := ApplicationRequest{
		Name:             name,
		Slug:             slug,
		Provider:         providerPK,
		MetaLaunchURL:    launchURL,
		PolicyEngineMode: "any", // Default to "any" policy mode
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal application request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/core/applications/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("application creation request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log but don't override the main error
			_ = closeErr
		}
	}()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("application creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var app ApplicationResponse
	if err := json.Unmarshal(body, &app); err != nil {
		return nil, fmt.Errorf("failed to unmarshal application response: %w", err)
	}

	return &app, nil
}

// GetApplication retrieves an application by slug
func (c *APIClient) GetApplication(ctx context.Context, slug string) (*ApplicationResponse, error) {
	url := fmt.Sprintf("%s/api/v3/core/applications/%s/", c.BaseURL, slug)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("application fetch request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log but don't override the main error
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("application fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var app ApplicationResponse
	if err := json.NewDecoder(resp.Body).Decode(&app); err != nil {
		return nil, fmt.Errorf("failed to decode application response: %w", err)
	}

	return &app, nil
}

// ListApplications lists all applications
func (c *APIClient) ListApplications(ctx context.Context) ([]ApplicationResponse, error) {
	url := fmt.Sprintf("%s/api/v3/core/applications/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("applications list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("applications list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []ApplicationResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode applications list response: %w", err)
	}

	return result.Results, nil
}

// DeleteApplication deletes an application by slug
func (c *APIClient) DeleteApplication(ctx context.Context, slug string) error {
	url := fmt.Sprintf("%s/api/v3/core/applications/%s/", c.BaseURL, slug)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("application deletion request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("application deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// UpdateApplication updates an application's configuration using PATCH semantics.
// Common use cases: attach proxy provider, set default group, update launch URL.
func (c *APIClient) UpdateApplication(ctx context.Context, slug string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}

	jsonBody, err := json.Marshal(updates)
	if err != nil {
		return fmt.Errorf("failed to marshal application update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/core/applications/%s/", c.BaseURL, slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("application update request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("application update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

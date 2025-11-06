// pkg/authentik/outpost.go - Outpost management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OutpostResponse represents an Authentik outpost
type OutpostResponse struct {
	PK        string                 `json:"pk"`
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Providers []int                  `json:"providers"`
	Config    map[string]interface{} `json:"config"`
}

// ListOutposts lists all outposts
func (c *APIClient) ListOutposts(ctx context.Context) ([]OutpostResponse, error) {
	url := fmt.Sprintf("%s/api/v3/outposts/instances/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("outposts list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("outposts list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []OutpostResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode outposts list response: %w", err)
	}

	return result.Results, nil
}

// GetOutpost retrieves an outpost by PK
func (c *APIClient) GetOutpost(ctx context.Context, pk string) (*OutpostResponse, error) {
	url := fmt.Sprintf("%s/api/v3/outposts/instances/%s/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("outpost fetch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("outpost fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var outpost OutpostResponse
	if err := json.NewDecoder(resp.Body).Decode(&outpost); err != nil {
		return nil, fmt.Errorf("failed to decode outpost response: %w", err)
	}

	return &outpost, nil
}

// AddProviderToOutpost adds a provider to an outpost's provider list
func (c *APIClient) AddProviderToOutpost(ctx context.Context, outpostPK string, providerPK int) error {
	// First, get the current outpost to get existing providers
	outpost, err := c.GetOutpost(ctx, outpostPK)
	if err != nil {
		return fmt.Errorf("failed to get outpost: %w", err)
	}

	// Check if provider already in list
	for _, existingPK := range outpost.Providers {
		if existingPK == providerPK {
			// Already assigned, nothing to do
			return nil
		}
	}

	// Add new provider to list
	updatedProviders := append(outpost.Providers, providerPK)

	// Update outpost with new provider list
	reqBody := map[string]interface{}{
		"providers": updatedProviders,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/outposts/instances/%s/", c.BaseURL, outpostPK)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("outpost update request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("outpost update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveProviderFromOutpost removes a provider from an outpost's provider list
func (c *APIClient) RemoveProviderFromOutpost(ctx context.Context, outpostPK string, providerPK int) error {
	// First, get the current outpost to get existing providers
	outpost, err := c.GetOutpost(ctx, outpostPK)
	if err != nil {
		return fmt.Errorf("failed to get outpost: %w", err)
	}

	// Filter out the provider to remove
	updatedProviders := []int{}
	found := false
	for _, existingPK := range outpost.Providers {
		if existingPK != providerPK {
			updatedProviders = append(updatedProviders, existingPK)
		} else {
			found = true
		}
	}

	if !found {
		// Provider not in list, nothing to do
		return nil
	}

	// Update outpost with filtered provider list
	reqBody := map[string]interface{}{
		"providers": updatedProviders,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/outposts/instances/%s/", c.BaseURL, outpostPK)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("outpost update request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("outpost update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

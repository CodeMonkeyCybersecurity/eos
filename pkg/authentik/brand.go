// pkg/authentik/brand.go - Brand management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// BrandResponse represents an Authentik brand
type BrandResponse struct {
	PK                 string `json:"pk"`
	BrandingTitle      string `json:"branding_title"`
	BrandingLogo       string `json:"branding_logo"`
	BrandingFavicon    string `json:"branding_favicon"`
	FlowAuthentication string `json:"flow_authentication"`
	FlowEnrollment     string `json:"flow_enrollment,omitempty"`
	FlowInvalidation   string `json:"flow_invalidation"`
	FlowRecovery       string `json:"flow_recovery,omitempty"`
	FlowUserSettings   string `json:"flow_user_settings,omitempty"`
	FlowDeviceCode     string `json:"flow_device_code,omitempty"`
	Domain             string `json:"domain"`
}

// ListBrands lists all brands in Authentik
func (c *APIClient) ListBrands(ctx context.Context) ([]BrandResponse, error) {
	url := fmt.Sprintf("%s/api/v3/brands/instances/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("brands list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("brands list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []BrandResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode brands list response: %w", err)
	}

	return result.Results, nil
}

// GetBrand retrieves a brand by PK
func (c *APIClient) GetBrand(ctx context.Context, pk string) (*BrandResponse, error) {
	url := fmt.Sprintf("%s/api/v3/brands/instances/%s/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("brand fetch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("brand fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var brand BrandResponse
	if err := json.NewDecoder(resp.Body).Decode(&brand); err != nil {
		return nil, fmt.Errorf("failed to decode brand response: %w", err)
	}

	return &brand, nil
}

// UpdateBrand updates a brand's configuration
// Only non-empty fields in updates will be modified
func (c *APIClient) UpdateBrand(ctx context.Context, pk string, updates map[string]interface{}) error {
	jsonBody, err := json.Marshal(updates)
	if err != nil {
		return fmt.Errorf("failed to marshal update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/brands/instances/%s/", c.BaseURL, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("brand update request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("brand update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

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
	// P0 FIX: Authentik brands API returns 'brand_uuid' not 'pk'
	// Based on Authentik OpenAPI schema: /api/v3/core/brands/ returns brand_uuid as primary identifier
	PK                 string `json:"brand_uuid"` // Primary identifier (was incorrectly 'pk')
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
	// P0 FIX: Correct API endpoint path based on Authentik OpenAPI schema
	// The schema shows /core/brands/ not /brands/instances/
	url := fmt.Sprintf("%s/api/v3/core/brands/", c.BaseURL)

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
	// P0 FIX: Correct API endpoint path
	url := fmt.Sprintf("%s/api/v3/core/brands/%s/", c.BaseURL, pk)

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

// UpdateBrand updates a brand's configuration and returns the updated brand
// Only non-empty fields in updates will be modified
// Returns the updated brand object from API response for verification
func (c *APIClient) UpdateBrand(ctx context.Context, pk string, updates map[string]interface{}) (*BrandResponse, error) {
	jsonBody, err := json.Marshal(updates)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal update request: %w", err)
	}

	// P0 FIX: Correct API endpoint path
	url := fmt.Sprintf("%s/api/v3/core/brands/%s/", c.BaseURL, pk)

	// P0 DEBUG: Log exact request being sent to API (CRITICAL for diagnosing field name issues)
	// This will show us the exact JSON payload Authentik receives
	fmt.Printf("\n========== AUTHENTIK API DEBUG ==========\n")
	fmt.Printf("HTTP Method: PATCH\n")
	fmt.Printf("URL: %s\n", url)
	fmt.Printf("Request Body (JSON):\n%s\n", string(jsonBody))
	fmt.Printf("=========================================\n\n")

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json") // Request JSON response

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("brand update request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body for both success and error cases
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// P0 DEBUG: Log exact response received from API
	// This will show us what Authentik actually returns (including which fields are set/empty)
	fmt.Printf("\n========== AUTHENTIK API RESPONSE ==========\n")
	fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
	fmt.Printf("Response Body (JSON):\n%s\n", string(body))
	fmt.Printf("============================================\n\n")

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("brand update failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response body to get updated brand
	var updatedBrand BrandResponse
	if err := json.Unmarshal(body, &updatedBrand); err != nil {
		return nil, fmt.Errorf("failed to parse brand update response: %w\nResponse body: %s", err, string(body))
	}

	return &updatedBrand, nil
}

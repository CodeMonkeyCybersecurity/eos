// pkg/authentik/client.go

package authentik

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// APIClient represents an Authentik API client
type APIClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewClient creates a new Authentik API client
func NewClient(baseURL, token string) *APIClient {
	// Auto-add https:// if no protocol specified
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	return &APIClient{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// APICall makes an authenticated API call to Authentik
func (c *APIClient) APICall(ctx context.Context, endpoint string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v3/%s", c.BaseURL, strings.TrimPrefix(endpoint, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// ExportBlueprints exports all Authentik blueprints as YAML
func (c *APIClient) ExportBlueprints(ctx context.Context) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v3/blueprints/export/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "text/yaml")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("blueprint export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("authentik export failed: %s – %s", resp.Status, string(body))
	}

	return io.ReadAll(resp.Body)
}

// GetVersion fetches the Authentik version
func (c *APIClient) GetVersion(ctx context.Context) (string, error) {
	_, err := c.APICall(ctx, "root/config/")
	if err != nil {
		return "", err
	}

	// Simple version extraction - this can be improved with proper JSON parsing
	// For now, return empty string if we can't determine version
	return "", nil
}

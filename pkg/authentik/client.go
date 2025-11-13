// pkg/authentik/client.go

package authentik

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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

	// Use centralized URL sanitization to handle trailing slashes, whitespace, etc.
	baseURL = shared.SanitizeURL(baseURL)

	// Configure TLS with minimum version TLS 1.2
	// RATIONALE: TLS 1.0/1.1 are deprecated and vulnerable (POODLE, BEAST attacks)
	// SECURITY: Enforces modern TLS for API communication with Authentik
	// NOTE: InsecureSkipVerify is false by default - validates certificates
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// InsecureSkipVerify: false (default) - ALWAYS verify certificates in production
		// Only set to true during development with self-signed certs
	}

	return &APIClient{
		BaseURL: baseURL,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Application & Policy Management (P1 - Security Enhancement)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GetApplicationBySlug retrieves an application by its slug
// SECURITY: Required to get app PK for policy binding
// PATTERN: Slug is typically the app name in lowercase (e.g., "bionicgpt")
func (c *APIClient) GetApplicationBySlug(ctx context.Context, slug string) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("core/applications/?slug=%s", slug)
	respBody, err := c.APICall(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get application: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse application response: %w", err)
	}

	// API returns paginated results
	results, ok := result["results"].([]interface{})
	if !ok || len(results) == 0 {
		return nil, fmt.Errorf("application not found: %s", slug)
	}

	app, ok := results[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid application data structure")
	}

	return app, nil
}

// CreateGroupApplicationPolicy creates a policy to restrict application access to a group
// SECURITY: Implements per-app authorization for self-enrollment
// ARCHITECTURE: Wrapper around unified client's policy methods
//
// This provides per-application access control on top of brand-level enrollment:
//   - Self-enrollment is brand-level (Authentik design constraint)
//   - Authorization policies are app-level (this method)
//   - Result: Users enroll at brand level, but only access authorized apps
//
// Parameters:
//   - groupPK: UUID of the group (e.g., "eos-self-enrolled-users")
//   - appSlug: Application slug (e.g., "bionicgpt")
//
// Returns: (policyPK, bindingPK, error)
func (c *APIClient) CreateGroupApplicationPolicy(ctx context.Context, groupPK, appSlug string) (string, string, error) {
	// Get application details
	app, err := c.GetApplicationBySlug(ctx, appSlug)
	if err != nil {
		return "", "", fmt.Errorf("failed to get application %s: %w", appSlug, err)
	}

	appPK, ok := app["pk"].(string)
	if !ok {
		return "", "", fmt.Errorf("application %s missing PK field", appSlug)
	}

	appName, ok := app["name"].(string)
	if !ok {
		appName = appSlug // Fallback to slug if name not available
	}

	// Use unified client for policy operations
	unifiedClient := NewUnifiedClient(c.BaseURL, c.Token)
	policyPK, bindingPK, err := unifiedClient.CreateGroupApplicationPolicy(ctx, groupPK, appPK, appName)
	if err != nil {
		return "", "", err
	}

	return policyPK, bindingPK, nil
}

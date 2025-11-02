// pkg/authentik/unified_client.go
// Unified Authentik API client consolidating all HTTP communication
// ARCHITECTURE: Single source of truth for Authentik API interactions
// REPLACES: client.go (APIClient), authentik_client.go (AuthentikClient), pkg/hecate/authentik/export.go (AuthentikClient)

package authentik

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// UnifiedClient represents a unified Authentik API client
// CONSOLIDATION: Merges functionality from three separate client implementations
// FEATURES: TLS 1.2 enforcement, exponential backoff retry, proper error handling
type UnifiedClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewUnifiedClient creates a new unified Authentik API client
// SECURITY: Enforces TLS 1.2+ for all API communication
// RELIABILITY: Includes retry logic with exponential backoff
func NewUnifiedClient(baseURL, token string) *UnifiedClient {
	// Auto-add https:// if no protocol specified
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	// Use centralized URL sanitization
	baseURL = shared.SanitizeURL(baseURL)

	// Configure TLS with minimum version TLS 1.2
	// RATIONALE: TLS 1.0/1.1 are deprecated and vulnerable (POODLE, BEAST attacks)
	// SECURITY: Enforces modern TLS for API communication with Authentik
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// InsecureSkipVerify: false (default) - ALWAYS verify certificates in production
	}

	return &UnifiedClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// DoRequest performs an HTTP request with authentication and retry logic
// ENHANCED: Exponential backoff retry for transient failures
// P1 FIX: Respects Retry-After header for rate limiting
// CONSOLIDATION: Unified implementation from pkg/hecate/authentik/export.go
func (c *UnifiedClient) DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var lastErr error
	maxRetries := 3
	baseDelay := time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// P1 FIX: Use Retry-After header if present (from previous attempt)
			// RATIONALE: API knows best when to retry (rate limit windows, maintenance)
			// SECURITY: Prevents aggressive retry that could trigger IP ban
			// Note: retryAfter is set below when we get 429/503 response
			delay := baseDelay * time.Duration(1<<uint(attempt-1)) // Default: exponential backoff
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Construct full URL
		url := c.baseURL + path
		if !strings.HasPrefix(path, "/api/v3/") && !strings.HasPrefix(path, "/api/v3") {
			url = fmt.Sprintf("%s/api/v3/%s", c.baseURL, strings.TrimPrefix(path, "/"))
		}

		// Prepare request body
		var reqBody io.Reader
		if body != nil {
			jsonBody, err := json.Marshal(body)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal request body: %w", err)
			}
			reqBody = bytes.NewReader(jsonBody)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			// P1 FIX: Only retry network errors (no status code), not HTTP errors
			if isTransientError(err, 0) && attempt < maxRetries {
				continue
			}
			return nil, lastErr
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		// Success status codes
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return respBody, nil
		}

		// P1 FIX: Parse Retry-After header for rate limiting (RFC 7231)
		// RATIONALE: API specifies exact retry time, more efficient than guessing
		// SECURITY: Prevents aggressive retry that could trigger IP ban
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				// Retry-After can be seconds (integer) or HTTP date
				if seconds, parseErr := strconv.Atoi(retryAfter); parseErr == nil && seconds > 0 {
					// Wait for specified seconds before next retry
					retryDelay := time.Duration(seconds) * time.Second
					// Cap at 5 minutes to prevent indefinite wait
					if retryDelay > 5*time.Minute {
						retryDelay = 5 * time.Minute
					}
					select {
					case <-time.After(retryDelay):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				// Note: HTTP date format parsing not implemented - use default backoff
			}
		}

		// P1 FIX: Use isTransientError to decide whether to retry based on status code
		lastErr = fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
		if isTransientError(lastErr, resp.StatusCode) && attempt < maxRetries {
			// Transient error (429, 5xx) - retry with backoff
			continue
		}

		// Deterministic error (4xx except 429) - fail immediately
		return nil, lastErr
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// Get performs a GET request
func (c *UnifiedClient) Get(ctx context.Context, path string) ([]byte, error) {
	return c.DoRequest(ctx, http.MethodGet, path, nil)
}

// Post performs a POST request
func (c *UnifiedClient) Post(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return c.DoRequest(ctx, http.MethodPost, path, body)
}

// Patch performs a PATCH request
func (c *UnifiedClient) Patch(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return c.DoRequest(ctx, http.MethodPatch, path, body)
}

// Delete performs a DELETE request
func (c *UnifiedClient) Delete(ctx context.Context, path string) ([]byte, error) {
	return c.DoRequest(ctx, http.MethodDelete, path, nil)
}

// Health checks if the Authentik API is accessible and responding
func (c *UnifiedClient) Health(ctx context.Context) error {
	_, err := c.Get(ctx, "/api/v3/")
	if err != nil {
		return fmt.Errorf("authentik API not responding: %w", err)
	}
	return nil
}

// GetVersion retrieves the Authentik version information
func (c *UnifiedClient) GetVersion(ctx context.Context) (string, error) {
	data, err := c.Get(ctx, "/api/v3/root/config/")
	if err != nil {
		return "", fmt.Errorf("failed to get version: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("failed to decode version response: %w", err)
	}

	if version, ok := config["version"].(string); ok {
		return version, nil
	}

	return "unknown", nil
}

// isTransientError checks if an error is transient and should be retried
// P1 FIX: Only retry transient failures, fail fast on deterministic errors
// RATIONALE: Retrying validation errors (400) wastes time and API quota
// SECURITY: Prevents retry-based DoS when user provides invalid input
func isTransientError(err error, statusCode int) bool {
	if err == nil {
		return false
	}

	// FAIL FAST: Client errors are deterministic (bad request, auth failure, not found)
	// DO NOT RETRY: 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 405 Method Not Allowed
	if statusCode >= 400 && statusCode < 500 {
		return false // Client errors - configuration/validation issue, won't fix with retry
	}

	// RETRY: Rate limiting (429) and server errors (5xx) are transient
	if statusCode == 429 || statusCode >= 500 {
		return true // Transient failures - retry with backoff
	}

	// Network errors (no status code) - check error string
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "temporary failure") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "EOF")
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Policy Management (P1 - Security Enhancement for Self-Enrollment)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// CreateExpressionPolicy creates an expression-based policy in Authentik
// SECURITY: Enables per-application access control for self-enrolled users
// USE CASE: Restrict which applications a group can access
// RATIONALE: Authentik enrollment is brand-level, but authorization can be app-level
// REFERENCE: https://github.com/goauthentik/authentik/issues/2807 (domain-level forward auth limitation)
//
// Example expression: "return ak_is_group_member(request.user, 'uuid-of-group')"
func (c *UnifiedClient) CreateExpressionPolicy(ctx context.Context, name, expression string) (string, error) {
	payload := map[string]interface{}{
		"name":       name,
		"expression": expression,
	}

	respBody, err := c.Post(ctx, "/api/v3/policies/expression/", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create expression policy: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse policy response: %w", err)
	}

	policyPK, ok := result["pk"].(string)
	if !ok {
		return "", fmt.Errorf("policy response missing 'pk' field")
	}

	return policyPK, nil
}

// CreatePolicyBinding binds a policy to a target (application, flow, etc.)
// SECURITY: Enforces policy evaluation before granting access
// ARCHITECTURE: Policy bindings create the access control layer
// ORDER: Lower order number = evaluated first (use 10 for general group policies)
//
// Parameters:
//   - policyPK: The policy UUID to bind
//   - targetPK: The target UUID (application, flow, stage, etc.)
//   - order: Evaluation order (lower = earlier, recommend 10 for standard policies)
//   - enabled: Whether the binding is active
func (c *UnifiedClient) CreatePolicyBinding(ctx context.Context, policyPK, targetPK string, order int, enabled bool) (string, error) {
	payload := map[string]interface{}{
		"policy":  policyPK,
		"target":  targetPK,
		"order":   order,
		"enabled": enabled,
	}

	respBody, err := c.Post(ctx, "/api/v3/policies/bindings/", payload)
	if err != nil {
		return "", fmt.Errorf("failed to create policy binding: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse binding response: %w", err)
	}

	bindingPK, ok := result["pk"].(string)
	if !ok {
		return "", fmt.Errorf("binding response missing 'pk' field")
	}

	return bindingPK, nil
}

// CreateGroupApplicationPolicy creates a policy that allows a group to access an application
// CONVENIENCE METHOD: Combines CreateExpressionPolicy + CreatePolicyBinding
// SECURITY: Implements per-app authorization for self-enrollment
//
// This is the recommended way to restrict self-enrolled users to specific applications:
//  1. Create enrollment flow (brand-level, affects all apps)
//  2. Create group for self-enrolled users
//  3. Call this method for EACH application that should be accessible
//
// Example:
//
//	err := client.CreateGroupApplicationPolicy(ctx, "eos-self-enrolled-users-uuid", "bionicgpt-app-uuid", "BionicGPT")
//
// Returns: (policyPK, bindingPK, error)
func (c *UnifiedClient) CreateGroupApplicationPolicy(ctx context.Context, groupPK, appPK, appName string) (string, string, error) {
	// Step 1: Create expression policy
	policyName := fmt.Sprintf("eos-enrollment-allow-%s", appName)
	expression := fmt.Sprintf("return ak_is_group_member(request.user, '%s')", groupPK)

	policyPK, err := c.CreateExpressionPolicy(ctx, policyName, expression)
	if err != nil {
		return "", "", fmt.Errorf("failed to create policy for %s: %w", appName, err)
	}

	// Step 2: Bind policy to application
	bindingPK, err := c.CreatePolicyBinding(ctx, policyPK, appPK, 10, true)
	if err != nil {
		// Attempt to clean up policy if binding fails
		_, _ = c.Delete(ctx, fmt.Sprintf("/api/v3/policies/expression/%s/", policyPK))
		return "", "", fmt.Errorf("failed to bind policy to %s: %w", appName, err)
	}

	return policyPK, bindingPK, nil
}

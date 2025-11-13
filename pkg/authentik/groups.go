// pkg/authentik/groups.go - Group management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GroupRequest represents the request body for creating a group
type GroupRequest struct {
	Name        string                 `json:"name"`
	Parent      string                 `json:"parent,omitempty"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
	IsSuperuser bool                   `json:"is_superuser,omitempty"`
}

// GroupResponse represents the response when creating/fetching a group
type GroupResponse struct {
	PK          string                 `json:"pk"`
	NumPK       int                    `json:"num_pk"`
	Name        string                 `json:"name"`
	Parent      string                 `json:"parent,omitempty"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
	IsSuperuser bool                   `json:"is_superuser,omitempty"`
	UsersObj    []interface{}          `json:"users_obj,omitempty"`
}

// CreateGroup creates a new group in Authentik
func (c *APIClient) CreateGroup(ctx context.Context, name string, attributes map[string]interface{}) (*GroupResponse, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Creating Authentik group",
		zap.String("group_name", name),
		zap.Any("attributes", attributes))

	reqBody := GroupRequest{
		Name:        name,
		Attributes:  attributes,
		IsSuperuser: false, // Default: NOT superuser (secure default)
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		logger.Error("Failed to marshal group request",
			zap.String("group_name", name),
			zap.Error(err))
		return nil, fmt.Errorf("failed to marshal group request: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/v3/core/groups/", c.BaseURL)
	logger.Debug("Making group creation request",
		zap.String("url", apiURL),
		zap.String("method", http.MethodPost))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		logger.Error("Failed to create HTTP request",
			zap.String("url", apiURL),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		logger.Error("Group creation request failed",
			zap.String("group_name", name),
			zap.String("url", apiURL),
			zap.Error(err))
		return nil, fmt.Errorf("group creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		logger.Error("Failed to read response body",
			zap.Error(readErr))
		return nil, fmt.Errorf("failed to read response body: %w", readErr)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// Try to parse error detail from response
		var apiError struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &apiError) == nil && apiError.Detail != "" {
			logger.Error("Group creation failed with API error",
				zap.String("group_name", name),
				zap.Int("status_code", resp.StatusCode),
				zap.String("error_detail", apiError.Detail))
			return nil, fmt.Errorf("group creation failed with status %d: %s", resp.StatusCode, apiError.Detail)
		}

		logger.Error("Group creation failed",
			zap.String("group_name", name),
			zap.Int("status_code", resp.StatusCode),
			zap.String("response_body", string(body)))
		return nil, fmt.Errorf("group creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var group GroupResponse
	if err := json.Unmarshal(body, &group); err != nil {
		logger.Error("Failed to unmarshal group response",
			zap.String("group_name", name),
			zap.String("response_body", string(body)),
			zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal group response: %w", err)
	}

	logger.Info("Successfully created Authentik group",
		zap.String("group_name", group.Name),
		zap.String("group_pk", group.PK),
		zap.Int("num_pk", group.NumPK),
		zap.Bool("is_superuser", group.IsSuperuser))

	return &group, nil
}

// GetGroupByName retrieves a group by name using search parameter and client-side filtering.
// RATIONALE: Authentik API doesn't support exact filtering by name parameter (?name=).
// Using ?search= and client-side filtering ensures exact case-sensitive match.
func (c *APIClient) GetGroupByName(ctx context.Context, name string) (*GroupResponse, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Fetching Authentik group by name",
		zap.String("group_name", name))

	// Use search parameter instead of name filter (Authentik API limitation)
	// URL-encode the search term to handle spaces and special characters
	encodedName := url.QueryEscape(name)
	apiURL := fmt.Sprintf("%s/api/v3/core/groups/?search=%s", c.BaseURL, encodedName)

	logger.Debug("Making group search request",
		zap.String("url", apiURL),
		zap.String("search_term", name),
		zap.String("encoded_search", encodedName))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		logger.Error("Failed to create HTTP request",
			zap.String("url", apiURL),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		logger.Error("Group fetch request failed",
			zap.String("group_name", name),
			zap.String("url", apiURL),
			zap.Error(err))
		return nil, fmt.Errorf("group fetch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read body for both error and success cases
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		logger.Error("Failed to read response body",
			zap.Error(readErr))
		return nil, fmt.Errorf("failed to read response body: %w", readErr)
	}

	logger.Debug("Received group search response",
		zap.String("group_name", name),
		zap.Int("status_code", resp.StatusCode),
		zap.Int("body_length", len(body)))

	if resp.StatusCode != http.StatusOK {
		// Try to parse error detail from response
		var apiError struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &apiError) == nil && apiError.Detail != "" {
			logger.Error("Group fetch failed with API error",
				zap.String("group_name", name),
				zap.Int("status_code", resp.StatusCode),
				zap.String("error_detail", apiError.Detail))
			return nil, fmt.Errorf("group fetch failed with status %d: %s", resp.StatusCode, apiError.Detail)
		}

		logger.Error("Group fetch failed",
			zap.String("group_name", name),
			zap.Int("status_code", resp.StatusCode),
			zap.String("response_body", string(body)))
		return nil, fmt.Errorf("group fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []GroupResponse `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		logger.Error("Failed to decode group response",
			zap.String("group_name", name),
			zap.String("response_body", string(body)),
			zap.Error(err))
		return nil, fmt.Errorf("failed to decode group response: %w", err)
	}

	logger.Debug("Group search returned results",
		zap.String("group_name", name),
		zap.Int("result_count", len(result.Results)))

	// Filter results for exact case-sensitive match
	// (search may return partial matches)
	for i := range result.Results {
		if result.Results[i].Name == name {
			logger.Info("Found matching Authentik group",
				zap.String("group_name", result.Results[i].Name),
				zap.String("group_pk", result.Results[i].PK),
				zap.Int("num_pk", result.Results[i].NumPK))
			return &result.Results[i], nil
		}
	}

	// Group not found
	logger.Debug("Group not found in search results",
		zap.String("group_name", name),
		zap.Int("total_results", len(result.Results)))
	return nil, fmt.Errorf("group not found: %s", name)
}

// ListGroups lists all groups, optionally filtered by prefix
func (c *APIClient) ListGroups(ctx context.Context, namePrefix string) ([]GroupResponse, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Listing Authentik groups",
		zap.String("name_prefix", namePrefix))

	apiURL := fmt.Sprintf("%s/api/v3/core/groups/", c.BaseURL)
	if namePrefix != "" {
		encodedPrefix := url.QueryEscape(namePrefix)
		apiURL += fmt.Sprintf("?name__startswith=%s", encodedPrefix)
	}

	logger.Debug("Making groups list request",
		zap.String("url", apiURL),
		zap.String("method", http.MethodGet))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		logger.Error("Failed to create HTTP request",
			zap.String("url", apiURL),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		logger.Error("Groups list request failed",
			zap.String("url", apiURL),
			zap.Error(err))
		return nil, fmt.Errorf("groups list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192)) // Larger limit for list operations
	if readErr != nil {
		logger.Error("Failed to read response body",
			zap.Error(readErr))
		return nil, fmt.Errorf("failed to read response body: %w", readErr)
	}

	logger.Debug("Received groups list response",
		zap.Int("status_code", resp.StatusCode),
		zap.Int("body_length", len(body)))

	if resp.StatusCode != http.StatusOK {
		// Try to parse error detail from response
		var apiError struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &apiError) == nil && apiError.Detail != "" {
			logger.Error("Groups list failed with API error",
				zap.Int("status_code", resp.StatusCode),
				zap.String("error_detail", apiError.Detail))
			return nil, fmt.Errorf("groups list failed with status %d: %s", resp.StatusCode, apiError.Detail)
		}

		logger.Error("Groups list failed",
			zap.Int("status_code", resp.StatusCode),
			zap.String("response_body", string(body)))
		return nil, fmt.Errorf("groups list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []GroupResponse `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		logger.Error("Failed to decode groups list response",
			zap.String("response_body", string(body)),
			zap.Error(err))
		return nil, fmt.Errorf("failed to decode groups list response: %w", err)
	}

	logger.Info("Successfully listed Authentik groups",
		zap.String("name_prefix", namePrefix),
		zap.Int("group_count", len(result.Results)))

	return result.Results, nil
}

// DeleteGroup deletes a group by PK
func (c *APIClient) DeleteGroup(ctx context.Context, pk string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Deleting Authentik group",
		zap.String("group_pk", pk))

	apiURL := fmt.Sprintf("%s/api/v3/core/groups/%s/", c.BaseURL, pk)

	logger.Debug("Making group deletion request",
		zap.String("url", apiURL),
		zap.String("method", http.MethodDelete))

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, apiURL, nil)
	if err != nil {
		logger.Error("Failed to create HTTP request",
			zap.String("url", apiURL),
			zap.Error(err))
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		logger.Error("Group deletion request failed",
			zap.String("group_pk", pk),
			zap.String("url", apiURL),
			zap.Error(err))
		return fmt.Errorf("group deletion request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		logger.Error("Failed to read response body",
			zap.Error(readErr))
		return fmt.Errorf("failed to read response body: %w", readErr)
	}

	logger.Debug("Received group deletion response",
		zap.String("group_pk", pk),
		zap.Int("status_code", resp.StatusCode))

	if resp.StatusCode != http.StatusNoContent {
		// Try to parse error detail from response
		var apiError struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &apiError) == nil && apiError.Detail != "" {
			logger.Error("Group deletion failed with API error",
				zap.String("group_pk", pk),
				zap.Int("status_code", resp.StatusCode),
				zap.String("error_detail", apiError.Detail))
			return fmt.Errorf("group deletion failed with status %d: %s", resp.StatusCode, apiError.Detail)
		}

		logger.Error("Group deletion failed",
			zap.String("group_pk", pk),
			zap.Int("status_code", resp.StatusCode),
			zap.String("response_body", string(body)))
		return fmt.Errorf("group deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	logger.Info("Successfully deleted Authentik group",
		zap.String("group_pk", pk))

	return nil
}

// GroupExists checks if a group with the given name exists
func (c *APIClient) GroupExists(ctx context.Context, name string) (bool, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Checking if Authentik group exists",
		zap.String("group_name", name))

	group, err := c.GetGroupByName(ctx, name)
	if err != nil {
		// Check if it's a "not found" error (expected, not an error condition)
		if err.Error() == fmt.Sprintf("group not found: %s", name) {
			logger.Debug("Group does not exist",
				zap.String("group_name", name))
			return false, nil
		}
		// Actual error (network, API, etc.)
		logger.Error("Failed to check if group exists",
			zap.String("group_name", name),
			zap.Error(err))
		return false, err
	}

	logger.Debug("Group exists",
		zap.String("group_name", name),
		zap.String("group_pk", group.PK))
	return true, nil
}

// CreateGroupIfNotExists creates a group only if it doesn't already exist
func (c *APIClient) CreateGroupIfNotExists(ctx context.Context, name string, attributes map[string]interface{}) (*GroupResponse, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Ensuring Authentik group exists",
		zap.String("group_name", name))

	exists, err := c.GroupExists(ctx, name)
	if err != nil {
		logger.Error("Failed to check if group exists",
			zap.String("group_name", name),
			zap.Error(err))
		return nil, fmt.Errorf("failed to check if group exists: %w", err)
	}

	if exists {
		logger.Info("Group already exists, fetching existing group",
			zap.String("group_name", name))
		return c.GetGroupByName(ctx, name)
	}

	logger.Info("Group does not exist, creating new group",
		zap.String("group_name", name))
	return c.CreateGroup(ctx, name, attributes)
}

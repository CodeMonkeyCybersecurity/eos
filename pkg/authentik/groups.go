// pkg/authentik/groups.go - Group management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GroupRequest represents the request body for creating a group
type GroupRequest struct {
	Name       string                 `json:"name"`
	Parent     string                 `json:"parent,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	IsSuperuser bool                   `json:"is_superuser,omitempty"`
}

// GroupResponse represents the response when creating/fetching a group
type GroupResponse struct {
	PK         string                 `json:"pk"`
	NumPK      int                    `json:"num_pk"`
	Name       string                 `json:"name"`
	Parent     string                 `json:"parent,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	IsSuperuser bool                   `json:"is_superuser,omitempty"`
	UsersObj   []interface{}          `json:"users_obj,omitempty"`
}

// CreateGroup creates a new group in Authentik
func (c *APIClient) CreateGroup(ctx context.Context, name string, attributes map[string]interface{}) (*GroupResponse, error) {
	reqBody := GroupRequest{
		Name:        name,
		Attributes:  attributes,
		IsSuperuser: false, // Default: NOT superuser (secure default)
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal group request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/core/groups/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("group creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("group creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var group GroupResponse
	if err := json.Unmarshal(body, &group); err != nil {
		return nil, fmt.Errorf("failed to unmarshal group response: %w", err)
	}

	return &group, nil
}

// GetGroupByName retrieves a group by name
func (c *APIClient) GetGroupByName(ctx context.Context, name string) (*GroupResponse, error) {
	url := fmt.Sprintf("%s/api/v3/core/groups/?name=%s", c.BaseURL, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("group fetch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("group fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []GroupResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode group response: %w", err)
	}

	if len(result.Results) == 0 {
		return nil, fmt.Errorf("group not found: %s", name)
	}

	return &result.Results[0], nil
}

// ListGroups lists all groups, optionally filtered by prefix
func (c *APIClient) ListGroups(ctx context.Context, namePrefix string) ([]GroupResponse, error) {
	url := fmt.Sprintf("%s/api/v3/core/groups/", c.BaseURL)
	if namePrefix != "" {
		url += fmt.Sprintf("?name__startswith=%s", namePrefix)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("groups list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("groups list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []GroupResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode groups list response: %w", err)
	}

	return result.Results, nil
}

// DeleteGroup deletes a group by PK
func (c *APIClient) DeleteGroup(ctx context.Context, pk string) error {
	url := fmt.Sprintf("%s/api/v3/core/groups/%s/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("group deletion request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("group deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GroupExists checks if a group with the given name exists
func (c *APIClient) GroupExists(ctx context.Context, name string) (bool, error) {
	_, err := c.GetGroupByName(ctx, name)
	if err != nil {
		if err.Error() == fmt.Sprintf("group not found: %s", name) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CreateGroupIfNotExists creates a group only if it doesn't already exist
func (c *APIClient) CreateGroupIfNotExists(ctx context.Context, name string, attributes map[string]interface{}) (*GroupResponse, error) {
	exists, err := c.GroupExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to check if group exists: %w", err)
	}

	if exists {
		return c.GetGroupByName(ctx, name)
	}

	return c.CreateGroup(ctx, name, attributes)
}

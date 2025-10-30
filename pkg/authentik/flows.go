// pkg/authentik/flows.go - Flow management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// FlowResponse represents an Authentik flow
type FlowResponse struct {
	PK               string `json:"pk"`
	Slug             string `json:"slug"`
	Name             string `json:"name"`
	Title            string `json:"title"`
	Designation      string `json:"designation"`
	PolicyEngineMode string `json:"policy_engine_mode"`
	DeniedAction     string `json:"denied_action"`
}

// ListFlows lists all flows, optionally filtered by designation
func (c *APIClient) ListFlows(ctx context.Context, designation string) ([]FlowResponse, error) {
	url := fmt.Sprintf("%s/api/v3/flows/instances/", c.BaseURL)
	if designation != "" {
		url += fmt.Sprintf("?designation=%s", designation)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flows list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("flows list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []FlowResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode flows list response: %w", err)
	}

	return result.Results, nil
}

// GetFlow retrieves a flow by slug
func (c *APIClient) GetFlow(ctx context.Context, slug string) (*FlowResponse, error) {
	// List flows filtered by slug (API doesn't support direct slug lookup)
	url := fmt.Sprintf("%s/api/v3/flows/instances/?slug=%s", c.BaseURL, slug)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flow fetch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("flow fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []FlowResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode flow response: %w", err)
	}

	if len(result.Results) == 0 {
		return nil, fmt.Errorf("flow with slug '%s' not found", slug)
	}

	return &result.Results[0], nil
}

// GetFlowByPK retrieves a flow by PK
func (c *APIClient) GetFlowByPK(ctx context.Context, pk string) (*FlowResponse, error) {
	url := fmt.Sprintf("%s/api/v3/flows/instances/%s/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flow fetch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("flow fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var flow FlowResponse
	if err := json.NewDecoder(resp.Body).Decode(&flow); err != nil {
		return nil, fmt.Errorf("failed to decode flow response: %w", err)
	}

	return &flow, nil
}

// UpdateFlow updates a flow's configuration
func (c *APIClient) UpdateFlow(ctx context.Context, pk string, updates map[string]interface{}) error {
	jsonBody, err := json.Marshal(updates)
	if err != nil {
		return fmt.Errorf("failed to marshal update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/flows/instances/%s/", c.BaseURL, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("flow update request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("flow update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreateEnrollmentFlow creates a new enrollment flow
func (c *APIClient) CreateEnrollmentFlow(ctx context.Context, name, slug, title string) (*FlowResponse, error) {
	reqBody := map[string]interface{}{
		"name":               name,
		"slug":               slug,
		"title":              title,
		"designation":        "enrollment",
		"policy_engine_mode": "any",
		"denied_action":      "message_continue",
		"authentication":     "none",
		"layout":             "stacked",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/flows/instances/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrollment flow creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrollment flow creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var flow FlowResponse
	if err := json.Unmarshal(body, &flow); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &flow, nil
}

// DeleteFlow deletes a flow by PK
func (c *APIClient) DeleteFlow(ctx context.Context, pk string) error {
	url := fmt.Sprintf("%s/api/v3/flows/instances/%s/", c.BaseURL, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("flow deletion request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("flow deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

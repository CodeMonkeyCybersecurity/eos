// pkg/authentik/flows.go - Flow management for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
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
// P1 FIX: Returns (nil, nil) if flow not found (distinguishes "not found" from API errors)
// This enables idempotency checks: check if exists, create if not
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
		// P1 FIX: Not found is not an error - return nil, nil
		// Caller can check: if flow != nil { exists } else { create }
		return nil, nil
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

// DeleteFlow removes a flow by PK.
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

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("flow deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteFlowBySlug removes a flow if it exists.
func (c *APIClient) DeleteFlowBySlug(ctx context.Context, slug string) error {
	flow, err := c.GetFlow(ctx, slug)
	if err != nil {
		return err
	}
	if flow == nil {
		return nil
	}
	return c.DeleteFlow(ctx, flow.PK)
}

// ImportFlow uploads a blueprint YAML definition for a flow.
func (c *APIClient) ImportFlow(ctx context.Context, yaml []byte) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Importing Authentik flow",
		zap.Int("yaml_size_bytes", len(yaml)))

	url := fmt.Sprintf("%s/api/v3/flows/instances/import/", c.BaseURL)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "flow.yaml")
	if err != nil {
		logger.Error("Failed to create multipart form for flow import",
			zap.Error(err))
		return fmt.Errorf("failed to create multipart form: %w", err)
	}

	if _, err := part.Write(yaml); err != nil {
		logger.Error("Failed to write flow blueprint to multipart form",
			zap.Error(err))
		return fmt.Errorf("failed to write flow blueprint: %w", err)
	}

	if err := writer.Close(); err != nil {
		logger.Error("Failed to finalize multipart form",
			zap.Error(err))
		return fmt.Errorf("failed to finalize multipart form: %w", err)
	}

	logger.Debug("Making flow import request",
		zap.String("url", url),
		zap.String("method", http.MethodPost),
		zap.String("content_type", writer.FormDataContentType()))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		logger.Error("Failed to create HTTP request for flow import",
			zap.String("url", url),
			zap.Error(err))
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		logger.Error("Flow import request failed",
			zap.String("url", url),
			zap.Error(err))
		return fmt.Errorf("flow import request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if readErr != nil {
		logger.Error("Failed to read import response body",
			zap.Error(readErr))
		return fmt.Errorf("failed to read response body: %w", readErr)
	}

	// CRITICAL: Log response body at INFO level so we can see what Authentik returned
	logger.Info("Received flow import response",
		zap.Int("status_code", resp.StatusCode),
		zap.Int("body_length", len(responseBody)),
		zap.String("response_body", string(responseBody))) // CRITICAL: Log actual response

	// CRITICAL FIX: Parse response body on ALL status codes, not just errors
	// Authentik may return 200 OK but include validation errors in the response
	var importResponse struct {
		Success bool     `json:"success"`
		Detail  string   `json:"detail"`
		Logs    []string `json:"logs"`
	}

	// Try to parse the response (may be JSON or empty on 204 No Content)
	if len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, &importResponse); err != nil {
			logger.Warn("Failed to parse import response as JSON",
				zap.Error(err),
				zap.String("raw_response", string(responseBody)))
			// Continue - may be plain text or empty response
		} else {
			logger.Info("Parsed import response",
				zap.Bool("success", importResponse.Success),
				zap.String("detail", importResponse.Detail),
				zap.Strings("logs", importResponse.Logs))
		}
	}

	// Check for HTTP-level errors
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		// HTTP error status
		if importResponse.Detail != "" {
			logger.Error("Flow import failed with API error",
				zap.Int("status_code", resp.StatusCode),
				zap.String("error_detail", importResponse.Detail),
				zap.Strings("import_logs", importResponse.Logs))
			return fmt.Errorf("flow import failed with status %d: %s (logs: %v)", resp.StatusCode, importResponse.Detail, importResponse.Logs)
		}

		logger.Error("Flow import failed",
			zap.Int("status_code", resp.StatusCode),
			zap.String("response_body", string(responseBody)))
		return fmt.Errorf("flow import failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	// CRITICAL: Check response body for import validation errors even on 200 OK
	if importResponse.Success == false && importResponse.Detail != "" {
		logger.Error("Flow import returned success status but validation failed",
			zap.Int("status_code", resp.StatusCode),
			zap.String("error_detail", importResponse.Detail),
			zap.Strings("import_logs", importResponse.Logs))
		return fmt.Errorf("flow import validation failed: %s (logs: %v)", importResponse.Detail, importResponse.Logs)
	}

	// Log import logs if available (may contain warnings or info)
	if len(importResponse.Logs) > 0 {
		logger.Info("Flow import completed with logs",
			zap.Strings("import_logs", importResponse.Logs))
	}

	logger.Debug("Flow import successful",
		zap.Int("status_code", resp.StatusCode),
		zap.String("note", "Flow may take a few seconds to become queryable due to API indexing"))

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

// GetFlowStages retrieves all stage bindings for a flow (ordered by binding order)
// Returns stages in execution order for the given flow
func (c *APIClient) GetFlowStages(ctx context.Context, flowPK string) ([]StageBindingResponse, error) {
	url := fmt.Sprintf("%s/api/v3/flows/bindings/?target=%s&ordering=order", c.BaseURL, flowPK)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("flow stages request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("flow stages fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []StageBindingResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode flow stages response: %w", err)
	}

	return result.Results, nil
}

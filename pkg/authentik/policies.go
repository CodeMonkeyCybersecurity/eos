// pkg/authentik/policies.go - Expression policy and binding helpers for Authentik

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ExpressionPolicyResponse represents an Authentik expression policy.
type ExpressionPolicyResponse struct {
	PK         string `json:"pk"`
	Name       string `json:"name"`
	Expression string `json:"expression"`
}

// PolicyBindingResponse represents a policy binding in Authentik.
type PolicyBindingResponse struct {
	PK      string `json:"pk"`
	Policy  string `json:"policy"`
	Target  string `json:"target"`
	Order   int    `json:"order"`
	Enabled bool   `json:"enabled"`
	Timeout int    `json:"timeout"`
}

// GetExpressionPolicyByName looks up an expression policy by name.
func (c *APIClient) GetExpressionPolicyByName(ctx context.Context, name string) (*ExpressionPolicyResponse, error) {
	query := url.QueryEscape(name)
	path := fmt.Sprintf("%s/api/v3/policies/expression/?name=%s", c.BaseURL, query)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("expression policy lookup failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("expression policy lookup failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []ExpressionPolicyResponse `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode expression policy response: %w", err)
	}

	if len(result.Results) == 0 {
		return nil, nil
	}

	return &result.Results[0], nil
}

// CreateExpressionPolicy creates a new expression policy.
func (c *APIClient) CreateExpressionPolicy(ctx context.Context, name, expression string) (*ExpressionPolicyResponse, error) {
	payload := map[string]interface{}{
		"name":       name,
		"expression": expression,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal expression policy request: %w", err)
	}

	path := fmt.Sprintf("%s/api/v3/policies/expression/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("expression policy creation failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("expression policy creation failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var policy ExpressionPolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to decode expression policy response: %w", err)
	}

	return &policy, nil
}

// EnsureExpressionPolicy returns an existing expression policy or creates a new one.
func (c *APIClient) EnsureExpressionPolicy(ctx context.Context, name, expression string) (*ExpressionPolicyResponse, error) {
	existing, err := c.GetExpressionPolicyByName(ctx, name)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		return existing, nil
	}

	return c.CreateExpressionPolicy(ctx, name, expression)
}

// GetPolicyBinding fetches the first binding that matches the provided policy and target.
func (c *APIClient) GetPolicyBinding(ctx context.Context, policyPK, targetPK string) (*PolicyBindingResponse, error) {
	query := fmt.Sprintf("%s/api/v3/policies/bindings/?policy=%s&target=%s", c.BaseURL, url.QueryEscape(policyPK), url.QueryEscape(targetPK))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy binding lookup failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("policy binding lookup failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []PolicyBindingResponse `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode policy binding response: %w", err)
	}

	if len(result.Results) == 0 {
		return nil, nil
	}

	return &result.Results[0], nil
}

// CreatePolicyBinding creates a new policy binding.
func (c *APIClient) CreatePolicyBinding(ctx context.Context, policyPK, targetPK string, order, timeout int, enabled bool) (*PolicyBindingResponse, error) {
	payload := map[string]interface{}{
		"policy":  policyPK,
		"target":  targetPK,
		"order":   order,
		"timeout": timeout,
		"enabled": enabled,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy binding request: %w", err)
	}

	path := fmt.Sprintf("%s/api/v3/policies/bindings/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy binding creation failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("policy binding creation failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var binding PolicyBindingResponse
	if err := json.NewDecoder(resp.Body).Decode(&binding); err != nil {
		return nil, fmt.Errorf("failed to decode policy binding response: %w", err)
	}

	return &binding, nil
}

// EnsurePolicyBinding ensures a policy binding exists with the desired attributes.
func (c *APIClient) EnsurePolicyBinding(ctx context.Context, policyPK, targetPK string, order, timeout int, enabled bool) (*PolicyBindingResponse, error) {
	existing, err := c.GetPolicyBinding(ctx, policyPK, targetPK)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		return existing, nil
	}

	return c.CreatePolicyBinding(ctx, policyPK, targetPK, order, timeout, enabled)
}

// DeleteExpressionPolicy removes an expression policy by primary key.
func (c *APIClient) DeleteExpressionPolicy(ctx context.Context, pk string) error {
	path := fmt.Sprintf("%s/api/v3/policies/expression/%s/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("expression policy deletion failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("expression policy deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeletePolicyBinding removes a policy binding by primary key.
func (c *APIClient) DeletePolicyBinding(ctx context.Context, pk string) error {
	path := fmt.Sprintf("%s/api/v3/policies/bindings/%s/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("policy binding deletion failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("policy binding deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

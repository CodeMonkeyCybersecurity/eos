// pkg/authentik/stages.go - Stage management for Authentik flows

package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// StageResponse represents a generic stage in Authentik
type StageResponse struct {
	PK          string `json:"pk"`
	Name        string `json:"name"`
	Component   string `json:"component"`
	VerboseName string `json:"verbose_name"`
	Type        string `json:"type"`
}

// PromptStageResponse represents a prompt stage
type PromptStageResponse struct {
	PK               string   `json:"pk"`
	Name             string   `json:"name"`
	Fields           []string `json:"fields"` // UUIDs of prompt fields
	ValidationPolicy string   `json:"validation_policy,omitempty"`
}

// PromptFieldResponse represents a prompt field
type PromptFieldResponse struct {
	PK                    string `json:"pk"`
	Name                  string `json:"name"`
	FieldKey              string `json:"field_key"`
	Type                  string `json:"type"` // text, email, password, username, etc.
	Required              bool   `json:"required"`
	Placeholder           string `json:"placeholder,omitempty"`
	Label                 string `json:"label,omitempty"`
	Order                 int    `json:"order"`
	PlaceholderExpression bool   `json:"placeholder_expression"`
}

// EmailStageResponse represents an email stage
type EmailStageResponse struct {
	PK          string `json:"pk"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	UseTLS      bool   `json:"use_tls"`
	UseSSL      bool   `json:"use_ssl"`
	Timeout     int    `json:"timeout"`
	FromAddress string `json:"from_address"`
}

// UserWriteStageResponse represents a user write stage
type UserWriteStageResponse struct {
	PK                    string `json:"pk"`
	Name                  string `json:"name"`
	CreateUsersAsInactive bool   `json:"create_users_as_inactive"`
	CreateUsersGroup      string `json:"create_users_group,omitempty"`
	UserPathTemplate      string `json:"user_path_template"`
}

// PasswordStageResponse represents a password stage
type PasswordStageResponse struct {
	PK                         string   `json:"pk"`
	Name                       string   `json:"name"`
	Backends                   []string `json:"backends"`
	ConfigureFlow              string   `json:"configure_flow,omitempty"`
	FailedAttemptsBeforeCancel int      `json:"failed_attempts_before_cancel"`
}

// StageBindingResponse represents a binding between a flow and a stage
type StageBindingResponse struct {
	PK                 string          `json:"pk"`
	Target             string          `json:"target"` // Flow PK
	Stage              string          `json:"stage"`  // Stage PK
	Order              int             `json:"order"`
	EvaluateOnPlan     bool            `json:"evaluate_on_plan"`
	ReEvaluatePolicies bool            `json:"re_evaluate_policies"`
	StageObj           *StageResponse  `json:"stage_obj,omitempty"`
	TargetObj          *FlowSummary    `json:"target_obj,omitempty"`
	PolicyBindings     []PolicyBinding `json:"policy_bindings,omitempty"`
}

// FlowSummary represents minimal flow metadata returned in binding lookups
type FlowSummary struct {
	PK          string `json:"pk"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Designation string `json:"designation"`
}

// PolicyBinding summarizes a policy attached to a binding
type PolicyBinding struct {
	PK      string `json:"pk"`
	Policy  string `json:"policy"`
	Negate  bool   `json:"negate"`
	Enabled bool   `json:"enabled"`
	Order   int    `json:"order"`
}

// ListStages lists all stages
func (c *APIClient) ListStages(ctx context.Context) ([]StageResponse, error) {
	url := fmt.Sprintf("%s/api/v3/stages/all/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stages list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("stages list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []StageResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode stages list response: %w", err)
	}

	return result.Results, nil
}

// CreateUserWriteStage creates a user write stage
func (c *APIClient) CreateUserWriteStage(ctx context.Context, name string, createAsInactive bool, groupPK string) (*UserWriteStageResponse, error) {
	reqBody := map[string]interface{}{
		"name":                     name,
		"create_users_as_inactive": createAsInactive,
		"user_path_template":       "users",
	}

	if groupPK != "" {
		reqBody["create_users_group"] = groupPK
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/user_write/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user write stage creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user write stage creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var stage UserWriteStageResponse
	if err := json.Unmarshal(body, &stage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &stage, nil
}

// GetUserWriteStage retrieves a user-write stage by primary key.
func (c *APIClient) GetUserWriteStage(ctx context.Context, pk string) (*UserWriteStageResponse, error) {
	url := fmt.Sprintf("%s/api/v3/stages/user_write/%s/", c.BaseURL, pk)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user write stage fetch failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("user write stage fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var stage UserWriteStageResponse
	if err := json.NewDecoder(resp.Body).Decode(&stage); err != nil {
		return nil, fmt.Errorf("failed to decode user write stage response: %w", err)
	}

	return &stage, nil
}

// UpdateUserWriteStage applies partial updates to a user-write stage.
func (c *APIClient) UpdateUserWriteStage(ctx context.Context, pk string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}

	jsonBody, err := json.Marshal(updates)
	if err != nil {
		return fmt.Errorf("failed to marshal user write stage update: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/user_write/%s/", c.BaseURL, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("user write stage update failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("user write stage update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// UpdateStage performs a generic PATCH update for a stage of the specified type.
func (c *APIClient) UpdateStage(ctx context.Context, stageType, pk string, updates map[string]interface{}) error {
	if strings.TrimSpace(stageType) == "" {
		return fmt.Errorf("stage type is required")
	}
	if strings.TrimSpace(pk) == "" {
		return fmt.Errorf("stage primary key is required")
	}
	if len(updates) == 0 {
		return fmt.Errorf("updates map is empty")
	}

	jsonBody, err := json.Marshal(updates)
	if err != nil {
		return fmt.Errorf("failed to marshal stage update request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/%s/%s/", c.BaseURL, stageType, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("stage update request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("stage update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreatePasswordStage creates a password stage
func (c *APIClient) CreatePasswordStage(ctx context.Context, name string) (*PasswordStageResponse, error) {
	reqBody := map[string]interface{}{
		"name":                          name,
		"backends":                      []string{"authentik.core.auth.InbuiltBackend"},
		"failed_attempts_before_cancel": 5,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/password/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("password stage creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("password stage creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var stage PasswordStageResponse
	if err := json.Unmarshal(body, &stage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &stage, nil
}

// CreateStageBinding binds a stage to a flow
func (c *APIClient) CreateStageBinding(ctx context.Context, flowPK, stagePK string, order int) (*StageBindingResponse, error) {
	reqBody := map[string]interface{}{
		"target":               flowPK,
		"stage":                stagePK,
		"order":                order,
		"evaluate_on_plan":     true,
		"re_evaluate_policies": false,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/flows/bindings/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stage binding creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stage binding creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var binding StageBindingResponse
	if err := json.Unmarshal(body, &binding); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &binding, nil
}

// ListFlowBindings lists all stage bindings for a flow
func (c *APIClient) ListFlowBindings(ctx context.Context, flowPK string) ([]StageBindingResponse, error) {
	url := fmt.Sprintf("%s/api/v3/flows/bindings/?target=%s", c.BaseURL, flowPK)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bindings list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("bindings list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []StageBindingResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode bindings list response: %w", err)
	}

	return result.Results, nil
}

// DeleteStageBinding deletes a stage binding by PK
func (c *APIClient) DeleteStageBinding(ctx context.Context, pk string) error {
	url := fmt.Sprintf("%s/api/v3/flows/bindings/%s/", c.BaseURL, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("stage binding deletion request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("stage binding deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListPromptFields lists all existing prompt fields
func (c *APIClient) ListPromptFields(ctx context.Context) ([]PromptFieldResponse, error) {
	url := fmt.Sprintf("%s/api/v3/stages/prompt/prompts/", c.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prompt fields list request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("prompt fields list failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Results []PromptFieldResponse `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode prompt fields list response: %w", err)
	}

	return result.Results, nil
}

// CreatePromptField creates a prompt field for use in prompt stages
func (c *APIClient) CreatePromptField(ctx context.Context, fieldKey, fieldType, label, placeholder string, required bool, order int) (*PromptFieldResponse, error) {
	// P0 FIX: Authentik requires 'name' field (internal identifier) per API schema
	// The 'name' field is the internal identifier, 'label' is the display text
	// Generate name from field_key (e.g., "username" -> "eos-username-field")
	name := fmt.Sprintf("eos-%s-field", fieldKey)

	reqBody := map[string]interface{}{
		"name":                   name,      // REQUIRED: Internal identifier for the prompt field
		"field_key":              fieldKey,  // The form field name (used in expressions)
		"type":                   fieldType, // Field type (username, email, password, etc.)
		"label":                  label,     // Display text shown to users
		"required":               required,
		"placeholder":            placeholder,
		"placeholder_expression": false,
		"order":                  order,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/prompt/prompts/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prompt field creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prompt field creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var field PromptFieldResponse
	if err := json.Unmarshal(body, &field); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &field, nil
}

// CreatePromptStage creates a prompt stage with specified fields
func (c *APIClient) CreatePromptStage(ctx context.Context, name string, fieldPKs []string) (*PromptStageResponse, error) {
	reqBody := map[string]interface{}{
		"name":   name,
		"fields": fieldPKs,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/prompt/stages/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prompt stage creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prompt stage creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var stage PromptStageResponse
	if err := json.Unmarshal(body, &stage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &stage, nil
}

// UserLoginStageResponse represents a user login stage
type UserLoginStageResponse struct {
	PK                     string `json:"pk"`
	Name                   string `json:"name"`
	SessionDuration        string `json:"session_duration"`
	TerminateOtherSessions bool   `json:"terminate_other_sessions"`
	RememberMeOffset       string `json:"remember_me_offset"`
}

// CreateUserLoginStage creates a user login stage (for auto-login after enrollment)
func (c *APIClient) CreateUserLoginStage(ctx context.Context, name string) (*UserLoginStageResponse, error) {
	reqBody := map[string]interface{}{
		"name":                     name,
		"session_duration":         "seconds=0", // 0 = use default session duration
		"terminate_other_sessions": false,
		"remember_me_offset":       "weeks=4",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/user_login/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user login stage creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user login stage creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var stage UserLoginStageResponse
	if err := json.Unmarshal(body, &stage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &stage, nil
}

// CaptchaStageResponse represents a captcha stage
type CaptchaStageResponse struct {
	PK                string  `json:"pk"`
	Name              string  `json:"name"`
	PublicKey         string  `json:"public_key"`
	PrivateKey        string  `json:"private_key"`
	JSUrl             string  `json:"js_url,omitempty"`
	APIUrl            string  `json:"api_url,omitempty"`
	ScoreMinThreshold float64 `json:"score_min_threshold"`
	ScoreMaxThreshold float64 `json:"score_max_threshold"`
	ErrorOnInvalid    bool    `json:"error_on_invalid"`
}

// CreateCaptchaStage creates a captcha stage (hCaptcha or reCAPTCHA)
// If publicKey and privateKey are empty, uses Authentik's test keys (not for production!)
func (c *APIClient) CreateCaptchaStage(ctx context.Context, name, publicKey, privateKey string) (*CaptchaStageResponse, error) {
	// Use test keys if not provided (WARNING: Only for development/testing!)
	if publicKey == "" {
		publicKey = "10000000-ffff-ffff-ffff-000000000001" // hCaptcha test key
	}
	if privateKey == "" {
		privateKey = "0x0000000000000000000000000000000000000000" // hCaptcha test private key
	}

	reqBody := map[string]interface{}{
		"name":                name,
		"public_key":          publicKey,
		"private_key":         privateKey,
		"score_min_threshold": 0.0,
		"score_max_threshold": 1.0,
		"error_on_invalid":    true,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/captcha/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("captcha stage creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("captcha stage creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var stage CaptchaStageResponse
	if err := json.Unmarshal(body, &stage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &stage, nil
}

// EmailStageTemplateChoices represents email template choices
const (
	EmailTemplateAccountConfirmation = "account_confirmation"
	EmailTemplatePasswordReset       = "password_reset"
	EmailTemplateActivation          = "activation"
)

// CreateEmailVerificationStage creates an email verification stage for enrollment
func (c *APIClient) CreateEmailVerificationStage(ctx context.Context, name, fromAddress, host string, port int, template string) (*EmailStageResponse, error) {
	if template == "" {
		template = EmailTemplateAccountConfirmation
	}

	reqBody := map[string]interface{}{
		"name":                     name,
		"activate_user_on_success": true,
		"use_global_settings":      false,
		"host":                     host,
		"port":                     port,
		"username":                 "",
		"use_tls":                  true,
		"use_ssl":                  false,
		"timeout":                  30,
		"from_address":             fromAddress,
		"token_expiry":             30, // minutes
		"subject":                  "Confirm your account",
		"template":                 template,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v3/stages/email/", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("email stage creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("email stage creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var stage EmailStageResponse
	if err := json.Unmarshal(body, &stage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &stage, nil
}

// DeleteStage deletes a stage by PK (works for all stage types)
func (c *APIClient) DeleteStage(ctx context.Context, pk string) error {
	// Authentik uses /api/v3/stages/all/{pk}/ for generic stage deletion
	url := fmt.Sprintf("%s/api/v3/stages/all/%s/", c.BaseURL, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("stage deletion request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("stage deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeletePromptField deletes a prompt field by PK
func (c *APIClient) DeletePromptField(ctx context.Context, pk string) error {
	url := fmt.Sprintf("%s/api/v3/stages/prompt/prompts/%s/", c.BaseURL, pk)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("prompt field deletion request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("prompt field deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

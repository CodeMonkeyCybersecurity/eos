// pkg/salt/api.go

package saltstack

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client represents a Salt API client
type Client struct {
	BaseURL    string
	Username   string
	Password   string
	Token      string
	HTTPClient *http.Client
}

// NewClient creates a new Salt API client
func NewClient(baseURL, username, password string) *Client {
	return &Client{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For self-signed certs; configure properly in production
				},
			},
		},
	}
}

// LoginResponse represents the response from the login endpoint
type LoginResponse struct {
	Return []struct {
		Token  string   `json:"token"`
		Expire float64  `json:"expire"`
		Start  float64  `json:"start"`
		User   string   `json:"user"`
		EAuth  string   `json:"eauth"`
		Perms  []string `json:"perms"`
	} `json:"return"`
}

// Login authenticates with the Salt API and stores the token
func (c *Client) Login() error {
	loginData := map[string]string{
		"username": c.Username,
		"password": c.Password,
		"eauth":    "pam", // or "ldap", "auto", etc.
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return fmt.Errorf("failed to marshal login data: %w", err)
	}

	resp, err := c.HTTPClient.Post(
		c.BaseURL+"/login",
		"application/json",
		bytes.NewReader(jsonData),
	)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read login response: %w", err)
	}

	var loginResp LoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return fmt.Errorf("failed to parse login response: %w", err)
	}

	if len(loginResp.Return) == 0 {
		return fmt.Errorf("login failed: no token returned")
	}

	c.Token = loginResp.Return[0].Token
	return nil
}

// doRequest executes an authenticated request
func (c *Client) doRequest(method, endpoint string, data interface{}) (json.RawMessage, error) {
	if c.Token == "" {
		if err := c.Login(); err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request data: %w", err)
	}

	req, err := http.NewRequest(method, c.BaseURL+endpoint, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check if we need to re-authenticate
	if resp.StatusCode == 401 {
		c.Token = ""
		return c.doRequest(method, endpoint, data) // Retry with fresh token
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse the standard Salt response format
	var saltResp struct {
		Return json.RawMessage `json:"return"`
	}

	if err := json.Unmarshal(body, &saltResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return saltResp.Return, nil
}

// RunCommand executes a Salt command on targeted minions
func (c *Client) RunCommand(target, targetType, function string, args []interface{}, kwargs map[string]interface{}) (map[string]interface{}, error) {
	requestData := map[string]interface{}{
		"client": "local",
		"tgt":    target,
		"fun":    function,
	}

	// Add target type if not a simple glob
	if targetType != "" && targetType != "glob" {
		requestData["tgt_type"] = targetType
	}

	// Add arguments if provided
	if len(args) > 0 {
		requestData["arg"] = args
	}

	// Add keyword arguments if provided
	if len(kwargs) > 0 {
		requestData["kwarg"] = kwargs
	}

	result, err := c.doRequest("POST", "/", requestData)
	if err != nil {
		return nil, err
	}

	// Parse the result
	var cmdResult []map[string]interface{}
	if err := json.Unmarshal(result, &cmdResult); err != nil {
		return nil, fmt.Errorf("failed to parse command result: %w", err)
	}

	if len(cmdResult) == 0 {
		return nil, fmt.Errorf("no results returned")
	}

	return cmdResult[0], nil
}

// ApplyState applies a Salt state to targeted minions
func (c *Client) ApplyState(target, targetType, state string, pillar map[string]interface{}) (map[string]interface{}, error) {
	kwargs := make(map[string]interface{})
	if pillar != nil {
		kwargs["pillar"] = pillar
	}

	return c.RunCommand(target, targetType, "state.apply", []interface{}{state}, kwargs)
}

// GetGrains retrieves grains from targeted minions
func (c *Client) GetGrains(target, targetType string, grains []string) (map[string]interface{}, error) {
	// Convert []string to []interface{} for RunCommand
	args := make([]interface{}, len(grains))
	for i, grain := range grains {
		args[i] = grain
	}
	return c.RunCommand(target, targetType, "grains.items", args, nil)
}

// JobResult represents a Salt job result
type JobResult struct {
	JID     string                 `json:"jid"`
	Minions []string               `json:"minions"`
	Result  map[string]interface{} `json:"result"`
}

// RunJobAsync starts an asynchronous Salt job
func (c *Client) RunJobAsync(target, targetType, function string, args []interface{}) (string, error) {
	requestData := map[string]interface{}{
		"client": "local_async",
		"tgt":    target,
		"fun":    function,
	}

	if targetType != "" && targetType != "glob" {
		requestData["tgt_type"] = targetType
	}

	if len(args) > 0 {
		requestData["arg"] = args
	}

	result, err := c.doRequest("POST", "/", requestData)
	if err != nil {
		return "", err
	}

	var jobResp []struct {
		JID     string   `json:"jid"`
		Minions []string `json:"minions"`
	}

	if err := json.Unmarshal(result, &jobResp); err != nil {
		return "", fmt.Errorf("failed to parse job response: %w", err)
	}

	if len(jobResp) == 0 {
		return "", fmt.Errorf("no job ID returned")
	}

	return jobResp[0].JID, nil
}

// GetJobResult retrieves the result of an asynchronous job
func (c *Client) GetJobResult(jid string) (*JobResult, error) {
	requestData := map[string]interface{}{
		"client": "runner",
		"fun":    "jobs.lookup_jid",
		"arg":    []string{jid},
	}

	result, err := c.doRequest("POST", "/", requestData)
	if err != nil {
		return nil, err
	}

	var jobResults []map[string]interface{}
	if err := json.Unmarshal(result, &jobResults); err != nil {
		return nil, fmt.Errorf("failed to parse job result: %w", err)
	}

	if len(jobResults) == 0 || len(jobResults[0]) == 0 {
		return nil, fmt.Errorf("job not found or still running")
	}

	// Extract minions and results
	minions := make([]string, 0, len(jobResults[0]))
	for minion := range jobResults[0] {
		minions = append(minions, minion)
	}

	return &JobResult{
		JID:     jid,
		Minions: minions,
		Result:  jobResults[0],
	}, nil
}

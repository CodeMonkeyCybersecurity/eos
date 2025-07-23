// pkg/saltstack/rest_client.go

package saltstack

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RESTClient handles communication with Salt REST API (CherryPy)
type RESTClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
	logger     *zap.Logger
}

// AuthRequest represents authentication request to Salt API
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Eauth    string `json:"eauth"`
}

// AuthResponse represents authentication response from Salt API
type AuthResponse struct {
	Return []struct {
		Token  string   `json:"token"`
		User   string   `json:"user"`
		Expire float64  `json:"expire"`
		Perms  []string `json:"perms"`
	} `json:"return"`
}

// ExecutionRequest represents a command execution request
type ExecutionRequest struct {
	Client   string                 `json:"client"`
	Target   string                 `json:"tgt"`
	Function string                 `json:"fun"`
	Args     []interface{}          `json:"arg,omitempty"`
	Kwargs   map[string]interface{} `json:"kwarg,omitempty"`
	Expr     string                 `json:"expr_form,omitempty"`
}

// StateApplyRequest represents a state apply request
type StateApplyRequest struct {
	Client string                 `json:"client"`
	Target string                 `json:"tgt"`
	Fun    string                 `json:"fun"`
	Arg    []string               `json:"arg,omitempty"`
	Kwarg  map[string]interface{} `json:"kwarg,omitempty"`
}

// RESTResponse represents a generic response from Salt API
type RESTResponse struct {
	Return []interface{} `json:"return"`
}

// NewRESTClient creates a new Salt REST API client
func NewRESTClient(baseURL string, skipTLSVerify bool) *RESTClient {
	// Configure HTTP client with optional TLS verification skip
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
		},
	}

	return &RESTClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		logger: zap.L(),
	}
}

// Authenticate authenticates with the Salt API and obtains a token
func (c *RESTClient) Authenticate(ctx context.Context, username, password, eauth string) error {
	logger := c.logger.With(zap.String("method", "Authenticate"))

	authReq := AuthRequest{
		Username: username,
		Password: password,
		Eauth:    eauth,
	}

	body, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/login", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	if len(authResp.Return) == 0 || authResp.Return[0].Token == "" {
		return fmt.Errorf("authentication failed: no token received")
	}

	c.token = authResp.Return[0].Token
	logger.Info("Successfully authenticated with Salt API",
		zap.String("user", authResp.Return[0].User),
		zap.Float64("expire", authResp.Return[0].Expire))

	return nil
}

// SetToken sets the authentication token directly (for pre-authenticated scenarios)
func (c *RESTClient) SetToken(token string) {
	c.token = token
}

// makeRequest makes an authenticated request to the Salt API
func (c *RESTClient) makeRequest(ctx context.Context, method, endpoint string, body interface{}) (*RESTResponse, error) {
	if c.token == "" {
		return nil, fmt.Errorf("not authenticated - call Authenticate() first")
	}

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	url := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	c.logger.Debug("Making Salt API request",
		zap.String("method", method),
		zap.String("url", url))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication expired or invalid")
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var apiResp RESTResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &apiResp, nil
}

// ExecuteCommand executes a Salt command via the REST API
func (c *RESTClient) ExecuteCommand(ctx context.Context, target, function string, args []interface{}, kwargs map[string]interface{}) (map[string]interface{}, error) {
	logger := c.logger.With(
		zap.String("method", "ExecuteCommand"),
		zap.String("target", target),
		zap.String("function", function))

	req := ExecutionRequest{
		Client:   "local",
		Target:   target,
		Function: function,
		Args:     args,
		Kwargs:   kwargs,
	}

	resp, err := c.makeRequest(ctx, "POST", "/", req)
	if err != nil {
		return nil, fmt.Errorf("execution request failed: %w", err)
	}

	// Extract result from response
	if len(resp.Return) == 0 {
		return nil, fmt.Errorf("empty response from Salt API")
	}

	// The response format is typically: [{"minion1": result1, "minion2": result2}]
	result, ok := resp.Return[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}

	logger.Debug("Command executed successfully", zap.Int("minions", len(result)))
	return result, nil
}

// ApplyState applies a Salt state via the REST API
func (c *RESTClient) ApplyState(ctx context.Context, target, state string, pillar map[string]interface{}) (map[string]interface{}, error) {
	logger := c.logger.With(
		zap.String("method", "ApplyState"),
		zap.String("target", target),
		zap.String("state", state))

	// Build kwargs with pillar data if provided
	kwargs := make(map[string]interface{})
	if len(pillar) > 0 {
		kwargs["pillar"] = pillar
	}

	// Determine function based on state
	function := "state.apply"
	args := []interface{}{}
	if state != "" && state != "highstate" {
		args = append(args, state)
	}

	req := ExecutionRequest{
		Client:   "local",
		Target:   target,
		Function: function,
		Args:     args,
		Kwargs:   kwargs,
	}

	resp, err := c.makeRequest(ctx, "POST", "/", req)
	if err != nil {
		return nil, fmt.Errorf("state apply request failed: %w", err)
	}

	// Extract result from response
	if len(resp.Return) == 0 {
		return nil, fmt.Errorf("empty response from Salt API")
	}

	result, ok := resp.Return[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}

	logger.Info("State applied successfully",
		zap.String("state", state),
		zap.Int("minions", len(result)))

	return result, nil
}

// RunLocalCommand runs a command via local client (on master only)
func (c *RESTClient) RunLocalCommand(ctx context.Context, function string, args []interface{}) (interface{}, error) {
	logger := c.logger.With(
		zap.String("method", "RunLocalCommand"),
		zap.String("function", function))

	req := ExecutionRequest{
		Client:   "local",
		Target:   "*",
		Function: function,
		Args:     args,
	}

	resp, err := c.makeRequest(ctx, "POST", "/", req)
	if err != nil {
		return nil, fmt.Errorf("local command request failed: %w", err)
	}

	if len(resp.Return) == 0 {
		return nil, fmt.Errorf("empty response from Salt API")
	}

	logger.Debug("Local command executed successfully")
	return resp.Return[0], nil
}

// TestPing tests connectivity to minions
func (c *RESTClient) TestPing(ctx context.Context, target string) (map[string]bool, error) {
	logger := c.logger.With(
		zap.String("method", "TestPing"),
		zap.String("target", target))

	result, err := c.ExecuteCommand(ctx, target, "test.ping", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("ping test failed: %w", err)
	}

	// Convert result to bool map
	pingResult := make(map[string]bool)
	for minion, response := range result {
		if response == true || response == "True" {
			pingResult[minion] = true
		} else {
			pingResult[minion] = false
		}
	}

	logger.Info("Ping test completed",
		zap.Int("total_minions", len(pingResult)),
		zap.Int("responsive", countTrue(pingResult)))

	return pingResult, nil
}

// GetMinions returns a list of all minions
func (c *RESTClient) GetMinions(ctx context.Context) ([]string, error) {
	logger := c.logger.With(zap.String("method", "GetMinions"))

	// Use Salt's manage.up runner to get list of responsive minions
	req := ExecutionRequest{
		Client:   "runner",
		Function: "manage.up",
	}

	resp, err := c.makeRequest(ctx, "POST", "/", req)
	if err != nil {
		return nil, fmt.Errorf("get minions request failed: %w", err)
	}

	if len(resp.Return) == 0 {
		return nil, fmt.Errorf("empty response from Salt API")
	}

	// Extract minion list from response
	minions := []string{}
	if minionList, ok := resp.Return[0].([]interface{}); ok {
		for _, m := range minionList {
			if minion, ok := m.(string); ok {
				minions = append(minions, minion)
			}
		}
	}

	logger.Info("Retrieved minion list", zap.Int("count", len(minions)))
	return minions, nil
}

// GetJobResult retrieves the result of an async job
func (c *RESTClient) GetJobResult(ctx context.Context, jobID string) (map[string]interface{}, error) {
	logger := c.logger.With(
		zap.String("method", "GetJobResult"),
		zap.String("job_id", jobID))

	req := ExecutionRequest{
		Client:   "runner",
		Function: "jobs.lookup_jid",
		Args:     []interface{}{jobID},
	}

	resp, err := c.makeRequest(ctx, "POST", "/", req)
	if err != nil {
		return nil, fmt.Errorf("job lookup request failed: %w", err)
	}

	if len(resp.Return) == 0 {
		return nil, fmt.Errorf("empty response from Salt API")
	}

	result, ok := resp.Return[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}

	logger.Debug("Retrieved job result", zap.String("job_id", jobID))
	return result, nil
}

// ValidateConnection validates the connection to Salt API
func (c *RESTClient) ValidateConnection(ctx context.Context) error {
	// Try a simple API call to validate connection and authentication
	_, err := c.TestPing(ctx, "*")
	if err != nil {
		if strings.Contains(err.Error(), "authentication") {
			return fmt.Errorf("authentication failed - token may be expired")
		}
		return fmt.Errorf("connection validation failed: %w", err)
	}
	return nil
}

// Helper function to count true values in a bool map
func countTrue(m map[string]bool) int {
	count := 0
	for _, v := range m {
		if v {
			count++
		}
	}
	return count
}

// ConfigureRESTAPI configures the Salt REST API on the system
func ConfigureRESTAPI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Salt REST API (CherryPy)")

	// Create REST API configuration
	config := `# Salt REST API Configuration
rest_cherrypy:
  port: 8000
  host: 0.0.0.0
  ssl_crt: /etc/pki/tls/certs/salt-api.crt
  ssl_key: /etc/pki/tls/private/salt-api.key
  webhook_disable_auth: False
  webhook_url: /hook
  thread_pool: 100
  socket_queue_size: 30
  expire_responses: True
  max_request_body_size: 1048576
  collect_stats: True

# External authentication
external_auth:
  pam:
    salt:
      - .*
      - '@wheel'
      - '@runner'
      - '@jobs'
  file:
    ^filename: /etc/salt/user_list
    salt:
      - .*
`

	// Write configuration to master.d
	configPath := "/etc/salt/master.d/api.conf"
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write API configuration: %w", err)
	}

	logger.Info("Salt REST API configuration written", zap.String("path", configPath))
	return nil
}

// CreateAPIUser creates a system user for Salt API authentication
func CreateAPIUser(rc *eos_io.RuntimeContext, username, password string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating Salt API user", zap.String("username", username))

	// Create system user
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "useradd",
		Args:    []string{"-r", "-s", "/bin/false", username},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		// User might already exist
		logger.Debug("User creation failed, may already exist", zap.Error(err))
	}

	// Set password using chpasswd via echo pipe
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "bash",
		Args:    []string{"-c", fmt.Sprintf("echo '%s:%s' | chpasswd", username, password)},
		Shell:   true,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to set user password: %w", err)
	}

	// Add user to salt group if it exists
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "usermod",
		Args:    []string{"-a", "-G", "salt", username},
		Timeout: 10 * time.Second,
	})

	logger.Info("Salt API user created successfully")
	return nil
}

// GenerateAPISSLCerts generates self-signed SSL certificates for the API
func GenerateAPISSLCerts(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating SSL certificates for Salt API")

	// Create certificate directories
	certDirs := []string{
		"/etc/pki/tls/certs",
		"/etc/pki/tls/private",
	}

	for _, dir := range certDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Generate self-signed certificate
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "openssl",
		Args: []string{
			"req", "-new", "-x509", "-days", "365", "-nodes",
			"-out", "/etc/pki/tls/certs/salt-api.crt",
			"-keyout", "/etc/pki/tls/private/salt-api.key",
			"-subj", "/C=US/ST=State/L=City/O=Organization/CN=salt-api",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to generate SSL certificate: %w", err)
	}

	// Set proper permissions
	if err := os.Chmod("/etc/pki/tls/private/salt-api.key", 0600); err != nil {
		return fmt.Errorf("failed to set key permissions: %w", err)
	}

	logger.Info("SSL certificates generated successfully")
	return nil
}
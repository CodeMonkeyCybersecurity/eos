// pkg/salt/client/http.go
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewHTTPSaltClient creates a new HTTP Salt client
func NewHTTPSaltClient(rc *eos_io.RuntimeContext, config *ClientConfig) (*HTTPSaltClient, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if config.BaseURL == "" {
		return nil, &SaltError{
			Code:    400,
			Message: "base URL is required",
			Type:    ErrInvalidRequest,
		}
	}

	if config.Username == "" || config.Password == "" {
		return nil, &SaltError{
			Code:    400,
			Message: "username and password are required",
			Type:    ErrInvalidRequest,
		}
	}

	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 2 * time.Second
	}
	if config.Eauth == "" {
		config.Eauth = "pam"
	}
	if config.TokenRefreshTime == 0 {
		config.TokenRefreshTime = 10 * time.Minute
	}

	client := &HTTPSaltClient{
		config: config,
		rc:     rc,
	}

	logger.Info("Created Salt HTTP client",
		zap.String("base_url", config.BaseURL),
		zap.String("username", config.Username),
		zap.String("eauth", config.Eauth))

	return client, nil
}

// Login authenticates with Salt API and retrieves token
func (c *HTTPSaltClient) Login(ctx context.Context, credentials *Credentials) (*AuthResponse, error) {
	logger := otelzap.Ctx(ctx)

	if credentials == nil {
		credentials = &Credentials{
			Username: c.config.Username,
			Password: c.config.Password,
			Eauth:    c.config.Eauth,
		}
	}

	loginData := map[string]interface{}{
		"username": credentials.Username,
		"password": credentials.Password,
		"eauth":    credentials.Eauth,
	}

	if credentials.TokenTTL > 0 {
		loginData["token_ttl"] = credentials.TokenTTL
	}

	response, err := c.makeRequest(ctx, "POST", "/login", loginData, false)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(response, &authResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse auth response: %v", err),
			Type:    ErrAuthenticationFailed,
		}
	}

	if authResp.Token == "" {
		return nil, &SaltError{
			Code:    401,
			Message: "authentication failed - no token received",
			Type:    ErrAuthenticationFailed,
		}
	}

	c.token = authResp.Token
	c.tokenExpiry = time.Unix(int64(authResp.Expire), 0)

	logger.Info("Salt API authentication successful",
		zap.String("user", authResp.User),
		zap.String("eauth", authResp.Eauth),
		zap.Time("expires", c.tokenExpiry))

	return &authResp, nil
}

// Logout invalidates the current session
func (c *HTTPSaltClient) Logout(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	if c.token == "" {
		return nil
	}

	_, err := c.makeRequest(ctx, "POST", "/logout", nil, true)
	if err != nil {
		logger.Warn("Logout request failed", zap.Error(err))
	}

	c.token = ""
	c.tokenExpiry = time.Time{}

	logger.Info("Salt API logout completed")
	return nil
}

// RefreshToken refreshes the authentication token
func (c *HTTPSaltClient) RefreshToken(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	if time.Until(c.tokenExpiry) > c.config.TokenRefreshTime {
		return nil // Token still valid
	}

	logger.Info("Refreshing Salt API token")
	_, err := c.Login(ctx, nil)
	return err
}

// ValidateConnection tests the connection to Salt API
func (c *HTTPSaltClient) ValidateConnection(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Try to get Salt status
	status, err := c.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("connection validation failed: %w", err)
	}

	logger.Info("Salt API connection validated",
		zap.String("version", status.Version),
		zap.Int("minions_up", status.MinionsUp))

	return nil
}

// RunCommand executes a Salt command
func (c *HTTPSaltClient) RunCommand(ctx context.Context, req *CommandRequest) (*CommandResponse, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing Salt command",
		zap.String("client", req.Client),
		zap.String("target", req.Target),
		zap.String("function", req.Function))

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("command execution failed: %w", err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse command response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	logger.Info("Salt command completed",
		zap.String("job_id", cmdResp.JobID))

	return &cmdResp, nil
}

// RunState executes a Salt state
func (c *HTTPSaltClient) RunState(ctx context.Context, req *StateRequest) (*StateResponse, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing Salt state",
		zap.String("target", req.Target),
		zap.String("function", req.Function),
		zap.Bool("test", req.Test))

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("state execution failed: %w", err)
	}

	var stateResp StateResponse
	if err := json.Unmarshal(response, &stateResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse state response: %v", err),
			Type:    ErrStateError,
		}
	}

	logger.Info("Salt state completed",
		zap.String("job_id", stateResp.JobID))

	return &stateResp, nil
}

// RunOrchestrate executes Salt orchestration
func (c *HTTPSaltClient) RunOrchestrate(ctx context.Context, req *OrchestrationRequest) (*OrchestrationResponse, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing Salt orchestration",
		zap.String("function", req.Function),
		zap.Strings("mods", req.Mods))

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("orchestration execution failed: %w", err)
	}

	var orchResp OrchestrationResponse
	if err := json.Unmarshal(response, &orchResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse orchestration response: %v", err),
			Type:    ErrOrchestrationError,
		}
	}

	logger.Info("Salt orchestration completed",
		zap.String("job_id", orchResp.JobID))

	return &orchResp, nil
}

// GetJob retrieves job information
func (c *HTTPSaltClient) GetJob(ctx context.Context, jobID string) (*JobResult, error) {
	logger := otelzap.Ctx(ctx)

	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "jobs.lookup_jid",
		Args:     []string{jobID},
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get job %s: %w", jobID, err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse job response: %v", err),
			Type:    ErrJobNotFound,
		}
	}

	if len(cmdResp.Return) == 0 {
		return nil, &SaltError{
			Code:    404,
			Message: fmt.Sprintf("job %s not found", jobID),
			Type:    ErrJobNotFound,
		}
	}

	jobData := cmdResp.Return[0]
	jobBytes, _ := json.Marshal(jobData)

	var job JobResult
	if err := json.Unmarshal(jobBytes, &job); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse job data: %v", err),
			Type:    ErrJobNotFound,
		}
	}

	logger.Info("Retrieved Salt job",
		zap.String("job_id", jobID),
		zap.String("function", job.Function))

	return &job, nil
}

// ListJobs retrieves job list
func (c *HTTPSaltClient) ListJobs(ctx context.Context, opts *JobListOptions) (*JobList, error) {
	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "jobs.list_jobs",
	}

	if opts != nil {
		if opts.SearchFunction != "" {
			req.Kwargs = make(map[string]interface{})
			req.Kwargs["search_function"] = opts.SearchFunction
		}
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse jobs response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	jobList := &JobList{Jobs: []JobResult{}}

	if len(cmdResp.Return) > 0 {
		jobsData := cmdResp.Return[0]
		for _, jobData := range jobsData {
			jobBytes, _ := json.Marshal(jobData)
			var job JobResult
			if err := json.Unmarshal(jobBytes, &job); err == nil {
				jobList.Jobs = append(jobList.Jobs, job)
			}
		}
	}

	return jobList, nil
}

// KillJob terminates a running job
func (c *HTTPSaltClient) KillJob(ctx context.Context, jobID string) error {
	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "jobs.kill",
		Args:     []string{jobID},
	}

	_, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return fmt.Errorf("failed to kill job %s: %w", jobID, err)
	}

	return nil
}

// ListMinions retrieves minion list
func (c *HTTPSaltClient) ListMinions(ctx context.Context, opts *MinionListOptions) (*MinionList, error) {
	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "manage.status",
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to list minions: %w", err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse minions response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	minionList := &MinionList{Minions: []MinionInfo{}}

	if len(cmdResp.Return) > 0 {
		statusData := cmdResp.Return[0]
		if upMinions, ok := statusData["up"].([]interface{}); ok {
			for _, minionID := range upMinions {
				if id, ok := minionID.(string); ok {
					minionList.Minions = append(minionList.Minions, MinionInfo{
						ID:     id,
						Status: "up",
					})
				}
			}
		}
		if downMinions, ok := statusData["down"].([]interface{}); ok {
			for _, minionID := range downMinions {
				if id, ok := minionID.(string); ok {
					minionList.Minions = append(minionList.Minions, MinionInfo{
						ID:     id,
						Status: "down",
					})
				}
			}
		}
	}

	return minionList, nil
}

// GetMinionInfo retrieves detailed minion information
func (c *HTTPSaltClient) GetMinionInfo(ctx context.Context, minionID string) (*MinionInfo, error) {
	req := &CommandRequest{
		Client:   ClientTypeLocal,
		Target:   minionID,
		Function: FunctionGrains,
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get minion info for %s: %w", minionID, err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse minion info response: %v", err),
			Type:    ErrMinionNotFound,
		}
	}

	if len(cmdResp.Return) == 0 {
		return nil, &SaltError{
			Code:    404,
			Message: fmt.Sprintf("minion %s not found", minionID),
			Type:    ErrMinionNotFound,
		}
	}

	minionData := cmdResp.Return[0]
	if grains, ok := minionData[minionID].(map[string]interface{}); ok {
		minion := &MinionInfo{
			ID:     minionID,
			Status: "up",
			Grains: grains,
		}

		if os, ok := grains["os"].(string); ok {
			minion.OS = os
		}
		if osVersion, ok := grains["osrelease"].(string); ok {
			minion.OSVersion = osVersion
		}
		if ips, ok := grains["ipv4"].([]interface{}); ok && len(ips) > 0 {
			if ip, ok := ips[0].(string); ok {
				minion.IPAddress = ip
			}
		}

		return minion, nil
	}

	return nil, &SaltError{
		Code:    404,
		Message: fmt.Sprintf("minion %s not found", minionID),
		Type:    ErrMinionNotFound,
	}
}

// Ping tests minion connectivity
func (c *HTTPSaltClient) Ping(ctx context.Context, minionID string) (*PingResponse, error) {
	req := &CommandRequest{
		Client:   ClientTypeLocal,
		Target:   minionID,
		Function: FunctionTest,
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to ping minion %s: %w", minionID, err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse ping response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	pingResp := &PingResponse{
		MinionID: minionID,
		Success:  false,
		Time:     time.Now().Format(time.RFC3339),
	}

	if len(cmdResp.Return) > 0 {
		if result, ok := cmdResp.Return[0][minionID]; ok && result == true {
			pingResp.Success = true
		}
	}

	return pingResp, nil
}

// GetStatus retrieves Salt master status
func (c *HTTPSaltClient) GetStatus(ctx context.Context) (*SaltStatus, error) {
	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "manage.status",
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get Salt status: %w", err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse status response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	status := &SaltStatus{
		Version: "unknown",
	}

	if len(cmdResp.Return) > 0 {
		statusData := cmdResp.Return[0]
		if upMinions, ok := statusData["up"].([]interface{}); ok {
			status.MinionsUp = len(upMinions)
		}
		if downMinions, ok := statusData["down"].([]interface{}); ok {
			status.MinionsDown = len(downMinions)
		}
	}

	return status, nil
}

// makeRequest handles HTTP requests to Salt API
func (c *HTTPSaltClient) makeRequest(ctx context.Context, method, path string, data interface{}, requireAuth bool) ([]byte, error) {
	logger := otelzap.Ctx(ctx)

	if requireAuth && c.token == "" {
		if _, err := c.Login(ctx, nil); err != nil {
			return nil, fmt.Errorf("authentication required: %w", err)
		}
	}

	// Refresh token if needed
	if requireAuth {
		if err := c.RefreshToken(ctx); err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
	}

	// Prepare URL
	baseURL, err := url.Parse(c.config.BaseURL)
	if err != nil {
		return nil, &SaltError{
			Code:    400,
			Message: fmt.Sprintf("invalid base URL: %v", err),
			Type:    ErrInvalidRequest,
		}
	}

	fullURL := baseURL.ResolveReference(&url.URL{Path: path})

	// Prepare request body
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, &SaltError{
				Code:    400,
				Message: fmt.Sprintf("failed to marshal request data: %v", err),
				Type:    ErrInvalidRequest,
			}
		}
		body = bytes.NewReader(jsonData)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, method, fullURL.String(), body)
	if err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to create HTTP request: %v", err),
			Type:    ErrConnectionFailed,
		}
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if requireAuth && c.token != "" {
		req.Header.Set("X-Auth-Token", c.token)
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.config.TLSSkipVerify,
		},
	}

	httpClient := &http.Client{
		Timeout:   c.config.Timeout,
		Transport: transport,
	}

	// Execute request with retries
	var resp *http.Response
	var lastErr error

	for retry := 0; retry <= c.config.MaxRetries; retry++ {
		if retry > 0 {
			logger.Warn("Retrying Salt API request",
				zap.Int("retry", retry),
				zap.String("method", method),
				zap.String("path", path))

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.config.RetryDelay):
			}
		}

		resp, lastErr = httpClient.Do(req)
		if lastErr == nil {
			break
		}
	}

	if lastErr != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("HTTP request failed after %d retries: %v", c.config.MaxRetries, lastErr),
			Type:    ErrConnectionFailed,
		}
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to read response body: %v", err),
			Type:    ErrConnectionFailed,
		}
	}

	// Check HTTP status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var saltErr SaltError
		if err := json.Unmarshal(responseBody, &saltErr); err == nil {
			return nil, &saltErr
		}

		return nil, &SaltError{
			Code:    resp.StatusCode,
			Message: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(responseBody)),
			Type:    ErrConnectionFailed,
		}
	}

	logger.Debug("Salt API request completed",
		zap.String("method", method),
		zap.String("path", path),
		zap.Int("status", resp.StatusCode),
		zap.Int("response_size", len(responseBody)))

	return responseBody, nil
}

// AcceptKey accepts a minion key
func (c *HTTPSaltClient) AcceptKey(ctx context.Context, minionID string) error {
	req := &CommandRequest{
		Client:   ClientTypeWheel,
		Function: "key.accept",
		Args:     []string{minionID},
	}

	_, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return fmt.Errorf("failed to accept key for minion %s: %w", minionID, err)
	}

	return nil
}

// RejectKey rejects a minion key
func (c *HTTPSaltClient) RejectKey(ctx context.Context, minionID string) error {
	req := &CommandRequest{
		Client:   ClientTypeWheel,
		Function: "key.reject",
		Args:     []string{minionID},
	}

	_, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return fmt.Errorf("failed to reject key for minion %s: %w", minionID, err)
	}

	return nil
}

// DeleteKey deletes a minion key
func (c *HTTPSaltClient) DeleteKey(ctx context.Context, minionID string) error {
	req := &CommandRequest{
		Client:   ClientTypeWheel,
		Function: "key.delete",
		Args:     []string{minionID},
	}

	_, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return fmt.Errorf("failed to delete key for minion %s: %w", minionID, err)
	}

	return nil
}

// GetPillar retrieves pillar data for a minion
func (c *HTTPSaltClient) GetPillar(ctx context.Context, minionID string, key string) (*PillarData, error) {
	req := &CommandRequest{
		Client:   ClientTypeLocal,
		Target:   minionID,
		Function: FunctionPillar,
	}

	if key != "" {
		req.Args = []string{key}
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get pillar for minion %s: %w", minionID, err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse pillar response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	pillarData := &PillarData{
		MinionID: minionID,
		Data:     make(map[string]interface{}),
	}

	if len(cmdResp.Return) > 0 {
		if data, ok := cmdResp.Return[0][minionID].(map[string]interface{}); ok {
			pillarData.Data = data
		}
	}

	return pillarData, nil
}

// SetPillar sets pillar data for a minion
func (c *HTTPSaltClient) SetPillar(ctx context.Context, minionID string, key string, data interface{}) error {
	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "pillar.set",
		Args:     []string{minionID, key},
		Kwargs:   map[string]interface{}{"val": data},
	}

	_, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return fmt.Errorf("failed to set pillar for minion %s: %w", minionID, err)
	}

	return nil
}

// RefreshPillar refreshes pillar data for a minion
func (c *HTTPSaltClient) RefreshPillar(ctx context.Context, minionID string) error {
	req := &CommandRequest{
		Client:   ClientTypeLocal,
		Target:   minionID,
		Function: "saltutil.refresh_pillar",
	}

	_, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return fmt.Errorf("failed to refresh pillar for minion %s: %w", minionID, err)
	}

	return nil
}

// GetState retrieves state information
func (c *HTTPSaltClient) GetState(ctx context.Context, req *StateInfoRequest) (*StateInfo, error) {
	cmdReq := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "state.show_sls",
		Args:     []string{req.State},
	}

	if req.MinionID != "" {
		cmdReq.Target = req.MinionID
		cmdReq.Client = ClientTypeLocal
	}

	response, err := c.makeRequest(ctx, "POST", "/", cmdReq, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get state info: %w", err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse state info response: %v", err),
			Type:    ErrStateError,
		}
	}

	stateInfo := &StateInfo{
		Name:        req.State,
		Description: fmt.Sprintf("State information for %s", req.State),
		Functions:   []string{},
	}

	return stateInfo, nil
}

// TestState tests state execution without applying changes
func (c *HTTPSaltClient) TestState(ctx context.Context, req *StateRequest) (*StateResponse, error) {
	req.Test = true
	return c.RunState(ctx, req)
}

// ApplyHighstate applies the highstate to a minion
func (c *HTTPSaltClient) ApplyHighstate(ctx context.Context, minionID string) (*StateResponse, error) {
	req := &StateRequest{
		Client:   ClientTypeLocal,
		Target:   minionID,
		Function: FunctionHighstate,
	}

	return c.RunState(ctx, req)
}

// ListFiles lists files in Salt file server
func (c *HTTPSaltClient) ListFiles(ctx context.Context, path string, env string) (*FileList, error) {
	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "fileserver.file_list",
	}

	if env != "" {
		req.Kwargs = map[string]interface{}{"saltenv": env}
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse file list response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	fileList := &FileList{Files: []FileInfo{}}

	if len(cmdResp.Return) > 0 {
		returnData := cmdResp.Return[0]
		if files, ok := returnData["files"].([]interface{}); ok {
			for _, file := range files {
				if filePath, ok := file.(string); ok {
					if strings.HasPrefix(filePath, path) {
						fileList.Files = append(fileList.Files, FileInfo{
							Path:  filePath,
							IsDir: false,
						})
					}
				}
			}
		}
	}

	return fileList, nil
}

// GetFile retrieves file content from Salt file server
func (c *HTTPSaltClient) GetFile(ctx context.Context, path string, env string) (*FileContent, error) {
	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "cp.get_file_str",
		Args:     []string{path},
	}

	if env != "" {
		req.Kwargs = map[string]interface{}{"saltenv": env}
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get file content: %w", err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse file content response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	fileContent := &FileContent{
		Path: path,
	}

	if len(cmdResp.Return) > 0 {
		returnData := cmdResp.Return[0]
		if content, ok := returnData["content"].(string); ok {
			fileContent.Content = []byte(content)
			fileContent.Size = int64(len(content))
		}
	}

	return fileContent, nil
}

// WriteFile writes content to Salt file server
func (c *HTTPSaltClient) WriteFile(ctx context.Context, path string, env string, content []byte) error {
	req := &CommandRequest{
		Client:   ClientTypeRunner,
		Function: "cp.put_file",
		Args:     []string{string(content), path},
	}

	if env != "" {
		req.Kwargs = map[string]interface{}{"saltenv": env}
	}

	_, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// GetGrains retrieves grains data for a minion
func (c *HTTPSaltClient) GetGrains(ctx context.Context, minionID string) (*GrainsData, error) {
	req := &CommandRequest{
		Client:   ClientTypeLocal,
		Target:   minionID,
		Function: FunctionGrains,
	}

	response, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get grains for minion %s: %w", minionID, err)
	}

	var cmdResp CommandResponse
	if err := json.Unmarshal(response, &cmdResp); err != nil {
		return nil, &SaltError{
			Code:    500,
			Message: fmt.Sprintf("failed to parse grains response: %v", err),
			Type:    ErrCommandFailed,
		}
	}

	grainsData := &GrainsData{
		MinionID: minionID,
		Grains:   make(map[string]interface{}),
	}

	if len(cmdResp.Return) > 0 {
		if data, ok := cmdResp.Return[0][minionID].(map[string]interface{}); ok {
			grainsData.Grains = data
		}
	}

	return grainsData, nil
}

// SetGrain sets a grain value for a minion
func (c *HTTPSaltClient) SetGrain(ctx context.Context, minionID string, key string, value interface{}) error {
	req := &CommandRequest{
		Client:   ClientTypeLocal,
		Target:   minionID,
		Function: "grains.setval",
		Args:     []string{key},
		Kwargs:   map[string]interface{}{"val": value},
	}

	_, err := c.makeRequest(ctx, "POST", "/", req, true)
	if err != nil {
		return fmt.Errorf("failed to set grain for minion %s: %w", minionID, err)
	}

	return nil
}

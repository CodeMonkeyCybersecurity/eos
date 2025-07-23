package salt

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
)

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrTokenExpired         = errors.New("token expired")
	ErrNoResults            = errors.New("no results returned")
	ErrStateExecutionFailed = errors.New("state execution failed")
)

// Client represents a Salt API client
type Client struct {
	baseURL    string
	username   string
	password   string
	eauth      string

	httpClient *retryablehttp.Client
	logger     *zap.Logger

	// Token management
	mu          sync.RWMutex
	token       string
	tokenExpiry time.Time

	// Configuration
	config ClientConfig
}

// ClientConfig holds client configuration
type ClientConfig struct {
	BaseURL            string
	Username           string
	Password           string
	EAuth              string
	Timeout            time.Duration
	MaxRetries         int
	InsecureSkipVerify bool
	Logger             *zap.Logger
}

// NewClient creates a new Salt API client
func NewClient(config ClientConfig) (*Client, error) {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	if config.Timeout == 0 {
		config.Timeout = 5 * time.Minute
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	if config.EAuth == "" {
		config.EAuth = "pam"
	}

	// Create retryable HTTP client
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = config.MaxRetries
	retryClient.Logger = nil // We'll use our own logger

	// Configure transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	retryClient.HTTPClient = &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	client := &Client{
		baseURL:    strings.TrimRight(config.BaseURL, "/"),
		username:   config.Username,
		password:   config.Password,
		eauth:      config.EAuth,
		httpClient: retryClient,
		logger:     config.Logger,
		config:     config,
	}

	// Initial authentication
	if err := client.authenticate(context.Background()); err != nil {
		return nil, fmt.Errorf("initial authentication failed: %w", err)
	}

	return client, nil
}

// authenticate gets a new token from Salt API
func (c *Client) authenticate(ctx context.Context) error {
	c.logger.Debug("authenticating with Salt API",
		zap.String("username", c.username),
		zap.String("eauth", c.eauth))

	data := url.Values{
		"username": {c.username},
		"password": {c.password},
		"eauth":    {c.eauth},
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST",
		c.baseURL+"/login", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: status=%d body=%s", ErrAuthenticationFailed, resp.StatusCode, body)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(authResp.Return) == 0 || authResp.Return[0].Token == "" {
		return ErrAuthenticationFailed
	}

	// Update token with mutex
	c.mu.Lock()
	c.token = authResp.Return[0].Token
	// Calculate expiry (usually 12 hours, but we'll refresh after 11)
	c.tokenExpiry = time.Now().Add(11 * time.Hour)
	c.mu.Unlock()

	c.logger.Info("successfully authenticated with Salt API",
		zap.String("user", authResp.Return[0].User))

	return nil
}

// ensureAuthenticated checks token validity and refreshes if needed
func (c *Client) ensureAuthenticated(ctx context.Context) error {
	c.mu.RLock()
	needsRefresh := time.Now().After(c.tokenExpiry) || c.token == ""
	c.mu.RUnlock()

	if needsRefresh {
		return c.authenticate(ctx)
	}

	return nil
}

// ExecuteCommand runs a Salt command synchronously
func (c *Client) ExecuteCommand(ctx context.Context, cmd Command) (*CommandResult, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, err
	}

	c.logger.Debug("executing command",
		zap.String("client", cmd.Client),
		zap.String("target", cmd.Target),
		zap.String("function", cmd.Function))

	// Build request data
	data := url.Values{
		"client": {cmd.Client},
		"tgt":    {cmd.Target},
		"fun":    {cmd.Function},
	}

	// Add arguments
	for _, arg := range cmd.Args {
		data.Add("arg", arg)
	}

	// Add keyword arguments
	for k, v := range cmd.Kwargs {
		data.Add("kwarg", fmt.Sprintf("%s=%v", k, v))
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST",
		c.baseURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	c.mu.RLock()
	req.Header.Set("X-Auth-Token", c.token)
	c.mu.RUnlock()

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Token might have expired, try once more
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
		return c.ExecuteCommand(ctx, cmd)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("command failed: status=%d body=%s", resp.StatusCode, body)
	}

	// Parse response
	var result CommandResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Return) == 0 {
		return nil, ErrNoResults
	}

	return &CommandResult{
		Raw:    result.Return[0],
		client: c,
	}, nil
}

// ExecuteStateApply runs state.apply with progress streaming
func (c *Client) ExecuteStateApply(ctx context.Context, state string, pillar map[string]interface{},
	progress func(StateProgress)) (*StateResult, error) {

	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, err
	}

	c.logger.Info("applying state",
		zap.String("state", state))

	// First, start the job asynchronously
	jobID, err := c.startStateJob(ctx, state, pillar)
	if err != nil {
		return nil, err
	}

	c.logger.Debug("state job started",
		zap.String("job_id", jobID))

	// Stream job events
	return c.streamJobProgress(ctx, jobID, progress)
}

// startStateJob starts an async state.apply job
func (c *Client) startStateJob(ctx context.Context, state string, pillar map[string]interface{}) (string, error) {
	pillarJSON, err := json.Marshal(pillar)
	if err != nil {
		return "", fmt.Errorf("failed to marshal pillar: %w", err)
	}

	data := url.Values{
		"client": {"local_async"},
		"tgt":    {"*"},
		"fun":    {"state.apply"},
		"arg":    {state},
		"kwarg":  {fmt.Sprintf("pillar=%s", pillarJSON)},
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, "POST",
		c.baseURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	c.mu.RLock()
	req.Header.Set("X-Auth-Token", c.token)
	c.mu.RUnlock()

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Return []struct {
			JID     string   `json:"jid"`
			Minions []string `json:"minions"`
		} `json:"return"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Return) == 0 || result.Return[0].JID == "" {
		return "", errors.New("no job ID returned")
	}

	return result.Return[0].JID, nil
}

// streamJobProgress monitors job progress via events
func (c *Client) streamJobProgress(ctx context.Context, jobID string,
	progress func(StateProgress)) (*StateResult, error) {

	// Use the events endpoint to stream progress
	eventURL := fmt.Sprintf("%s/events", c.baseURL)

	req, err := retryablehttp.NewRequestWithContext(ctx, "GET", eventURL, nil)
	if err != nil {
		return nil, err
	}

	c.mu.RLock()
	req.Header.Set("X-Auth-Token", c.token)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Create scanner for server-sent events
	scanner := bufio.NewScanner(resp.Body)
	result := &StateResult{
		States: make(map[string]StateExecutionResult),
	}

	timeout := time.NewTimer(c.config.Timeout)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.New("job timeout")
		default:
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return nil, err
				}
				break
			}

			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				var event EventData
				if err := json.Unmarshal([]byte(line[6:]), &event); err != nil {
					continue
				}

				// Process event based on tag
				if strings.Contains(event.Tag, jobID) {
					if err := c.processJobEvent(event, result, progress); err != nil {
						return nil, err
					}

					// Check if job is complete
					if result.Completed {
						return result, nil
					}
				}
			}
		}
	}

	return result, nil
}

// processJobEvent processes a job event and updates result
func (c *Client) processJobEvent(event EventData, result *StateResult,
	progress func(StateProgress)) error {

	// Parse event data based on tag
	if strings.Contains(event.Tag, "job/ret") {
		// Job return event
		var jobRet JobReturn
		// Convert event.Data to JSON bytes for unmarshaling
		dataBytes, err := json.Marshal(event.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal event data: %w", err)
		}
		if err := json.Unmarshal(dataBytes, &jobRet); err != nil {
			return err
		}

		// Update result
		for state, stateResult := range jobRet.Return {
			execResult := StateExecutionResult{
				ID:       state,
				Result:   stateResult.Result,
				Comment:  stateResult.Comment,
				Changes:  stateResult.Changes,
				Duration: stateResult.Duration,
			}

			result.States[state] = execResult

			if !stateResult.Result {
				result.Failed = true
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", state, stateResult.Comment))
			}

			// Send progress update
			if progress != nil {
				progress(StateProgress{
					State:     state,
					Completed: true,
					Success:   stateResult.Result,
					Message:   stateResult.Comment,
				})
			}
		}

		result.Completed = true
	} else if strings.Contains(event.Tag, "job/prog") {
		// Progress event
		if progress != nil {
			progress(StateProgress{
				State:     event.Data["state"].(string),
				Completed: false,
				Message:   event.Data["message"].(string),
			})
		}
	}

	return nil
}

// CheckStatus performs a simple ping to verify connectivity
func (c *Client) CheckStatus(ctx context.Context) error {
	cmd := Command{
		Client:   "local",
		Target:   "*",
		Function: "test.ping",
	}

	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		return err
	}

	// Check if any minion responded
	for _, v := range result.Raw {
		if v == true {
			return nil
		}
	}

	return errors.New("no minions responded to ping")
}
package unified

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// ExecuteCommand executes a Salt command using the appropriate method (API or local)
func (c *Client) ExecuteCommand(ctx context.Context, cmd Command) (*CommandResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if !c.initialized {
		return nil, fmt.Errorf("client not initialized")
	}
	
	c.stats.CommandsExecuted++
	c.stats.LastActivity = time.Now()
	
	logger := c.logger.With(
		zap.String("method", "ExecuteCommand"),
		zap.String("mode", c.currentMode.String()),
		zap.String("function", cmd.Function))
	
	logger.Debug("Executing Salt command")
	
	switch c.currentMode {
	case ModeAPI:
		return c.executeCommandAPI(ctx, cmd)
	case ModeLocal:
		return c.executeCommandLocal(ctx, cmd)
	default:
		return nil, &SaltError{
			Type:    ErrorTypeUnavailable,
			Message: "Salt is not available",
			Mode:    c.currentMode,
		}
	}
}

// ExecuteCommandWithRetry executes a command with retry logic
func (c *Client) ExecuteCommandWithRetry(ctx context.Context, cmd Command, maxRetries int) (*CommandResult, error) {
	var lastErr error
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		result, err := c.ExecuteCommand(ctx, cmd)
		if err == nil {
			return result, nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if saltErr, ok := err.(*SaltError); ok && !saltErr.Retryable {
			break
		}
		
		// Don't retry on the last attempt
		if attempt < maxRetries {
			c.logger.Warn("Command failed, retrying",
				zap.Error(err),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", maxRetries))
			
			// Wait before retrying
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(DefaultRetryDelay):
			}
		}
	}
	
	return nil, fmt.Errorf("command failed after %d retries: %w", maxRetries, lastErr)
}

// ExecuteState executes a Salt state using the appropriate method
func (c *Client) ExecuteState(ctx context.Context, state StateCommand) (*StateResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if !c.initialized {
		return nil, fmt.Errorf("client not initialized")
	}
	
	c.stats.StatesApplied++
	c.stats.LastActivity = time.Now()
	
	logger := c.logger.With(
		zap.String("method", "ExecuteState"),
		zap.String("mode", c.currentMode.String()),
		zap.String("state", state.State))
	
	logger.Debug("Executing Salt state")
	
	switch c.currentMode {
	case ModeAPI:
		return c.executeStateAPI(ctx, state)
	case ModeLocal:
		return c.executeStateLocal(ctx, state)
	default:
		return nil, &SaltError{
			Type:    ErrorTypeUnavailable,
			Message: "Salt is not available",
			Mode:    c.currentMode,
		}
	}
}

// ExecuteStateWithRetry executes a state with retry logic
func (c *Client) ExecuteStateWithRetry(ctx context.Context, state StateCommand, maxRetries int) (*StateResult, error) {
	var lastErr error
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		result, err := c.ExecuteState(ctx, state)
		if err == nil {
			return result, nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if saltErr, ok := err.(*SaltError); ok && !saltErr.Retryable {
			break
		}
		
		// Don't retry on the last attempt
		if attempt < maxRetries {
			c.logger.Warn("State execution failed, retrying",
				zap.Error(err),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", maxRetries))
			
			// Wait before retrying
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(DefaultRetryDelay):
			}
		}
	}
	
	return nil, fmt.Errorf("state execution failed after %d retries: %w", maxRetries, lastErr)
}

// TestState executes a state in test mode
func (c *Client) TestState(ctx context.Context, state StateCommand) (*StateResult, error) {
	// Create a copy with test mode enabled
	testState := state
	testState.Test = true
	
	return c.ExecuteState(ctx, testState)
}

// executeCommandAPI executes a command using Salt API
func (c *Client) executeCommandAPI(ctx context.Context, cmd Command) (*CommandResult, error) {
	if c.apiClient == nil {
		return nil, &SaltError{
			Type:    ErrorTypeConfig,
			Message: "API client not initialized",
			Mode:    ModeAPI,
		}
	}
	
	// Ensure we're authenticated
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	
	startTime := time.Now()
	result, err := c.apiClient.Execute(ctx, c.authInfo.Token, cmd)
	if err != nil {
		return nil, &SaltError{
			Type:      ErrorTypeCommand,
			Message:   fmt.Sprintf("API command execution failed: %s", err.Error()),
			Cause:     err,
			Mode:      ModeAPI,
			Retryable: c.isRetryableError(err),
		}
	}
	
	result.Mode = ModeAPI
	result.Duration = time.Since(startTime)
	c.stats.APIRequests++
	
	return result, nil
}

// executeCommandLocal executes a command using salt-call
func (c *Client) executeCommandLocal(ctx context.Context, cmd Command) (*CommandResult, error) {
	startTime := time.Now()
	
	// Build salt-call arguments
	args := []string{"--local"}
	
	// Add function and arguments
	args = append(args, cmd.Function)
	for _, arg := range cmd.Args {
		args = append(args, fmt.Sprintf("%v", arg))
	}
	
	// Add keyword arguments
	for key, value := range cmd.Kwargs {
		args = append(args, fmt.Sprintf("%s=%v", key, value))
	}
	
	// Add output format for easier parsing
	args = append(args, "--output=json")
	
	// Execute command
	output, err := execute.Run(ctx, execute.Options{
		Command: SaltCallBinaryName,
		Args:    args,
		Capture: true,
		Timeout: cmd.Timeout,
	})
	
	duration := time.Since(startTime)
	c.stats.LocalCalls++
	
	if err != nil {
		return &CommandResult{
			Success:  false,
			Mode:     ModeLocal,
			Duration: duration,
			Output:   output,
			Errors:   []string{err.Error()},
		}, &SaltError{
			Type:      ErrorTypeCommand,
			Message:   fmt.Sprintf("salt-call execution failed: %s", err.Error()),
			Cause:     err,
			Mode:      ModeLocal,
			Retryable: c.isRetryableError(err),
		}
	}
	
	// Parse result
	result := &CommandResult{
		Success:  true,
		Mode:     ModeLocal,
		Duration: duration,
		Output:   output,
		Raw:      make(map[string]interface{}),
	}
	
	// Try to parse JSON output
	if strings.TrimSpace(output) != "" {
		if err := json.Unmarshal([]byte(output), &result.Raw); err != nil {
			c.logger.Debug("Failed to parse command output as JSON", zap.Error(err))
			// Not a critical error, just use the raw output
		}
	}
	
	return result, nil
}

// executeStateAPI executes a state using Salt API
func (c *Client) executeStateAPI(ctx context.Context, state StateCommand) (*StateResult, error) {
	if c.apiClient == nil {
		return nil, &SaltError{
			Type:    ErrorTypeConfig,
			Message: "API client not initialized",
			Mode:    ModeAPI,
		}
	}
	
	// Ensure we're authenticated
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	
	startTime := time.Now()
	result, err := c.apiClient.ExecuteState(ctx, c.authInfo.Token, state)
	if err != nil {
		return nil, &SaltError{
			Type:      ErrorTypeState,
			Message:   fmt.Sprintf("API state execution failed: %s", err.Error()),
			Cause:     err,
			Mode:      ModeAPI,
			Retryable: c.isRetryableError(err),
		}
	}
	
	result.Mode = ModeAPI
	result.Duration = time.Since(startTime)
	c.stats.APIRequests++
	
	return result, nil
}

// executeStateLocal executes a state using salt-call
func (c *Client) executeStateLocal(ctx context.Context, state StateCommand) (*StateResult, error) {
	startTime := time.Now()
	
	// Build salt-call arguments
	args := []string{"--local", "state.apply", state.State}
	
	// Add pillar data if provided
	if len(state.Pillar) > 0 {
		pillarJSON, err := json.Marshal(state.Pillar)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal pillar data: %w", err)
		}
		args = append(args, fmt.Sprintf("pillar=%s", string(pillarJSON)))
	}
	
	// Add test mode if requested
	if state.Test {
		args = append(args, "test=True")
	}
	
	// Add output format for easier parsing
	args = append(args, "--output=json")
	
	// Set up progress callback if provided
	var progressCallback func(StateProgress)
	if state.ProgressCallback != nil {
		progressCallback = state.ProgressCallback
	}
	
	// Execute command
	output, err := execute.Run(ctx, execute.Options{
		Command: SaltCallBinaryName,
		Args:    args,
		Capture: true,
		Timeout: state.Timeout,
	})
	
	duration := time.Since(startTime)
	c.stats.LocalCalls++
	
	// Create basic result
	result := &StateResult{
		Mode:     ModeLocal,
		Duration: duration,
		Output:   output,
		States:   make(map[string]StateInfo),
		Summary:  StateSummary{},
	}
	
	if err != nil {
		result.Success = false
		result.Errors = []string{err.Error()}
		
		// Call progress callback with error
		if progressCallback != nil {
			progressCallback(StateProgress{
				State:     state.State,
				Message:   fmt.Sprintf("State execution failed: %s", err.Error()),
				Success:   false,
				Completed: true,
				Duration:  duration,
			})
		}
		
		return result, &SaltError{
			Type:      ErrorTypeState,
			Message:   fmt.Sprintf("salt-call state execution failed: %s", err.Error()),
			Cause:     err,
			Mode:      ModeLocal,
			Retryable: c.isRetryableError(err),
		}
	}
	
	// Parse state result
	if err := c.parseStateResult(output, result); err != nil {
		c.logger.Warn("Failed to parse state result", zap.Error(err))
		// Continue with basic success result
	}
	
	result.Success = true
	
	// Call progress callback with success
	if progressCallback != nil {
		progressCallback(StateProgress{
			State:     state.State,
			Message:   "State execution completed successfully",
			Success:   true,
			Completed: true,
			Duration:  duration,
		})
	}
	
	return result, nil
}

// parseStateResult parses salt-call state output into structured result
func (c *Client) parseStateResult(output string, result *StateResult) error {
	if strings.TrimSpace(output) == "" {
		return fmt.Errorf("empty output")
	}
	
	// Try to parse as JSON
	var rawResult map[string]interface{}
	if err := json.Unmarshal([]byte(output), &rawResult); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	
	// Extract state information
	for stateName, stateData := range rawResult {
		if stateMap, ok := stateData.(map[string]interface{}); ok {
			stateInfo := StateInfo{
				Name: stateName,
			}
			
			if resultVal, exists := stateMap["result"]; exists {
				if resultBool, ok := resultVal.(bool); ok {
					stateInfo.Result = resultBool
					if resultBool {
						result.Summary.Succeeded++
					} else {
						result.Summary.Failed++
					}
				}
			}
			
			if changesVal, exists := stateMap["changes"]; exists {
				if changesMap, ok := changesVal.(map[string]interface{}); ok {
					stateInfo.Changes = changesMap
					if len(changesMap) > 0 {
						result.Summary.Changed++
					} else {
						result.Summary.Unchanged++
					}
				}
			}
			
			if commentVal, exists := stateMap["comment"]; exists {
				if commentStr, ok := commentVal.(string); ok {
					stateInfo.Comment = commentStr
				}
			}
			
			result.States[stateName] = stateInfo
			result.Summary.Total++
		}
	}
	
	return nil
}

// isRetryableError determines if an error is retryable
func (c *Client) isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	errStr := strings.ToLower(err.Error())
	
	// Network errors are usually retryable
	retryablePatterns := []string{
		"connection refused",
		"timeout",
		"network",
		"temporary failure",
		"service unavailable",
	}
	
	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	
	return false
}

// ensureAuthenticated ensures the client is authenticated for API calls
func (c *Client) ensureAuthenticated(ctx context.Context) error {
	if c.authInfo.Authenticated && time.Now().Before(c.authInfo.TokenExpiry) {
		return nil
	}
	
	return c.Authenticate(ctx)
}
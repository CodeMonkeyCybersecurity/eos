package unified

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Ping performs a Salt ping test to verify connectivity
func (c *Client) Ping(ctx context.Context, target string) (bool, error) {
	logger := c.logger.With(
		zap.String("method", "Ping"),
		zap.String("target", target))
	
	logger.Debug("Performing Salt ping")
	
	cmd := Command{
		Target:   target,
		Function: "test.ping",
		Timeout:  10 * time.Second,
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		logger.Debug("Ping failed", zap.Error(err))
		return false, err
	}
	
	if !result.Success {
		logger.Debug("Ping unsuccessful", zap.Strings("errors", result.Errors))
		return false, nil
	}
	
	// Check if output contains "True" (Salt ping response)
	success := strings.Contains(result.Output, "True") || 
		strings.Contains(result.Output, "true")
	
	logger.Debug("Ping completed",
		zap.Bool("success", success),
		zap.String("output", result.Output))
	
	return success, nil
}

// GetGrains retrieves grain values from the target
func (c *Client) GetGrains(ctx context.Context, target string, grains []string) (map[string]interface{}, error) {
	logger := c.logger.With(
		zap.String("method", "GetGrains"),
		zap.String("target", target),
		zap.Strings("grains", grains))
	
	logger.Debug("Getting grain values")
	
	// If no specific grains requested, get all
	var function string
	var args []interface{}
	
	if len(grains) == 0 {
		function = "grains.items"
	} else if len(grains) == 1 {
		function = "grains.get"
		args = []interface{}{grains[0]}
	} else {
		function = "grains.get"
		args = make([]interface{}, len(grains))
		for i, grain := range grains {
			args[i] = grain
		}
	}
	
	cmd := Command{
		Target:   target,
		Function: function,
		Args:     args,
		Timeout:  30 * time.Second,
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		logger.Error("Failed to get grains", zap.Error(err))
		return nil, err
	}
	
	if !result.Success {
		logger.Error("Grain retrieval unsuccessful", zap.Strings("errors", result.Errors))
		return nil, fmt.Errorf("grain retrieval failed: %v", result.Errors)
	}
	
	// Parse the result
	grainData := make(map[string]interface{})
	
	// Try to parse JSON if available
	if result.Raw != nil {
		grainData = result.Raw
	} else {
		// Try to parse output as JSON
		if err := json.Unmarshal([]byte(result.Output), &grainData); err != nil {
			logger.Debug("Failed to parse grain output as JSON", zap.Error(err))
			// Return simple string result
			grainData["result"] = result.Output
		}
	}
	
	logger.Debug("Grains retrieved successfully",
		zap.Int("grain_count", len(grainData)))
	
	return grainData, nil
}

// RunShellCommand executes a shell command on the target
func (c *Client) RunShellCommand(ctx context.Context, target string, command string) (string, error) {
	logger := c.logger.With(
		zap.String("method", "RunShellCommand"),
		zap.String("target", target),
		zap.String("command", command))
	
	logger.Debug("Running shell command")
	
	cmd := Command{
		Target:   target,
		Function: "cmd.run",
		Args:     []interface{}{command},
		Timeout:  5 * time.Minute, // Longer timeout for shell commands
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		logger.Error("Shell command failed", zap.Error(err))
		return "", err
	}
	
	if !result.Success {
		logger.Error("Shell command unsuccessful", zap.Strings("errors", result.Errors))
		return result.Output, fmt.Errorf("command failed: %v", result.Errors)
	}
	
	logger.Debug("Shell command completed successfully",
		zap.Int("output_length", len(result.Output)))
	
	return result.Output, nil
}

// ApplyState applies a Salt state with the given pillar data
func (c *Client) ApplyState(ctx context.Context, target string, state string, pillar map[string]interface{}) (*StateResult, error) {
	logger := c.logger.With(
		zap.String("method", "ApplyState"),
		zap.String("target", target),
		zap.String("state", state))
	
	logger.Debug("Applying Salt state")
	
	stateCmd := StateCommand{
		Target:  target,
		State:   state,
		Pillar:  pillar,
		Timeout: 10 * time.Minute, // Longer timeout for state application
	}
	
	result, err := c.ExecuteState(ctx, stateCmd)
	if err != nil {
		logger.Error("State application failed", zap.Error(err))
		return nil, err
	}
	
	logger.Info("State applied",
		zap.Bool("success", result.Success),
		zap.Int("total_states", result.Summary.Total),
		zap.Int("succeeded", result.Summary.Succeeded),
		zap.Int("failed", result.Summary.Failed),
		zap.Int("changed", result.Summary.Changed))
	
	return result, nil
}

// TestState applies a Salt state in test mode (dry run)
func (c *Client) TestStateApplication(ctx context.Context, target string, state string, pillar map[string]interface{}) (*StateResult, error) {
	logger := c.logger.With(
		zap.String("method", "TestStateApplication"),
		zap.String("target", target),
		zap.String("state", state))
	
	logger.Debug("Testing Salt state application")
	
	stateCmd := StateCommand{
		Target:  target,
		State:   state,
		Pillar:  pillar,
		Test:    true, // Enable test mode
		Timeout: 5 * time.Minute,
	}
	
	result, err := c.ExecuteState(ctx, stateCmd)
	if err != nil {
		logger.Error("State test failed", zap.Error(err))
		return nil, err
	}
	
	logger.Info("State test completed",
		zap.Bool("success", result.Success),
		zap.Int("total_states", result.Summary.Total))
	
	return result, nil
}

// GetJobStatus retrieves the status of an asynchronous job (API mode only)
func (c *Client) GetJobStatus(ctx context.Context, jobID string) (*CommandResult, error) {
	if c.currentMode != ModeAPI {
		return nil, &SaltError{
			Type:    ErrorTypeConfig,
			Message: "Job status checking only available in API mode",
			Mode:    c.currentMode,
		}
	}
	
	if c.apiClient == nil {
		return nil, &SaltError{
			Type:    ErrorTypeConfig,
			Message: "API client not initialized",
			Mode:    ModeAPI,
		}
	}
	
	logger := c.logger.With(
		zap.String("method", "GetJobStatus"),
		zap.String("job_id", jobID))
	
	logger.Debug("Getting job status")
	
	// Ensure we're authenticated
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	
	result, err := c.apiClient.GetJobStatus(ctx, c.authInfo.Token, jobID)
	if err != nil {
		logger.Error("Failed to get job status", zap.Error(err))
		return nil, &SaltError{
			Type:      ErrorTypeCommand,
			Message:   fmt.Sprintf("Failed to get job status: %s", err.Error()),
			Cause:     err,
			Mode:      ModeAPI,
			Retryable: c.isRetryableError(err),
		}
	}
	
	logger.Debug("Job status retrieved",
		zap.Bool("success", result.Success),
		zap.String("job_id", jobID))
	
	return result, nil
}

// WaitForJob waits for an asynchronous job to complete (API mode only)
func (c *Client) WaitForJob(ctx context.Context, jobID string, timeout time.Duration) (*CommandResult, error) {
	if c.currentMode != ModeAPI {
		return nil, &SaltError{
			Type:    ErrorTypeConfig,
			Message: "Job waiting only available in API mode",
			Mode:    c.currentMode,
		}
	}
	
	logger := c.logger.With(
		zap.String("method", "WaitForJob"),
		zap.String("job_id", jobID),
		zap.Duration("timeout", timeout))
	
	logger.Debug("Waiting for job completion")
	
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	// Poll for job completion
	pollInterval := 2 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			logger.Warn("Job wait timed out", zap.String("job_id", jobID))
			return nil, &SaltError{
				Type:    ErrorTypeTimeout,
				Message: fmt.Sprintf("Job %s did not complete within timeout", jobID),
				Mode:    ModeAPI,
			}
			
		case <-ticker.C:
			result, err := c.GetJobStatus(ctx, jobID)
			if err != nil {
				logger.Debug("Error checking job status", zap.Error(err))
				continue // Keep trying
			}
			
			// Check if job is complete (this depends on the actual API implementation)
			// For now, assume any successful result means completion
			if result.Success {
				logger.Info("Job completed successfully", zap.String("job_id", jobID))
				return result, nil
			}
			
			// If there are errors, the job likely failed
			if len(result.Errors) > 0 {
				logger.Warn("Job failed", 
					zap.String("job_id", jobID),
					zap.Strings("errors", result.Errors))
				return result, nil
			}
			
			logger.Debug("Job still running", zap.String("job_id", jobID))
		}
	}
}

// StreamEvents streams Salt events (API mode only)
func (c *Client) StreamEvents(ctx context.Context, eventTypes []string) (<-chan Event, error) {
	if c.currentMode != ModeAPI {
		return nil, &SaltError{
			Type:    ErrorTypeConfig,
			Message: "Event streaming only available in API mode",
			Mode:    c.currentMode,
		}
	}
	
	logger := c.logger.With(
		zap.String("method", "StreamEvents"),
		zap.Strings("event_types", eventTypes))
	
	logger.Debug("Starting event stream")
	
	// Create event channel
	eventChan := make(chan Event, 100) // Buffer events
	
	// This would need to be implemented with the actual API client
	// For now, return an empty channel that closes immediately
	go func() {
		defer close(eventChan)
		
		// TODO: Implement actual event streaming
		logger.Info("Event streaming not yet implemented")
	}()
	
	return eventChan, nil
}

// GetSystemInfo retrieves basic system information
func (c *Client) GetSystemInfo(ctx context.Context, target string) (map[string]interface{}, error) {
	logger := c.logger.With(
		zap.String("method", "GetSystemInfo"),
		zap.String("target", target))
	
	logger.Debug("Getting system information")
	
	// Get basic system grains
	systemGrains := []string{
		"os",
		"osrelease", 
		"kernel",
		"mem_total",
		"num_cpus",
		"fqdn",
		"ip_interfaces",
	}
	
	grains, err := c.GetGrains(ctx, target, systemGrains)
	if err != nil {
		return nil, err
	}
	
	logger.Debug("System information retrieved",
		zap.Int("info_items", len(grains)))
	
	return grains, nil
}

// CheckServiceStatus checks the status of a system service
func (c *Client) CheckServiceStatus(ctx context.Context, target string, serviceName string) (map[string]interface{}, error) {
	logger := c.logger.With(
		zap.String("method", "CheckServiceStatus"),
		zap.String("target", target),
		zap.String("service", serviceName))
	
	logger.Debug("Checking service status")
	
	cmd := Command{
		Target:   target,
		Function: "service.status",
		Args:     []interface{}{serviceName},
		Timeout:  30 * time.Second,
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}
	
	status := map[string]interface{}{
		"service":   serviceName,
		"running":   result.Success,
		"output":    result.Output,
		"mode":      result.Mode.String(),
		"duration":  result.Duration.String(),
	}
	
	if !result.Success && len(result.Errors) > 0 {
		status["errors"] = result.Errors
	}
	
	logger.Debug("Service status checked",
		zap.String("service", serviceName),
		zap.Bool("running", result.Success))
	
	return status, nil
}

// InstallPackage installs a system package
func (c *Client) InstallPackage(ctx context.Context, target string, packageName string) (*CommandResult, error) {
	logger := c.logger.With(
		zap.String("method", "InstallPackage"),
		zap.String("target", target),
		zap.String("package", packageName))
	
	logger.Debug("Installing package")
	
	cmd := Command{
		Target:   target,
		Function: "pkg.install",
		Args:     []interface{}{packageName},
		Timeout:  10 * time.Minute, // Package installation can take time
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		logger.Error("Package installation failed", zap.Error(err))
		return nil, err
	}
	
	logger.Info("Package installation completed",
		zap.String("package", packageName),
		zap.Bool("success", result.Success))
	
	return result, nil
}
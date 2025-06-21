// Package architecture - Example implementations showing clean architecture patterns
package architecture

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// Example Infrastructure Layer Implementations
// These implement the domain interfaces using external dependencies

// ExecuteCommandExecutor implements CommandExecutor using pkg/execute
type ExecuteCommandExecutor struct {
	logger *zap.Logger
}

// NewExecuteCommandExecutor creates a new command executor using pkg/execute
func NewExecuteCommandExecutor(logger *zap.Logger) *ExecuteCommandExecutor {
	return &ExecuteCommandExecutor{
		logger: logger,
	}
}

// Execute implements CommandExecutor interface
func (e *ExecuteCommandExecutor) Execute(ctx context.Context, cmd *Command) (*CommandResult, error) {
	start := time.Now()

	// Convert domain Command to execute.Options
	opts := execute.Options{
		Ctx:     ctx,
		Command: cmd.Name,
		Args:    cmd.Args,
		Dir:     cmd.Dir,
		Timeout: cmd.Timeout,
		Capture: true, // Always capture output for domain layer
		Logger:  e.logger,
	}

	// Execute using the consolidated execute package
	output, err := execute.Run(ctx, opts)

	duration := time.Since(start)

	// Convert result back to domain type
	result := &CommandResult{
		Stdout:   output,
		Duration: duration,
		Error:    err,
	}

	if err != nil {
		result.ExitCode = 1 // Default non-zero exit code for errors
		result.Stderr = err.Error()
	} else {
		result.ExitCode = 0
	}

	e.logger.Debug("Command executed",
		zap.String("command", cmd.Name),
		zap.Strings("args", cmd.Args),
		zap.Int("exit_code", result.ExitCode),
		zap.Duration("duration", duration),
	)

	return result, err
}

// ExecuteWithRetry implements CommandExecutor interface with retry logic
func (e *ExecuteCommandExecutor) ExecuteWithRetry(ctx context.Context, cmd *Command, retries int) (*CommandResult, error) {
	var lastResult *CommandResult
	var lastErr error

	for i := 0; i <= retries; i++ {
		result, err := e.Execute(ctx, cmd)
		lastResult = result
		lastErr = err

		if err == nil {
			return result, nil
		}

		if i < retries {
			e.logger.Warn("Command failed, retrying",
				zap.String("command", cmd.Name),
				zap.Int("attempt", i+1),
				zap.Int("max_retries", retries),
				zap.Error(err),
			)
			// Add exponential backoff
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	return lastResult, fmt.Errorf("command failed after %d retries: %w", retries, lastErr)
}

// SystemServiceManager implements ServiceManager for systemd services
type SystemServiceManager struct {
	executor CommandExecutor
	logger   *zap.Logger
}

// NewSystemServiceManager creates a new systemd service manager
func NewSystemServiceManager(executor CommandExecutor, logger *zap.Logger) *SystemServiceManager {
	return &SystemServiceManager{
		executor: executor,
		logger:   logger,
	}
}

// ListServices implements ServiceManager interface
func (s *SystemServiceManager) ListServices(ctx context.Context) ([]*Service, error) {
	cmd := &Command{
		Name: "systemctl",
		Args: []string{"list-units", "--type=service", "--all", "--no-pager", "--plain"},
	}

	result, err := s.executor.Execute(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	return s.parseSystemctlOutput(result.Stdout), nil
}

// GetService implements ServiceManager interface
func (s *SystemServiceManager) GetService(ctx context.Context, name string) (*Service, error) {
	cmd := &Command{
		Name: "systemctl",
		Args: []string{"status", name},
	}

	result, _ := s.executor.Execute(ctx, cmd)
	// systemctl status returns non-zero for inactive services, which is expected

	service := &Service{
		Name: name,
	}

	// Parse the status output
	if strings.Contains(result.Stdout, "active (running)") {
		service.Status = "running"
	} else if strings.Contains(result.Stdout, "inactive (dead)") {
		service.Status = "stopped"
	} else if strings.Contains(result.Stdout, "failed") {
		service.Status = "failed"
	} else {
		service.Status = "unknown"
	}

	// Check if enabled
	enabledCmd := &Command{
		Name: "systemctl",
		Args: []string{"is-enabled", name},
	}
	enabledResult, _ := s.executor.Execute(ctx, enabledCmd)
	service.Enabled = strings.TrimSpace(enabledResult.Stdout) == "enabled"

	return service, nil
}

// StartService implements ServiceManager interface
func (s *SystemServiceManager) StartService(ctx context.Context, name string) error {
	cmd := &Command{
		Name: "systemctl",
		Args: []string{"start", name},
	}

	_, err := s.executor.Execute(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to start service %s: %w", name, err)
	}

	s.logger.Info("Service started", zap.String("service", name))
	return nil
}

// StopService implements ServiceManager interface
func (s *SystemServiceManager) StopService(ctx context.Context, name string) error {
	cmd := &Command{
		Name: "systemctl",
		Args: []string{"stop", name},
	}

	_, err := s.executor.Execute(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to stop service %s: %w", name, err)
	}

	s.logger.Info("Service stopped", zap.String("service", name))
	return nil
}

// EnableService implements ServiceManager interface
func (s *SystemServiceManager) EnableService(ctx context.Context, name string) error {
	cmd := &Command{
		Name: "systemctl",
		Args: []string{"enable", name},
	}

	_, err := s.executor.Execute(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to enable service %s: %w", name, err)
	}

	s.logger.Info("Service enabled", zap.String("service", name))
	return nil
}

// parseSystemctlOutput parses systemctl list-units output
func (s *SystemServiceManager) parseSystemctlOutput(output string) []*Service {
	lines := strings.Split(output, "\n")
	services := make([]*Service, 0)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.HasSuffix(fields[0], ".service") {
			service := &Service{
				Name:   strings.TrimSuffix(fields[0], ".service"),
				Status: fields[2], // ACTIVE state
			}
			
			// Description is everything after the 4th field
			if len(fields) > 4 {
				service.Description = strings.Join(fields[4:], " ")
			}
			
			services = append(services, service)
		}
	}

	return services
}

// Example Application Layer - Command Handlers

// InfrastructureStatusQuery represents a query for infrastructure status
type InfrastructureStatusQuery struct {
	UserID         string `json:"user_id"`
	IncludeServers bool   `json:"include_servers"`
	IncludeNetwork bool   `json:"include_network"`
}

// InfrastructureStatusHandler handles infrastructure status queries
type InfrastructureStatusHandler struct {
	service *InfrastructureService
	logger  *zap.Logger
}

// NewInfrastructureStatusHandler creates a new status handler
func NewInfrastructureStatusHandler(service *InfrastructureService, logger *zap.Logger) *InfrastructureStatusHandler {
	return &InfrastructureStatusHandler{
		service: service,
		logger:  logger,
	}
}

// Handle processes the infrastructure status query
func (h *InfrastructureStatusHandler) Handle(ctx context.Context, query *InfrastructureStatusQuery) (*InfrastructureStatus, error) {
	h.logger.Info("Processing infrastructure status query",
		zap.String("user_id", query.UserID),
		zap.Bool("include_servers", query.IncludeServers),
		zap.Bool("include_network", query.IncludeNetwork),
	)

	status, err := h.service.GetInfrastructureStatus(ctx, query.UserID)
	if err != nil {
		h.logger.Error("Failed to get infrastructure status", zap.Error(err))
		return nil, fmt.Errorf("infrastructure status query failed: %w", err)
	}

	// Apply query filters
	if !query.IncludeServers {
		status.Servers = nil
	}
	if !query.IncludeNetwork {
		status.Network = nil
	}

	h.logger.Info("Infrastructure status query completed",
		zap.String("user_id", query.UserID),
		zap.Int("servers", len(status.Servers)),
		zap.Int("containers", len(status.Containers)),
		zap.Int("services", len(status.Services)),
	)

	return status, nil
}

// This demonstrates how the new architecture would be used:
// 1. Domain interfaces define what we need
// 2. Infrastructure implementations provide concrete behavior
// 3. Domain services contain business logic
// 4. Application handlers orchestrate operations
// 5. Dependency injection container manages wiring
// pkg/container/operations.go
// Container lifecycle operations using Docker SDK

package container

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Start starts a container by ID or name
func (m *Manager) Start(ctx context.Context, containerID string) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Starting container",
		zap.String("container_id", containerID))

	m.mu.RLock()
	err := m.client.ContainerStart(ctx, containerID, container.StartOptions{})
	m.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", containerID, err)
	}

	logger.Info("Container started successfully",
		zap.String("container_id", containerID))

	return nil
}

// Stop stops a container with a timeout
func (m *Manager) Stop(ctx context.Context, containerID string, timeout int) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Stopping container",
		zap.String("container_id", containerID),
		zap.Int("timeout_seconds", timeout))

	stopOptions := container.StopOptions{
		Timeout: &timeout,
	}

	m.mu.RLock()
	err := m.client.ContainerStop(ctx, containerID, stopOptions)
	m.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", containerID, err)
	}

	logger.Info("Container stopped successfully",
		zap.String("container_id", containerID))

	return nil
}

// Restart restarts a container with a timeout
func (m *Manager) Restart(ctx context.Context, containerID string, timeout int) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Restarting container",
		zap.String("container_id", containerID),
		zap.Int("timeout_seconds", timeout))

	stopOptions := container.StopOptions{
		Timeout: &timeout,
	}

	m.mu.RLock()
	err := m.client.ContainerRestart(ctx, containerID, stopOptions)
	m.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to restart container %s: %w", containerID, err)
	}

	logger.Info("Container restarted successfully",
		zap.String("container_id", containerID))

	return nil
}

// Remove removes a container
func (m *Manager) Remove(ctx context.Context, containerID string, force bool) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Removing container",
		zap.String("container_id", containerID),
		zap.Bool("force", force))

	m.mu.RLock()
	err := m.client.ContainerRemove(ctx, containerID, container.RemoveOptions{
		Force: force,
	})
	m.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to remove container %s: %w", containerID, err)
	}

	logger.Info("Container removed successfully",
		zap.String("container_id", containerID))

	return nil
}

// InspectRaw gets detailed container information from Docker API
// Returns the raw Docker API response for maximum flexibility
func (m *Manager) InspectRaw(ctx context.Context, containerID string) (*container.InspectResponse, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Inspecting container",
		zap.String("container_id", containerID))

	m.mu.RLock()
	info, err := m.client.ContainerInspect(ctx, containerID)
	m.mu.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("failed to inspect container %s: %w", containerID, err)
	}

	return &info, nil
}

// Logs retrieves container logs
func (m *Manager) Logs(ctx context.Context, containerID string, options LogOptions) (io.ReadCloser, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Retrieving container logs",
		zap.String("container_id", containerID),
		zap.Bool("follow", options.Follow),
		zap.String("tail", options.Tail))

	logOptions := container.LogsOptions{
		ShowStdout: options.ShowStdout,
		ShowStderr: options.ShowStderr,
		Follow:     options.Follow,
		Tail:       options.Tail,
		Since:      options.Since,
		Until:      options.Until,
		Timestamps: options.Timestamps,
	}

	m.mu.RLock()
	logs, err := m.client.ContainerLogs(ctx, containerID, logOptions)
	m.mu.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("failed to get logs for container %s: %w", containerID, err)
	}

	return logs, nil
}

// WaitForState waits for a container to reach a specific state
func (m *Manager) WaitForState(ctx context.Context, containerID string, desiredState string, timeout time.Duration) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Waiting for container state",
		zap.String("container_id", containerID),
		zap.String("desired_state", desiredState),
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for container %s to reach state %s", containerID, desiredState)
			}

			info, err := m.InspectRaw(ctx, containerID)
			if err != nil {
				return err
			}

			if info.State.Status == desiredState {
				logger.Info("Container reached desired state",
					zap.String("container_id", containerID),
					zap.String("state", desiredState))
				return nil
			}
		}
	}
}

// LogOptions configures log retrieval
type LogOptions struct {
	ShowStdout bool
	ShowStderr bool
	Follow     bool
	Tail       string
	Since      string
	Until      string
	Timestamps bool
}

// DefaultLogOptions returns sensible defaults for log retrieval
func DefaultLogOptions() LogOptions {
	return LogOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     false,
		Tail:       "100",
		Timestamps: false,
	}
}

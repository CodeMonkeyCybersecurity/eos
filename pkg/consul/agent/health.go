// pkg/consul/agent/health.go
//
// Health monitoring and readiness checks for Consul agents.
//
// Last Updated: 2025-01-24

package agent

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WaitForAgentReady waits for a Consul agent to become ready and responsive.
//
// This function polls the agent's health endpoint until it responds successfully
// or the timeout is reached. Uses exponential backoff to avoid overwhelming
// the agent during startup.
//
// Parameters:
//   - rc: RuntimeContext for logging and cancellation
//   - agentAddr: Agent address (e.g., "http://localhost:8500")
//   - timeout: Maximum time to wait
//
// Returns:
//   - error: Timeout error or nil if agent is ready
//
// Example:
//
//	err := WaitForAgentReady(rc, "http://localhost:8500", 30*time.Second)
//	if err != nil {
//	    return fmt.Errorf("agent not ready: %w", err)
//	}
func WaitForAgentReady(rc *eos_io.RuntimeContext, agentAddr string, timeout time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Waiting for Consul agent to be ready",
		zap.String("address", agentAddr),
		zap.Duration("timeout", timeout))

	ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
	defer cancel()

	backoff := 1 * time.Second
	maxBackoff := 10 * time.Second
	attempt := 0

	for {
		attempt++
		select {
		case <-ctx.Done():
			logger.Error("Timeout waiting for agent to be ready",
				zap.Duration("timeout", timeout),
				zap.Int("attempts", attempt),
				zap.String("remediation", "Check agent logs with: journalctl -u consul -n 50"))
			return fmt.Errorf("timeout waiting for agent to be ready after %d attempts", attempt)

		default:
			// Check agent health
			healthy, err := checkAgentHealth(ctx, agentAddr)
			if err == nil && healthy {
				deadline, _ := ctx.Deadline()
				elapsed := time.Since(time.Now().Add(-time.Until(deadline)))
				logger.Info("Agent is ready",
					zap.String("address", agentAddr),
					zap.Int("attempts", attempt),
					zap.Duration("elapsed", elapsed))
				return nil
			}

			// Log the check result
			if err != nil {
				logger.Debug("Agent health check failed",
					zap.Error(err),
					zap.Int("attempt", attempt),
					zap.Duration("backoff", backoff))
			} else {
				logger.Debug("Agent not yet healthy",
					zap.Int("attempt", attempt),
					zap.Duration("backoff", backoff))
			}

			// Wait before retrying
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				// Exponential backoff with max
				backoff = min(backoff*2, maxBackoff)
			}
		}
	}
}

// checkAgentHealth performs a single health check against the Consul agent.
//
// Checks the /v1/agent/self endpoint which returns agent configuration
// and status. This endpoint is available even before the agent has joined
// a cluster.
//
// Parameters:
//   - ctx: Context for cancellation
//   - agentAddr: Agent address
//
// Returns:
//   - bool: true if agent is healthy
//   - error: Any HTTP or network error
func checkAgentHealth(ctx context.Context, agentAddr string) (bool, error) {
	// Build health endpoint URL
	healthURL := fmt.Sprintf("%s/v1/agent/self", agentAddr)

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

// GetAgentStatus retrieves detailed status information from a Consul agent.
//
// This function queries the agent's API to gather comprehensive status including:
//   - Running state
//   - Health status
//   - Cluster membership
//   - Service count
//   - Version information
//
// Parameters:
//   - rc: RuntimeContext
//   - agentAddr: Agent address
//
// Returns:
//   - *AgentStatus: Detailed status information
//   - error: Any query error
func GetAgentStatus(rc *eos_io.RuntimeContext, agentAddr string) (*AgentStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Querying agent status",
		zap.String("address", agentAddr))

	// Check basic health first
	healthy, err := checkAgentHealth(rc.Ctx, agentAddr)
	if err != nil {
		return &AgentStatus{
			Running: false,
			Health:  HealthUnknown,
		}, fmt.Errorf("failed to check agent health: %w", err)
	}

	status := &AgentStatus{
		Running: healthy,
	}

	if healthy {
		status.Health = HealthPassing
	} else {
		status.Health = HealthCritical
	}

	// TODO: Query additional endpoints for:
	// - /v1/agent/members (member count)
	// - /v1/agent/services (service count)
	// - /v1/status/leader (leader status)
	// - /v1/agent/self (version, uptime)

	logger.Debug("Agent status retrieved",
		zap.Bool("running", status.Running),
		zap.String("health", string(status.Health)))

	return status, nil
}

// min returns the minimum of two durations
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

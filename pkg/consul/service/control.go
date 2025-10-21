// pkg/consul/service/control.go
// Consul service control with proper waiting and rollback

package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RestartWithRollback restarts Consul and rolls back config if restart fails
func RestartWithRollback(ctx context.Context, configPath string, backupContent []byte) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Restarting Consul service...")

	// Restart Consul
	output, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "consul"},
		Capture: true,
	})

	if err != nil {
		// Restart failed - attempt rollback
		logger.Error("Failed to restart Consul, attempting rollback",
			zap.String("output", output),
			zap.Error(err))

		if backupContent != nil {
			logger.Warn("Rolling back configuration to previous version...")

			// Restore backup
			if err := WriteConfigAtomic(configPath, backupContent); err != nil {
				logger.Error("Failed to restore backup configuration", zap.Error(err))
				return fmt.Errorf("restart failed AND rollback failed: %w\n"+
					"Original error: %s\nRollback error: %v",
					err, output, err)
			}

			// Try to restart with old config
			logger.Info("Restarting Consul with previous configuration...")
			rollbackOutput, rollbackErr := execute.Run(ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"restart", "consul"},
				Capture: true,
			})

			if rollbackErr != nil {
				return fmt.Errorf("restart failed AND rollback restart failed\n"+
					"Original: %s\nRollback: %s\n"+
					"Check: sudo systemctl status consul",
					output, rollbackOutput)
			}

			logger.Info("Rollback successful - Consul restored to previous configuration")
			return fmt.Errorf("restart failed (rolled back successfully): %s\n"+
				"Configuration has been restored to previous version.\n"+
				"Fix the issue and try again.",
				output)
		}

		return fmt.Errorf("failed to restart Consul: %s\n"+
			"Output: %s\n"+
			"Fix: Check 'sudo systemctl status consul' for details",
			err, output)
	}

	logger.Info("Consul service restarted successfully")
	return nil
}

// WaitForReady waits for Consul to be ready after restart
// Uses exponential backoff with configurable timeout
// For single-node scenarios, only checks if Consul agent is running
// For multi-node scenarios, waits for leader election
func WaitForReady(ctx context.Context, timeout time.Duration) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Waiting for Consul to become ready...", zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	attempt := 0
	backoff := 500 * time.Millisecond
	consulRespondingOnce := false

	for time.Now().Before(deadline) {
		attempt++

		// Check if Consul is responding
		_, err := execute.Run(ctx, execute.Options{
			Command: "consul",
			Args:    []string{"info"},
			Capture: true,
		})

		if err == nil {
			consulRespondingOnce = true

			// Check cluster size to determine if we should wait for leader
			membersOutput, membersErr := execute.Run(ctx, execute.Options{
				Command: "consul",
				Args:    []string{"members"},
				Capture: true,
			})

			var memberCount int
			if membersErr == nil {
				// Count members (each line except header is a member)
				lines := strings.Split(strings.TrimSpace(membersOutput), "\n")
				memberCount = len(lines) - 1 // Subtract header line
			}

			logger.Debug("Consul agent responding",
				zap.Int("attempt", attempt),
				zap.Int("member_count", memberCount))

			// If single-node cluster, just verify agent is running
			if memberCount <= 1 {
				logger.Info("Consul is ready (single-node mode)",
					zap.Int("attempts", attempt),
					zap.Duration("elapsed", timeout-time.Until(deadline)))
				logger.Warn("Single-node Consul detected - leader election will happen after cluster forms")
				return nil
			}

			// Multi-node cluster - check for leader
			leaderOutput, leaderErr := execute.Run(ctx, execute.Options{
				Command: "consul",
				Args:    []string{"operator", "raft", "list-peers"},
				Capture: true,
			})

			if leaderErr == nil && strings.Contains(leaderOutput, "leader") {
				logger.Info("Consul is ready with leader elected",
					zap.Int("attempts", attempt),
					zap.Int("members", memberCount),
					zap.Duration("elapsed", timeout-time.Until(deadline)))
				return nil
			}

			logger.Debug("Consul responding but leader not elected yet",
				zap.Int("attempt", attempt),
				zap.Int("members", memberCount))
		} else {
			logger.Debug("Consul not ready yet",
				zap.Int("attempt", attempt),
				zap.Error(err))
		}

		// Wait with exponential backoff
		time.Sleep(backoff)
		backoff = backoff * 2
		if backoff > 5*time.Second {
			backoff = 5 * time.Second // Cap at 5 seconds
		}
	}

	// If Consul responded at least once but leader wasn't elected, that might be OK
	if consulRespondingOnce {
		logger.Warn("Consul agent is running but leader not yet elected - this is normal during cluster formation")
		logger.Info("You can check cluster status with: consul members")
		return nil // Don't fail - agent is running
	}

	return fmt.Errorf("timeout waiting for Consul to become ready after %v\n"+
		"Check status: sudo systemctl status consul\n"+
		"Check logs: sudo journalctl -u consul -n 50",
		timeout)
}

// ValidateConfig validates Consul configuration before applying
func ValidateConfig(ctx context.Context, configPath string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Validating Consul configuration", zap.String("config", configPath))

	output, err := execute.Run(ctx, execute.Options{
		Command: "consul",
		Args:    []string{"validate", configPath},
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("configuration validation failed: %s\n"+
			"Config file: %s\n"+
			"Fix the configuration syntax and try again",
			output, configPath)
	}

	logger.Debug("Configuration validation passed")
	return nil
}

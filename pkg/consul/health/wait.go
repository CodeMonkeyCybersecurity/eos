package health

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WaitForReady waits for Consul to be ready to accept connections
// Migrated from cmd/create/consul.go waitForConsulReady
func WaitForReady(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Define readiness criteria
	log.Info("Assessing Consul readiness requirements")

	maxAttempts := 30
	checkInterval := 2 * time.Second
	consulURL := fmt.Sprintf("http://localhost:%d/v1/status/leader", shared.PortConsul)

	// INTERVENE - Check readiness repeatedly
	log.Info("Waiting for Consul to be ready",
		zap.Int("max_attempts", maxAttempts),
		zap.Duration("check_interval", checkInterval))

	for i := 0; i < maxAttempts; i++ {
		// Check if Consul is responding
		checkCmd := execute.Options{
			Command: "curl",
			Args:    []string{"-f", "-s", consulURL},
		}

		output, err := execute.Run(rc.Ctx, checkCmd)
		if err == nil && output != "" {
			// EVALUATE - Consul is ready
			log.Info("Consul is ready",
				zap.Int("attempts", i+1),
				zap.String("leader", output))

			// Additional health check
			healthCmd := execute.Options{
				Command: "consul",
				Args:    []string{"members"},
			}

			members, err := execute.Run(rc.Ctx, healthCmd)
			if err != nil {
				log.Warn("Failed to get consul members", zap.Error(err))
			} else {
				log.Debug("Consul cluster members", zap.String("members", members))
			}

			return nil
		}

		log.Debug("Consul not ready yet",
			zap.Int("attempt", i+1),
			zap.Int("remaining", maxAttempts-i-1))

		// Don't sleep on the last attempt
		if i < maxAttempts-1 {
			time.Sleep(checkInterval)
		}
	}

	// EVALUATE - Failed to become ready
	return fmt.Errorf("consul failed to become ready after %d attempts (%v total wait time)",
		maxAttempts, time.Duration(maxAttempts)*checkInterval)
}

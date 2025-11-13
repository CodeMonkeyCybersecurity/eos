package vault

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// checkNomadAvailability checks if Nomad is available and accessible
// This replaces checkAvailability as part of the  → HashiCorp migration
func checkNomadAvailability(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "nomad_availability"))

	logger.Debug("Checking Nomad availability")

	// Check if nomad binary is available
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"nomad"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err != nil {
		logger.Debug("Nomad binary not found in PATH")
		return fmt.Errorf("nomad binary not available: %w", err)
	}

	// Check if Nomad agent is running and accessible
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"status"},
		Capture: true,
		Timeout: 10 * time.Second,
	}); err != nil {
		logger.Debug("Nomad agent not accessible")
		return fmt.Errorf("nomad agent not accessible: %w", err)
	}

	logger.Debug("Nomad is available and accessible")
	return nil
}

// Package saltstack provides SaltStack integration utilities
package saltstack

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ApplySaltStateWithPillar applies a Salt state with pillar configuration
func ApplySaltStateWithPillar(rc *eos_io.RuntimeContext, stateName string, pillarConfig map[string]interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Serialize pillar configuration
	pillarJSON, err := json.Marshal(pillarConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal pillar configuration: %w", err)
	}
	
	// Apply Salt state with pillar data
	args := []string{
		"--local",
		"state.apply",
		stateName,
		"pillar=" + string(pillarJSON),
	}
	
	logger.Info("Applying Salt state",
		zap.String("state", stateName),
		zap.Strings("args", args))
	
	cmd := exec.Command("salt-call", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Salt state application failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("salt state application failed: %w", err)
	}
	
	logger.Info("Salt state applied successfully",
		zap.String("output", string(output)))
	
	return nil
}
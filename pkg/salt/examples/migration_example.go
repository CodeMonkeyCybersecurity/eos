// Package examples shows how to migrate from CLI to API
package examples

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BEFORE: Using salt-call directly
func OldWayStateApply(state string, pillar map[string]interface{}) error {
	pillarJSON, _ := json.Marshal(pillar)
	cmd := exec.Command("salt-call", "--local", "state.apply", state, 
		fmt.Sprintf("pillar=%s", string(pillarJSON)))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("salt-call failed: %s", output)
	}
	return nil
}

// AFTER: Using Salt API
func NewWayStateApply(rc *eos_io.RuntimeContext, state string, pillar map[string]interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create client using factory
	factory := salt.NewClientFactory(rc)
	client, err := factory.CreateClient()
	if err != nil {
		return fmt.Errorf("failed to create Salt client: %w", err)
	}
	
	// Apply state with progress tracking
	result, err := client.ExecuteStateApply(rc.Ctx, state, pillar, 
		func(progress salt.StateProgress) {
			if progress.Completed {
				logger.Info("State completed",
					zap.String("state", progress.State),
					zap.Bool("success", progress.Success),
					zap.String("message", progress.Message))
			}
		})
	
	if err != nil {
		return fmt.Errorf("state apply failed: %w", err)
	}
	
	if result.Failed {
		return fmt.Errorf("state execution failed with errors: %v", result.Errors)
	}
	
	return nil
}

// BEFORE: Using salt-key to manage keys
func OldWayAcceptKey(minion string) error {
	// List pending keys
	listCmd := exec.Command("salt-key", "-l", "pre", "--out=json")
	_, err := listCmd.Output()
	if err != nil {
		return err
	}
	
	// Accept the key
	acceptCmd := exec.Command("salt-key", "-a", minion, "-y")
	if err := acceptCmd.Run(); err != nil {
		return err
	}
	
	return nil
}

// AFTER: Using Salt API for key management
func NewWayAcceptKey(rc *eos_io.RuntimeContext, minion string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	factory := salt.NewClientFactory(rc)
	client, err := factory.CreateClient()
	if err != nil {
		return err
	}
	
	// List all keys
	keyList, err := client.ListKeys(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}
	
	// Check if key is pending
	isPending := false
	for _, pendingKey := range keyList.MinionsPre {
		if pendingKey == minion {
			isPending = true
			break
		}
	}
	
	if !isPending {
		logger.Info("Key not in pending state",
			zap.String("minion", minion))
		return nil
	}
	
	// Accept the key
	if err := client.AcceptKey(rc.Ctx, minion); err != nil {
		return fmt.Errorf("failed to accept key: %w", err)
	}
	
	logger.Info("Successfully accepted minion key",
		zap.String("minion", minion))
	
	return nil
}

// BEFORE: Using salt-run for orchestration
func OldWayCheckMinions() ([]string, error) {
	cmd := exec.Command("salt-run", "manage.up")
	_, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	// Parse output manually (omitted for brevity)
	var minions []string
	// In real code, you would parse the output here
	
	return minions, nil
}

// AFTER: Using Salt API for orchestration
func NewWayCheckMinions(rc *eos_io.RuntimeContext) ([]string, []string, error) {
	factory := salt.NewClientFactory(rc)
	client, err := factory.CreateClient()
	if err != nil {
		return nil, nil, err
	}
	
	// Get responsive minions
	upMinions, err := client.ManageUp(rc.Ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get responsive minions: %w", err)
	}
	
	// Get unresponsive minions
	downMinions, err := client.ManageDown(rc.Ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get unresponsive minions: %w", err)
	}
	
	return upMinions, downMinions, nil
}

// Example of a complete migration for a service deployment
func DeployServiceExample(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Salt client
	factory := salt.NewClientFactory(rc)
	client, err := factory.CreateClient()
	if err != nil {
		return fmt.Errorf("Salt API required: %w", err)
	}
	
	// 1. Check minion connectivity
	logger.Info("Checking minion connectivity")
	pingResults, err := client.TestPing(rc.Ctx, "*")
	if err != nil {
		return fmt.Errorf("failed to ping minions: %w", err)
	}
	
	for minion, responded := range pingResults {
		if !responded {
			logger.Warn("Minion not responding",
				zap.String("minion", minion))
		}
	}
	
	// 2. Apply the service state
	logger.Info("Deploying service",
		zap.String("service", serviceName))
	
	pillar := map[string]interface{}{
		serviceName: map[string]interface{}{
			"enabled": true,
			"config": map[string]interface{}{
				"port": 8080,
				"host": "0.0.0.0",
			},
		},
	}
	
	result, err := client.ExecuteStateApply(rc.Ctx, serviceName, pillar,
		func(progress salt.StateProgress) {
			logger.Info("Progress",
				zap.String("state", progress.State),
				zap.Bool("completed", progress.Completed),
				zap.String("message", progress.Message))
		})
	
	if err != nil {
		return fmt.Errorf("state apply failed: %w", err)
	}
	
	if result.Failed {
		return fmt.Errorf("deployment failed: %v", result.Errors)
	}
	
	// 3. Verify service is running
	logger.Info("Verifying service status")
	
	cmd := salt.Command{
		Client:   "local",
		Target:   "*",
		Function: "service.status",
		Args:     []string{serviceName},
	}
	
	statusResult, err := client.ExecuteCommand(rc.Ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to check service status: %w", err)
	}
	
	// Check results
	for minion, status := range statusResult.Raw {
		if running, ok := status.(bool); ok && running {
			logger.Info("Service running",
				zap.String("minion", minion))
		} else {
			logger.Warn("Service not running",
				zap.String("minion", minion))
		}
	}
	
	return nil
}
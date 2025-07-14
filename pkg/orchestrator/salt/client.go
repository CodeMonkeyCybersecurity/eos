// pkg/orchestrator/salt/client.go
package salt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Client provides Salt orchestration capabilities
type Client struct {
	rc             *eos_io.RuntimeContext
	stateGenerator *StateGenerator
	config         Config
}

// Config holds Salt client configuration
type Config struct {
	MasterAddress string
	FileRoots     string
	PillarRoots   string
	Environment   string
	Timeout       time.Duration
}

// NewClient creates a new Salt orchestration client
func NewClient(rc *eos_io.RuntimeContext, config Config) *Client {
	return &Client{
		rc:             rc,
		stateGenerator: NewStateGenerator(config.FileRoots),
		config:         config,
	}
}

// Deploy deploys a component using Salt
func (c *Client) Deploy(ctx context.Context, component orchestrator.Component) (*orchestrator.Deployment, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Deploying component via Salt",
		zap.String("component", component.Name),
		zap.String("type", string(component.Type)))

	deployment := &orchestrator.Deployment{
		ID:        fmt.Sprintf("salt-%s-%d", component.Name, time.Now().Unix()),
		Component: component,
		Status:    orchestrator.StatusDeploying,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Outputs:   make(map[string]string),
	}

	// Phase 1: Generate Salt states
	logger.Info("Generating Salt states")
	states, err := c.stateGenerator.GenerateState(component)
	if err != nil {
		deployment.Status = orchestrator.StatusFailed
		deployment.Error = err.Error()
		return deployment, orchestrator.NewOrchestrationError(
			orchestrator.LayerSalt,
			orchestrator.PhasePreparation,
			component.Name,
			"Failed to generate Salt states",
			err,
		)
	}

	// Phase 2: Validate states
	logger.Info("Validating Salt states")
	if err := c.stateGenerator.ValidateState(states); err != nil {
		deployment.Status = orchestrator.StatusFailed
		deployment.Error = err.Error()
		return deployment, orchestrator.NewOrchestrationError(
			orchestrator.LayerSalt,
			orchestrator.PhaseValidation,
			component.Name,
			"Salt state validation failed",
			err,
		)
	}

	// Phase 3: Generate and apply pillar data
	logger.Info("Generating Salt pillar data")
	pillarData, err := c.stateGenerator.GeneratePillarData(component)
	if err != nil {
		deployment.Status = orchestrator.StatusFailed
		deployment.Error = err.Error()
		return deployment, orchestrator.NewOrchestrationError(
			orchestrator.LayerSalt,
			orchestrator.PhasePreparation,
			component.Name,
			"Failed to generate pillar data",
			err,
		)
	}

	if err := c.applyPillarData(component.Name, pillarData); err != nil {
		deployment.Status = orchestrator.StatusFailed
		deployment.Error = err.Error()
		return deployment, orchestrator.NewOrchestrationError(
			orchestrator.LayerSalt,
			orchestrator.PhaseApplication,
			component.Name,
			"Failed to apply pillar data",
			err,
		)
	}

	// Phase 4: Apply Salt states
	logger.Info("Applying Salt states")
	saltState := states.(*SaltState)
	if err := c.applyState(saltState); err != nil {
		deployment.Status = orchestrator.StatusFailed
		deployment.Error = err.Error()
		return deployment, orchestrator.NewOrchestrationError(
			orchestrator.LayerSalt,
			orchestrator.PhaseApplication,
			component.Name,
			"Failed to apply Salt states",
			err,
		)
	}

	// Phase 5: Verify deployment
	logger.Info("Verifying deployment")
	if err := c.verifyDeployment(component); err != nil {
		deployment.Status = orchestrator.StatusUnhealthy
		deployment.Error = err.Error()
		return deployment, orchestrator.NewOrchestrationError(
			orchestrator.LayerSalt,
			orchestrator.PhaseVerification,
			component.Name,
			"Deployment verification failed",
			err,
		)
	}

	deployment.Status = orchestrator.StatusHealthy
	deployment.UpdatedAt = time.Now()
	
	logger.Info("Component deployed successfully via Salt",
		zap.String("component", component.Name),
		zap.String("deployment_id", deployment.ID))

	return deployment, nil
}

// applyPillarData applies pillar data for a component
func (c *Client) applyPillarData(componentName string, pillarData map[string]interface{}) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	// Convert pillar data to YAML
	pillarJSON, err := json.Marshal(pillarData)
	if err != nil {
		return fmt.Errorf("failed to marshal pillar data: %w", err)
	}

	// Write pillar data to file (in real implementation)
	// For now, we'll use salt-call to set pillar data
	cmd := execute.Options{
		Command: "salt-call",
		Args: []string{
			"--local",
			"pillar.set",
			componentName,
			string(pillarJSON),
		},
		Capture: true,
	}

	output, err := execute.Run(c.rc.Ctx, cmd)
	if err != nil {
		logger.Error("Failed to set pillar data",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("failed to set pillar data: %w", err)
	}

	return nil
}

// applyState applies a Salt state
func (c *Client) applyState(state *SaltState) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	// In a real implementation, this would:
	// 1. Save the state file to the Salt file roots
	// 2. Apply the state using salt or salt-call
	
	// For now, we'll simulate with salt-call
	cmd := execute.Options{
		Command: "salt-call",
		Args: []string{
			"--local",
			"state.apply",
			state.ID,
			fmt.Sprintf("saltenv=%s", c.config.Environment),
		},
		Capture: true,
		Timeout: c.config.Timeout,
	}

	output, err := execute.Run(c.rc.Ctx, cmd)
	if err != nil {
		logger.Error("Failed to apply Salt state",
			zap.Error(err),
			zap.String("output", output),
			zap.String("state_id", state.ID))
		
		// Parse Salt output for better error messages
		if strings.Contains(output, "No matching sls found") {
			return eos_err.NewUserError("Salt state file not found. Ensure the state is properly deployed")
		}
		if strings.Contains(output, "Rendering SLS") && strings.Contains(output, "failed") {
			return eos_err.NewUserError("Salt state rendering failed. Check Jinja2 template syntax")
		}
		
		return fmt.Errorf("failed to apply Salt state: %w", err)
	}

	// Parse output to check for failures
	if strings.Contains(output, "Failed:") && !strings.Contains(output, "Failed:     0") {
		return fmt.Errorf("Salt state application had failures: %s", output)
	}

	logger.Info("Salt state applied successfully",
		zap.String("state_id", state.ID))

	return nil
}

// verifyDeployment verifies that a component was deployed successfully
func (c *Client) verifyDeployment(component orchestrator.Component) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	// Component-specific verification
	switch component.Name {
	case "consul":
		return c.verifyConsulDeployment(component)
	case "vault":
		return c.verifyVaultDeployment(component)
	case "nomad":
		return c.verifyNomadDeployment(component)
	default:
		logger.Warn("No specific verification for component",
			zap.String("component", component.Name))
		return nil
	}
}

// verifyConsulDeployment verifies Consul deployment
func (c *Client) verifyConsulDeployment(component orchestrator.Component) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	// Check if Consul service is running
	cmd := execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true,
	}

	output, err := execute.Run(c.rc.Ctx, cmd)
	if err != nil || strings.TrimSpace(output) != "active" {
		return fmt.Errorf("consul service is not active: %s", output)
	}

	// Check if Consul is responding
	config := component.Config.(orchestrator.ConsulConfig)
	checkCmd := execute.Options{
		Command: "consul",
		Args: []string{
			"info",
			fmt.Sprintf("-http-addr=127.0.0.1:%d", config.Ports.HTTP),
		},
		Capture: true,
	}

	output, err = execute.Run(c.rc.Ctx, checkCmd)
	if err != nil {
		return fmt.Errorf("consul is not responding: %w", err)
	}

	logger.Info("Consul deployment verified successfully")
	return nil
}

// verifyVaultDeployment verifies Vault deployment
func (c *Client) verifyVaultDeployment(component orchestrator.Component) error {
	// TODO: Implement Vault verification
	return nil
}

// verifyNomadDeployment verifies Nomad deployment
func (c *Client) verifyNomadDeployment(component orchestrator.Component) error {
	// TODO: Implement Nomad verification
	return nil
}

// Rollback rolls back a deployment
func (c *Client) Rollback(ctx context.Context, deployment *orchestrator.Deployment) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Rolling back Salt deployment",
		zap.String("deployment_id", deployment.ID),
		zap.String("component", deployment.Component.Name))

	// In a real implementation, this would:
	// 1. Identify the previous state
	// 2. Apply the previous state
	// 3. Verify the rollback
	
	// For now, we'll stop the service
	switch deployment.Component.Name {
	case "consul":
		cmd := execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", "consul"},
		}
		_, err := execute.Run(c.rc.Ctx, cmd)
		if err != nil {
			return fmt.Errorf("failed to stop consul service: %w", err)
		}
	}

	return nil
}

// GetStatus returns the status of a deployment
func (c *Client) GetStatus(ctx context.Context, deploymentID string) (*orchestrator.Status, error) {
	// TODO: Implement status checking via Salt
	return &orchestrator.Status{
		Healthy:     true,
		Message:     "Component is healthy",
		LastChecked: time.Now(),
		Details:     make(map[string]interface{}),
	}, nil
}

// PreviewState generates and returns a preview of Salt states
func (c *Client) PreviewState(component orchestrator.Component) (string, error) {
	states, err := c.stateGenerator.GenerateState(component)
	if err != nil {
		return "", fmt.Errorf("failed to generate states: %w", err)
	}

	return c.stateGenerator.PreviewState(states)
}

// PreviewPillar generates and returns a preview of Salt pillar data
func (c *Client) PreviewPillar(component orchestrator.Component) (string, error) {
	pillarData, err := c.stateGenerator.GeneratePillarData(component)
	if err != nil {
		return "", fmt.Errorf("failed to generate pillar data: %w", err)
	}

	// Convert to YAML for preview
	output, err := json.MarshalIndent(pillarData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal pillar data: %w", err)
	}

	return string(output), nil
}
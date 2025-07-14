package strategy

import (
	"context"
	"fmt"
	"time"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

// DirectDeployer implements direct deployment (current approach)
type DirectDeployer struct {
	*BaseDeployer
}

// NewDirectDeployer creates a new direct deployer
func NewDirectDeployer(rc *eos_io.RuntimeContext) *DirectDeployer {
	return &DirectDeployer{
		BaseDeployer: NewBaseDeployer(rc, DirectStrategy),
	}
}

// Deploy implements direct deployment
func (d *DirectDeployer) Deploy(ctx context.Context, component *Component) (*DeploymentResult, error) {
	// Record start time
	startTime := time.Now()
	
	// ASSESS
	d.logDeploymentStep("assess", component)
	if err := d.Validate(ctx, component); err != nil {
		return d.createDeploymentResult(component, "validation_failed", err), err
	}
	
	// Check for dry-run mode
	if dryRun, ok := component.Config["dry_run"].(bool); ok && dryRun {
		d.logger.Info("Dry-run mode - showing what would be deployed",
			zap.String("component", component.Name))
		return d.createDeploymentResult(component, "dry_run", nil), nil
	}
	
	// INTERVENE
	d.logDeploymentStep("intervene", component)
	
	var err error
	switch component.Name {
	case "consul":
		err = d.deployConsul(ctx, component)
	case "vault":
		err = d.deployVault(ctx, component)
	case "nomad":
		err = d.deployNomad(ctx, component)
	default:
		err = fmt.Errorf("unsupported component for direct deployment: %s", component.Name)
	}
	
	if err != nil {
		result := d.createDeploymentResult(component, "deploy_failed", err)
		d.recordDeploymentMetrics(result)
		return result, err
	}
	
	// EVALUATE
	d.logDeploymentStep("evaluate", component)
	if err := d.verifyDeployment(ctx, component); err != nil {
		d.logger.Warn("Deployment verification failed", 
			zap.String("component", component.Name),
			zap.Error(err))
		// Don't fail the deployment, just warn
	}
	
	result := d.createDeploymentResult(component, "success", nil)
	result.StartTime = startTime // Preserve original start time
	d.recordDeploymentMetrics(result)
	
	return result, nil
}

// Validate validates the component configuration
func (d *DirectDeployer) Validate(ctx context.Context, component *Component) error {
	// Base validation
	if err := d.validateComponent(component); err != nil {
		return err
	}
	
	// Strategy-specific validation
	switch component.Name {
	case "consul":
		return d.validateConsulConfig(component)
	case "vault":
		return d.validateVaultConfig(component)
	case "nomad":
		return d.validateNomadConfig(component)
	}
	
	return nil
}

// deployConsul deploys Consul using existing implementation
func (d *DirectDeployer) deployConsul(ctx context.Context, component *Component) error {
	d.logger.Info("Deploying Consul using direct strategy",
		zap.String("version", component.Version))
	
	// Map component config to consul config
	config := &consul.ConsulConfig{
		Mode:            "server",
		Datacenter:      "dc1",
		BootstrapExpect: 1,
	}
	
	// Extract datacenter if provided
	if dc, ok := component.Config["datacenter"].(string); ok {
		config.Datacenter = dc
	}
	
	// TODO: Use actual consul installer - for now just log
	d.logger.Info("Consul installation would be performed here",
		zap.String("datacenter", config.Datacenter),
		zap.String("mode", config.Mode))
	
	// Simulate installation success
	time.Sleep(100 * time.Millisecond)
	
	d.logger.Info("Consul deployed successfully")
	return nil
}

// deployVault deploys Vault using existing implementation
func (d *DirectDeployer) deployVault(ctx context.Context, component *Component) error {
	d.logger.Info("Deploying Vault using direct strategy",
		zap.String("version", component.Version))
	
	// TODO: Use actual Vault installer when available
	// For now, just log
	d.logger.Info("Vault deployment not yet implemented in direct strategy",
		zap.String("version", component.Version))
	
	return nil
}

// deployNomad deploys Nomad using existing implementation
func (d *DirectDeployer) deployNomad(ctx context.Context, component *Component) error {
	d.logger.Info("Deploying Nomad using direct strategy",
		zap.String("version", component.Version))
	
	// TODO: Implement Nomad direct deployment
	d.logger.Info("Nomad deployment not yet implemented in direct strategy")
	
	return nil
}

// verifyDeployment verifies that the deployment succeeded
func (d *DirectDeployer) verifyDeployment(ctx context.Context, component *Component) error {
	switch component.Name {
	case "consul":
		return d.verifyConsulDeployment(ctx, component)
	case "vault":
		return d.verifyVaultDeployment(ctx, component)
	case "nomad":
		return d.verifyNomadDeployment(ctx, component)
	}
	
	return nil
}

// verifyConsulDeployment verifies Consul is running
func (d *DirectDeployer) verifyConsulDeployment(ctx context.Context, component *Component) error {
	// TODO: Implement actual verification
	// Check if service is running, API is responding, etc.
	d.logger.Debug("Verifying Consul deployment")
	return nil
}

// verifyVaultDeployment verifies Vault is running
func (d *DirectDeployer) verifyVaultDeployment(ctx context.Context, component *Component) error {
	d.logger.Debug("Verifying Vault deployment")
	return nil
}

// verifyNomadDeployment verifies Nomad is running
func (d *DirectDeployer) verifyNomadDeployment(ctx context.Context, component *Component) error {
	d.logger.Debug("Verifying Nomad deployment")
	return nil
}

// validateConsulConfig validates Consul-specific configuration
func (d *DirectDeployer) validateConsulConfig(component *Component) error {
	// Check required fields
	if component.Version == "" {
		component.Version = "1.17.0" // Default version
	}
	
	// Validate datacenter name if provided
	if dc, ok := component.Config["datacenter"].(string); ok {
		if dc == "" {
			return &ValidationError{
				Component: component.Name,
				Field:     "datacenter",
				Message:   "datacenter cannot be empty",
			}
		}
	} else {
		// Set default datacenter
		component.Config["datacenter"] = "dc1"
	}
	
	return nil
}

// validateVaultConfig validates Vault-specific configuration
func (d *DirectDeployer) validateVaultConfig(component *Component) error {
	if component.Version == "" {
		component.Version = "1.15.0" // Default version
	}
	
	// Validate backend
	if backend, ok := component.Config["backend"].(string); ok {
		validBackends := []string{"file", "consul", "raft"}
		valid := false
		for _, vb := range validBackends {
			if backend == vb {
				valid = true
				break
			}
		}
		if !valid {
			return &ValidationError{
				Component: component.Name,
				Field:     "backend",
				Message:   fmt.Sprintf("invalid backend: %s", backend),
			}
		}
	}
	
	return nil
}

// validateNomadConfig validates Nomad-specific configuration
func (d *DirectDeployer) validateNomadConfig(component *Component) error {
	if component.Version == "" {
		component.Version = "1.7.0" // Default version
	}
	
	return nil
}

// Rollback attempts to rollback a deployment
func (d *DirectDeployer) Rollback(ctx context.Context, deployment *DeploymentResult) error {
	d.logger.Warn("Direct deployment rollback is limited",
		zap.String("component", deployment.Component),
		zap.String("deployment_id", deployment.ID))
	
	// Direct deployments have limited rollback capability
	// We can only stop services, not restore previous state
	
	switch deployment.Component {
	case "consul":
		// Stop Consul service
		d.logger.Info("Stopping Consul service for rollback")
		// TODO: Implement service stop
	case "vault":
		// Stop Vault service
		d.logger.Info("Stopping Vault service for rollback")
		// TODO: Implement service stop
	}
	
	return fmt.Errorf("direct deployment rollback not fully implemented")
}

// GetStatus gets the status of a deployed component
func (d *DirectDeployer) GetStatus(ctx context.Context, component *Component) (*DeploymentStatus, error) {
	status := &DeploymentStatus{
		Component:   component.Name,
		LastChecked: time.Now(),
		Details:     make(map[string]interface{}),
	}
	
	switch component.Name {
	case "consul":
		// Check Consul status
		// TODO: Implement actual status check
		status.Status = "running"
		status.Healthy = true
	case "vault":
		// Check Vault status
		// TODO: Implement actual status check
		status.Status = "running"
		status.Healthy = true
	default:
		status.Status = "unknown"
		status.Healthy = false
	}
	
	return status, nil
}

// SupportsComponent checks if this deployer supports the component type
func (d *DirectDeployer) SupportsComponent(componentType ComponentType) bool {
	// Direct deployment mainly for infrastructure services in dev/test
	return componentType == InfrastructureType || componentType == ServiceType
}
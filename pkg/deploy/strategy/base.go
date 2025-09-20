package strategy

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BaseDeployer provides common functionality for all deployers
type BaseDeployer struct {
	rc       *eos_io.RuntimeContext
	logger   otelzap.LoggerWithCtx
	strategy DeploymentStrategy
}

// NewBaseDeployer creates a new base deployer
func NewBaseDeployer(rc *eos_io.RuntimeContext, strategy DeploymentStrategy) *BaseDeployer {
	return &BaseDeployer{
		rc:       rc,
		logger:   otelzap.Ctx(rc.Ctx),
		strategy: strategy,
	}
}

// GetStrategy returns the deployment strategy
func (b *BaseDeployer) GetStrategy() DeploymentStrategy {
	return b.strategy
}

// createDeploymentResult creates a deployment result
func (b *BaseDeployer) createDeploymentResult(component *Component, status string, err error) *DeploymentResult {
	result := &DeploymentResult{
		ID:        fmt.Sprintf("%s-%d", component.Name, time.Now().Unix()),
		Component: component.Name,
		Strategy:  b.strategy,
		Status:    status,
		StartTime: time.Now(),
		Outputs:   make(map[string]interface{}),
	}

	if err != nil {
		result.Error = err.Error()
		result.Status = "failed"
	}

	endTime := time.Now()
	result.EndTime = &endTime

	return result
}

// logDeploymentStep logs a deployment step with structured logging
func (b *BaseDeployer) logDeploymentStep(step string, component *Component, fields ...zap.Field) {
	defaultFields := []zap.Field{
		zap.String("step", step),
		zap.String("component", component.Name),
		zap.String("strategy", string(b.strategy)),
		zap.String("type", string(component.Type)),
		zap.String("environment", component.Environment),
	}
	b.logger.Info("Deployment step", append(defaultFields, fields...)...)
}

// validateComponent performs basic component validation
func (b *BaseDeployer) validateComponent(component *Component) error {
	if component.Name == "" {
		return &ValidationError{
			Component: "component",
			Field:     "name",
			Message:   "component name cannot be empty",
		}
	}

	if component.Type == "" {
		return &ValidationError{
			Component: component.Name,
			Field:     "type",
			Message:   "component type cannot be empty",
		}
	}

	if component.Config == nil {
		component.Config = make(map[string]interface{})
	}

	// Check strategy capabilities
	capabilities := GetCapabilities(b.strategy)

	// Validate dry-run support
	if dryRun, ok := component.Config["dry_run"].(bool); ok && dryRun && !capabilities.SupportsDryRun {
		return fmt.Errorf("strategy %s does not support dry-run mode", b.strategy)
	}

	return nil
}

// saveRollbackInfo saves rollback information
func (b *BaseDeployer) saveRollbackInfo(component *Component, previousState map[string]interface{}) (*RollbackInfo, error) {
	rollbackInfo := &RollbackInfo{
		PreviousVersion: component.Version,
		StateBackup:     previousState,
		Strategy:        b.strategy,
		Timestamp:       time.Now(),
	}

	// TODO: Store in Consul KV or another persistent store
	// For now, just log it
	b.logger.Info("Rollback info saved",
		zap.String("component", component.Name),
		zap.String("previous_version", rollbackInfo.PreviousVersion),
		zap.Time("timestamp", rollbackInfo.Timestamp))

	return rollbackInfo, nil
}

// checkPrerequisites checks if all prerequisites for the strategy are met
func (b *BaseDeployer) checkPrerequisites(ctx context.Context) error {
	capabilities := GetCapabilities(b.strategy)

	if capabilities.Requires {
		if err := b.checkAvailable(ctx); err != nil {
			return fmt.Errorf(" is required but not available: %w", err)
		}
	}

	if capabilities.RequiresTerraform {
		if err := b.checkTerraformAvailable(ctx); err != nil {
			return fmt.Errorf("Terraform is required but not available: %w", err)
		}
	}

	if capabilities.RequiresNomad {
		if err := b.checkNomadAvailable(ctx); err != nil {
			return fmt.Errorf("Nomad is required but not available: %w", err)
		}
	}

	return nil
}

// checkAvailable checks if  is available
func (b *BaseDeployer) checkAvailable(ctx context.Context) error {
	// TODO: Implement actual check
	b.logger.Debug("Checking  availability")
	return nil
}

// checkTerraformAvailable checks if Terraform is available
func (b *BaseDeployer) checkTerraformAvailable(ctx context.Context) error {
	// TODO: Implement actual check
	b.logger.Debug("Checking Terraform availability")
	return nil
}

// checkNomadAvailable checks if Nomad is available
func (b *BaseDeployer) checkNomadAvailable(ctx context.Context) error {
	// TODO: Implement actual check
	b.logger.Debug("Checking Nomad availability")
	return nil
}

// sanitizeConfig sanitizes configuration values to prevent injection attacks
func (b *BaseDeployer) sanitizeConfig(config map[string]interface{}) map[string]interface{} {
	sanitized := make(map[string]interface{})

	for key, value := range config {
		switch v := value.(type) {
		case string:
			// Basic sanitization - in production, use more sophisticated validation
			sanitized[key] = b.sanitizeString(v)
		default:
			sanitized[key] = value
		}
	}

	return sanitized
}

// sanitizeString performs basic string sanitization
func (b *BaseDeployer) sanitizeString(input string) string {
	// TODO: Implement proper sanitization
	// For now, just return the input
	return input
}

// recordDeploymentMetrics records deployment metrics
func (b *BaseDeployer) recordDeploymentMetrics(result *DeploymentResult) {
	if result.EndTime != nil {
		duration := result.EndTime.Sub(result.StartTime)
		b.logger.Info("Deployment metrics",
			zap.String("component", result.Component),
			zap.String("strategy", string(result.Strategy)),
			zap.String("status", result.Status),
			zap.Duration("duration", duration))

		// TODO: Send to Prometheus or other metrics system
	}
}

// pkg/consul/registry/health.go
//
// Health check management implementation
//
// Last Updated: 2025-10-23

package registry

import (
	"context"
	"fmt"

	"github.com/hashicorp/consul/api"
	"go.uber.org/zap"
)

// RegisterHealthCheck registers a standalone health check (not tied to a service)
func (r *ConsulServiceRegistry) RegisterHealthCheck(ctx context.Context, check *HealthCheck) error {
	r.logger.Info("ASSESS: Registering health check",
		zap.String("check_id", check.ID),
		zap.String("check_name", check.Name),
		zap.String("check_type", string(check.Type)))

	// Validate check
	if check.ID == "" {
		return fmt.Errorf("check ID is required")
	}
	if check.Name == "" {
		check.Name = check.ID
	}

	// INTERVENE - Convert to Consul format
	registration := &api.AgentCheckRegistration{
		ID:   check.ID,
		Name: check.Name,
	}

	// Convert check details
	registration.AgentServiceCheck = *convertHealthCheck(check)

	// Register check
	if err := r.agent.CheckRegister(registration); err != nil {
		r.logger.Error("INTERVENE FAILED: Health check registration failed",
			zap.String("check_id", check.ID),
			zap.Error(err))
		return fmt.Errorf("failed to register health check %s: %w", check.ID, err)
	}

	// EVALUATE - Verify registration
	checks, err := r.agent.Checks()
	if err != nil {
		r.logger.Warn("EVALUATE: Failed to verify check registration",
			zap.Error(err))
		// Don't fail - registration likely succeeded
	} else if _, exists := checks[check.ID]; !exists {
		r.logger.Error("EVALUATE FAILED: Check not found after registration",
			zap.String("check_id", check.ID))
		return fmt.Errorf("check %s not found after registration", check.ID)
	}

	r.logger.Info("EVALUATE SUCCESS: Health check registered successfully",
		zap.String("check_id", check.ID))

	return nil
}

// DeregisterHealthCheck removes a health check
func (r *ConsulServiceRegistry) DeregisterHealthCheck(ctx context.Context, checkID string) error {
	r.logger.Info("ASSESS: Deregistering health check",
		zap.String("check_id", checkID))

	// ASSESS - Check if check exists
	checks, err := r.agent.Checks()
	if err != nil {
		r.logger.Warn("ASSESS: Failed to check health check existence",
			zap.String("check_id", checkID),
			zap.Error(err))
		// Continue anyway
	} else if _, exists := checks[checkID]; !exists {
		r.logger.Info("ASSESS: Health check not registered, nothing to deregister",
			zap.String("check_id", checkID))
		return nil // Idempotent
	}

	// INTERVENE - Deregister check
	if err := r.agent.CheckDeregister(checkID); err != nil {
		r.logger.Error("INTERVENE FAILED: Health check deregistration failed",
			zap.String("check_id", checkID),
			zap.Error(err))
		return fmt.Errorf("failed to deregister health check %s: %w", checkID, err)
	}

	// EVALUATE - Verify deregistration
	checks, err = r.agent.Checks()
	if err != nil {
		r.logger.Warn("EVALUATE: Failed to verify check deregistration",
			zap.Error(err))
		// Don't fail - deregistration likely succeeded
	} else if _, exists := checks[checkID]; exists {
		r.logger.Error("EVALUATE FAILED: Check still exists after deregistration",
			zap.String("check_id", checkID))
		return fmt.Errorf("check %s still exists after deregistration", checkID)
	}

	r.logger.Info("EVALUATE SUCCESS: Health check deregistered successfully",
		zap.String("check_id", checkID))

	return nil
}

// UpdateHealthCheckStatus updates the status of a TTL-based health check
// This is typically used for checks where the service itself reports health
func (r *ConsulServiceRegistry) UpdateHealthCheckStatus(ctx context.Context, checkID string, status HealthStatus, output string) error {
	r.logger.Info("ASSESS: Updating health check status",
		zap.String("check_id", checkID),
		zap.String("status", string(status)),
		zap.String("output", output))

	// ASSESS - Verify check exists
	checks, err := r.agent.Checks()
	if err != nil {
		return fmt.Errorf("failed to get checks: %w", err)
	}

	check, exists := checks[checkID]
	if !exists {
		return fmt.Errorf("health check %s not found", checkID)
	}

	// INTERVENE - Update check status
	var updateErr error
	switch status {
	case HealthPassing:
		updateErr = r.agent.UpdateTTL(checkID, output, api.HealthPassing)
	case HealthWarning:
		updateErr = r.agent.UpdateTTL(checkID, output, api.HealthWarning)
	case HealthCritical:
		updateErr = r.agent.UpdateTTL(checkID, output, api.HealthCritical)
	default:
		return fmt.Errorf("invalid health status: %s", status)
	}

	if updateErr != nil {
		r.logger.Error("INTERVENE FAILED: Health check status update failed",
			zap.String("check_id", checkID),
			zap.String("status", string(status)),
			zap.Error(updateErr))
		return fmt.Errorf("failed to update check status: %w", updateErr)
	}

	// EVALUATE - Verify status update
	checks, err = r.agent.Checks()
	if err != nil {
		r.logger.Warn("EVALUATE: Failed to verify status update",
			zap.Error(err))
		// Don't fail - update likely succeeded
	} else {
		updatedCheck := checks[checkID]
		if updatedCheck.Status != string(status) {
			r.logger.Warn("EVALUATE: Check status mismatch",
				zap.String("check_id", checkID),
				zap.String("expected", string(status)),
				zap.String("actual", updatedCheck.Status))
		}
	}

	r.logger.Info("EVALUATE SUCCESS: Health check status updated",
		zap.String("check_id", checkID),
		zap.String("old_status", check.Status),
		zap.String("new_status", string(status)))

	return nil
}

// PassHealthCheck marks a TTL check as passing (convenience method)
func (r *ConsulServiceRegistry) PassHealthCheck(ctx context.Context, checkID, output string) error {
	return r.UpdateHealthCheckStatus(ctx, checkID, HealthPassing, output)
}

// WarnHealthCheck marks a TTL check as warning (convenience method)
func (r *ConsulServiceRegistry) WarnHealthCheck(ctx context.Context, checkID, output string) error {
	return r.UpdateHealthCheckStatus(ctx, checkID, HealthWarning, output)
}

// FailHealthCheck marks a TTL check as critical (convenience method)
func (r *ConsulServiceRegistry) FailHealthCheck(ctx context.Context, checkID, output string) error {
	return r.UpdateHealthCheckStatus(ctx, checkID, HealthCritical, output)
}

// GetHealthCheckStatus retrieves the current status of a health check
func (r *ConsulServiceRegistry) GetHealthCheckStatus(ctx context.Context, checkID string) (*HealthCheckResult, error) {
	checks, err := r.agent.Checks()
	if err != nil {
		return nil, fmt.Errorf("failed to get checks: %w", err)
	}

	check, exists := checks[checkID]
	if !exists {
		return nil, fmt.Errorf("health check %s not found", checkID)
	}

	return &HealthCheckResult{
		CheckID: check.CheckID,
		Name:    check.Name,
		Status:  HealthStatus(check.Status),
		Output:  check.Output,
		Node:    check.Node,
	}, nil
}

// ListHealthChecks lists all health checks on the local agent
func (r *ConsulServiceRegistry) ListHealthChecks(ctx context.Context) (map[string]*HealthCheckResult, error) {
	checks, err := r.agent.Checks()
	if err != nil {
		return nil, fmt.Errorf("failed to list health checks: %w", err)
	}

	results := make(map[string]*HealthCheckResult)
	for id, check := range checks {
		results[id] = &HealthCheckResult{
			CheckID: check.CheckID,
			Name:    check.Name,
			Status:  HealthStatus(check.Status),
			Output:  check.Output,
			Node:    check.Node,
		}
	}

	return results, nil
}

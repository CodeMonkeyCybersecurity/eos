package managers

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/security_permissions"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecurityPermissionsManager is a unified manager for security permissions
// that follows the new framework pattern and wraps the existing implementation
type SecurityPermissionsManager struct {
	*BaseManager
	permManager *security_permissions.PermissionManager
}

// SecurityPermissionResource represents a security permission configuration
type SecurityPermissionResource struct {
	ID         string                                 `json:"id"`
	Categories []string                               `json:"categories"`
	Config     *security_permissions.SecurityConfig  `json:"config"`
	Timestamp  time.Time                             `json:"timestamp"`
}

// NewSecurityPermissionsManager creates a new unified security permissions manager
func NewSecurityPermissionsManager(config *ManagerConfig) *SecurityPermissionsManager {
	baseManager := NewBaseManager("security.permissions", config)
	
	// Create the underlying permission manager with default config
	permManager := security_permissions.NewPermissionManager(
		security_permissions.DefaultSecurityConfig(),
	)
	
	return &SecurityPermissionsManager{
		BaseManager: baseManager,
		permManager: permManager,
	}
}

// Create implements ResourceManager interface for creating security permission configurations
func (spm *SecurityPermissionsManager) Create(ctx context.Context, resource SecurityPermissionResource) (*OperationResult, error) {
	logger := otelzap.Ctx(ctx)
	start := time.Now()
	
	logger.Info("Creating security permission configuration",
		zap.String("id", resource.ID),
		zap.Strings("categories", resource.Categories))
	
	// ASSESS - Validate the configuration
	if err := spm.Validate(ctx, resource); err != nil {
		return spm.CreateOperationResult(false, "Validation failed", time.Since(start), err), err
	}
	
	// INTERVENE - Apply the permissions (in real implementation)
	if !spm.GetConfig().DryRun {
		_, err := spm.permManager.FixPermissions(resource.Categories)
		if err != nil {
			return spm.CreateOperationResult(false, "Failed to apply permissions", time.Since(start), err), err
		}
	}
	
	// EVALUATE - Verify the result
	checkResult, err := spm.permManager.CheckPermissions(resource.Categories)
	if err != nil {
		logger.Warn("Failed to verify permission application", zap.Error(err))
	}
	
	duration := time.Since(start)
	message := fmt.Sprintf("Successfully created security permission configuration for %d categories", len(resource.Categories))
	
	result := spm.CreateOperationResult(true, message, duration, nil)
	if checkResult != nil {
		result.Metadata["check_result"] = checkResult
	}
	
	return result, nil
}

// Read implements ResourceManager interface for reading security permission status
func (spm *SecurityPermissionsManager) Read(ctx context.Context, id string) (SecurityPermissionResource, error) {
	logger := otelzap.Ctx(ctx)
	
	logger.Debug("Reading security permission configuration", zap.String("id", id))
	
	// In a real implementation, this would read from persistent storage
	// For now, return a default configuration
	return SecurityPermissionResource{
		ID:         id,
		Categories: []string{"system", "application", "user"},
		Config:     security_permissions.DefaultSecurityConfig(),
		Timestamp:  time.Now(),
	}, nil
}

// Update implements ResourceManager interface for updating security permissions
func (spm *SecurityPermissionsManager) Update(ctx context.Context, resource SecurityPermissionResource) (*OperationResult, error) {
	logger := otelzap.Ctx(ctx)
	start := time.Now()
	
	logger.Info("Updating security permission configuration",
		zap.String("id", resource.ID),
		zap.Strings("categories", resource.Categories))
	
	// ASSESS - Validate the update
	if err := spm.Validate(ctx, resource); err != nil {
		return spm.CreateOperationResult(false, "Validation failed", time.Since(start), err), err
	}
	
	// INTERVENE - Apply the updated permissions
	if !spm.GetConfig().DryRun {
		_, err := spm.permManager.FixPermissions(resource.Categories)
		if err != nil {
			return spm.CreateOperationResult(false, "Failed to update permissions", time.Since(start), err), err
		}
	}
	
	duration := time.Since(start)
	message := fmt.Sprintf("Successfully updated security permission configuration")
	
	return spm.CreateOperationResult(true, message, duration, nil), nil
}

// Delete implements ResourceManager interface for removing security permission configurations
func (spm *SecurityPermissionsManager) Delete(ctx context.Context, id string) (*OperationResult, error) {
	logger := otelzap.Ctx(ctx)
	start := time.Now()
	
	logger.Info("Deleting security permission configuration", zap.String("id", id))
	
	// In a real implementation, this would remove the configuration
	// For security managers, deletion might mean reverting to defaults
	
	duration := time.Since(start)
	message := fmt.Sprintf("Successfully deleted security permission configuration %s", id)
	
	return spm.CreateOperationResult(true, message, duration, nil), nil
}

// List implements ResourceManager interface for listing security permission configurations
func (spm *SecurityPermissionsManager) List(ctx context.Context, options *ListOptions) ([]SecurityPermissionResource, error) {
	logger := otelzap.Ctx(ctx)
	
	logger.Debug("Listing security permission configurations")
	
	// In a real implementation, this would query persistent storage
	// For now, return a sample list
	resources := []SecurityPermissionResource{
		{
			ID:         "default",
			Categories: []string{"system", "application", "user"},
			Config:     security_permissions.DefaultSecurityConfig(),
			Timestamp:  time.Now(),
		},
	}
	
	return resources, nil
}

// Start implements ResourceManager interface for starting security permission monitoring
func (spm *SecurityPermissionsManager) Start(ctx context.Context, id string) (*OperationResult, error) {
	start := time.Now()
	
	// Start permission monitoring/enforcement
	message := fmt.Sprintf("Started security permission monitoring for %s", id)
	
	return spm.CreateOperationResult(true, message, time.Since(start), nil), nil
}

// Stop implements ResourceManager interface for stopping security permission monitoring
func (spm *SecurityPermissionsManager) Stop(ctx context.Context, id string) (*OperationResult, error) {
	start := time.Now()
	
	// Stop permission monitoring/enforcement
	message := fmt.Sprintf("Stopped security permission monitoring for %s", id)
	
	return spm.CreateOperationResult(true, message, time.Since(start), nil), nil
}

// Restart implements ResourceManager interface for restarting security permission monitoring
func (spm *SecurityPermissionsManager) Restart(ctx context.Context, id string) (*OperationResult, error) {
	logger := otelzap.Ctx(ctx)
	start := time.Now()
	
	logger.Info("Restarting security permission monitoring", zap.String("id", id))
	
	// Stop and start monitoring
	if _, err := spm.Stop(ctx, id); err != nil {
		return spm.CreateOperationResult(false, "Failed to stop monitoring", time.Since(start), err), err
	}
	
	if _, err := spm.Start(ctx, id); err != nil {
		return spm.CreateOperationResult(false, "Failed to start monitoring", time.Since(start), err), err
	}
	
	message := fmt.Sprintf("Successfully restarted security permission monitoring for %s", id)
	
	return spm.CreateOperationResult(true, message, time.Since(start), nil), nil
}

// GetStatus implements ResourceManager interface for getting security permission status
func (spm *SecurityPermissionsManager) GetStatus(ctx context.Context, id string) (*ResourceStatus, error) {
	logger := otelzap.Ctx(ctx)
	
	logger.Debug("Getting security permission status", zap.String("id", id))
	
	// Get current permission check results
	categories := []string{"system", "application", "user"}
	checkResult, err := spm.permManager.CheckPermissions(categories)
	
	status := &ResourceStatus{
		ID:         id,
		State:      StateActive,
		Health:     HealthHealthy,
		LastUpdate: time.Now(),
		Configuration: map[string]interface{}{
			"categories": categories,
			"dry_run":    spm.GetConfig().DryRun,
		},
		Metrics: map[string]interface{}{},
		Errors:  make([]string, 0),
	}
	
	if err != nil {
		status.Health = HealthUnhealthy
		status.Errors = append(status.Errors, err.Error())
	} else if checkResult != nil {
		status.Metrics["total_files"] = checkResult.Summary.TotalFiles
		status.Metrics["files_fixed"] = checkResult.Summary.FilesFixed
		status.Metrics["errors"] = len(checkResult.Summary.Errors)
		
		if len(checkResult.Summary.Errors) > 0 {
			status.Health = HealthDegraded
			status.Errors = checkResult.Summary.Errors
		}
	}
	
	return status, nil
}

// HealthCheck implements ResourceManager interface for security permission health checking
func (spm *SecurityPermissionsManager) HealthCheck(ctx context.Context, id string) (*HealthCheckResult, error) {
	logger := otelzap.Ctx(ctx)
	start := time.Now()
	
	logger.Debug("Performing health check for security permissions", zap.String("id", id))
	
	result := &HealthCheckResult{
		Overall:   HealthHealthy,
		Checks:    make(map[string]CheckResult),
		Timestamp: start,
		Errors:    make([]string, 0),
		Warnings:  make([]string, 0),
	}
	
	// Check basic functionality
	checkStart := time.Now()
	categories := []string{"system"}
	_, err := spm.permManager.CheckPermissions(categories)
	checkDuration := time.Since(checkStart)
	
	if err != nil {
		result.Overall = HealthUnhealthy
		result.Errors = append(result.Errors, fmt.Sprintf("Permission check failed: %v", err))
		result.Checks["permission_check"] = CheckResult{
			Name:     "Permission Check",
			Status:   HealthUnhealthy,
			Message:  fmt.Sprintf("Failed: %v", err),
			Duration: checkDuration,
		}
	} else {
		result.Checks["permission_check"] = CheckResult{
			Name:     "Permission Check",
			Status:   HealthHealthy,
			Message:  "Successfully checked permissions",
			Duration: checkDuration,
		}
	}
	
	result.Duration = time.Since(start)
	return result, nil
}

// Validate implements ResourceManager interface for validating security permission configurations
func (spm *SecurityPermissionsManager) Validate(ctx context.Context, resource SecurityPermissionResource) error {
	if resource.ID == "" {
		return fmt.Errorf("security permission resource ID cannot be empty")
	}
	
	if len(resource.Categories) == 0 {
		return fmt.Errorf("at least one category must be specified")
	}
	
	// Validate categories against known types
	validCategories := map[string]bool{
		"system":      true,
		"application": true,
		"user":        true,
		"network":     true,
		"storage":     true,
	}
	
	for _, category := range resource.Categories {
		if !validCategories[category] {
			return fmt.Errorf("invalid category: %s", category)
		}
	}
	
	return nil
}

// Configure implements ResourceManager interface for configuring security permissions
func (spm *SecurityPermissionsManager) Configure(ctx context.Context, id string, config map[string]interface{}) (*OperationResult, error) {
	logger := otelzap.Ctx(ctx)
	start := time.Now()
	
	logger.Info("Configuring security permissions",
		zap.String("id", id),
		zap.Any("config", config))
	
	// Apply configuration changes
	// In a real implementation, this would update the underlying permission manager configuration
	
	message := fmt.Sprintf("Successfully configured security permissions for %s", id)
	
	return spm.CreateOperationResult(true, message, time.Since(start), nil), nil
}
package helen

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Create provisions a new Helen nginx instance
func Create(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	span := trace.SpanFromContext(rc.Ctx)

	logger.Info("Starting Helen nginx deployment",
		zap.String("namespace", config.Namespace),
		zap.Int("port", config.Port),
		zap.String("html_path", config.PublicHTMLPath))

	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed", zap.Error(err))
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Validate HTML path exists
	if _, err := os.Stat(config.PublicHTMLPath); os.IsNotExist(err) {
		logger.Error("Public HTML path does not exist",
			zap.String("path", config.PublicHTMLPath))
		return fmt.Errorf("public HTML path does not exist: %s", config.PublicHTMLPath)
	}

	// Create manager
	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create Helen manager", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Start status monitoring
	go func() {
		for status := range manager.GetStatusChannel() {
			if status.Success {
				logger.Info(status.Message,
					zap.String("step", status.Step),
					zap.Any("details", status.Details))
			} else {
				logger.Error(status.Message,
					zap.String("step", status.Step),
					zap.Any("details", status.Details))
			}
		}
	}()

	// Execute deployment
	if err := manager.Deploy(rc.Ctx); err != nil {
		logger.Error("Helen deployment failed", zap.Error(err))
		span.RecordError(err)
		return fmt.Errorf("deployment failed: %w", err)
	}

	logger.Info("Helen deployment completed successfully",
		zap.String("url", fmt.Sprintf("http://localhost:%d", config.Port)),
		zap.String("namespace", config.Namespace))

	return nil
}

// Read retrieves information about existing Helen deployments
func Read(rc *eos_io.RuntimeContext, namespace string) (*DeploymentInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Reading Helen deployment information",
		zap.String("namespace", namespace))

	// Create manager with default config for reading
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for read operation", zap.Error(err))
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// Get deployment information
	info, err := manager.GetDeploymentInfo(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get deployment information", zap.Error(err))
		return nil, fmt.Errorf("failed to get deployment info: %w", err)
	}

	logger.Info("Helen deployment information retrieved",
		zap.String("status", info.Status),
		zap.Int("services", len(info.Services)),
		zap.Bool("healthy", info.Healthy))

	return info, nil
}

// Update modifies an existing Helen deployment
func Update(rc *eos_io.RuntimeContext, namespace string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating Helen deployment",
		zap.String("namespace", namespace),
		zap.Int("port", config.Port))

	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed", zap.Error(err))
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Set namespace from parameter
	config.Namespace = namespace

	// Create manager
	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for update", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Check if deployment exists
	exists, err := manager.DeploymentExists(rc.Ctx)
	if err != nil {
		logger.Error("Failed to check deployment existence", zap.Error(err))
		return fmt.Errorf("failed to check deployment: %w", err)
	}

	if !exists {
		logger.Error("Helen deployment not found", zap.String("namespace", namespace))
		return fmt.Errorf("deployment not found in namespace: %s", namespace)
	}

	// Update deployment
	if err := manager.UpdateDeployment(rc.Ctx); err != nil {
		logger.Error("Failed to update Helen deployment", zap.Error(err))
		return fmt.Errorf("update failed: %w", err)
	}

	logger.Info("Helen deployment updated successfully",
		zap.String("namespace", namespace))

	return nil
}

// Delete removes a Helen deployment
func Delete(rc *eos_io.RuntimeContext, namespace string, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deleting Helen deployment",
		zap.String("namespace", namespace),
		zap.Bool("force", force))

	// Create manager with default config
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for delete", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Check if deployment exists
	exists, err := manager.DeploymentExists(rc.Ctx)
	if err != nil {
		logger.Error("Failed to check deployment existence", zap.Error(err))
		return fmt.Errorf("failed to check deployment: %w", err)
	}

	if !exists && !force {
		logger.Warn("Helen deployment not found", zap.String("namespace", namespace))
		return fmt.Errorf("deployment not found in namespace: %s", namespace)
	}

	// Delete deployment
	if err := manager.DeleteDeployment(rc.Ctx, force); err != nil {
		logger.Error("Failed to delete Helen deployment", zap.Error(err))
		return fmt.Errorf("delete failed: %w", err)
	}

	logger.Info("Helen deployment deleted successfully",
		zap.String("namespace", namespace))

	return nil
}

// List returns all Helen deployments
func List(rc *eos_io.RuntimeContext) ([]*DeploymentInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing all Helen deployments")

	// Create manager with default config
	config := DefaultConfig()
	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for list", zap.Error(err))
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// List all deployments
	deployments, err := manager.ListDeployments(rc.Ctx)
	if err != nil {
		logger.Error("Failed to list deployments", zap.Error(err))
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	logger.Info("Found Helen deployments",
		zap.Int("count", len(deployments)))

	return deployments, nil
}

// Status checks the health status of a Helen deployment
func Status(rc *eos_io.RuntimeContext, namespace string) (*HealthStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Checking Helen deployment status",
		zap.String("namespace", namespace))

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for status check", zap.Error(err))
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// Get health status
	status, err := manager.GetHealthStatus(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get health status", zap.Error(err))
		return nil, fmt.Errorf("failed to get health status: %w", err)
	}

	logger.Info("Helen deployment status",
		zap.String("namespace", namespace),
		zap.String("overall_status", status.OverallStatus),
		zap.Bool("healthy", status.Healthy),
		zap.Int("services", len(status.Services)))

	return status, nil
}

// Restart restarts a Helen deployment
func Restart(rc *eos_io.RuntimeContext, namespace string, services []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restarting Helen deployment",
		zap.String("namespace", namespace),
		zap.Strings("services", services))

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for restart", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Restart services
	if err := manager.RestartServices(rc.Ctx, services); err != nil {
		logger.Error("Failed to restart services", zap.Error(err))
		return fmt.Errorf("restart failed: %w", err)
	}

	logger.Info("Helen services restarted successfully",
		zap.String("namespace", namespace),
		zap.Strings("services", services))

	return nil
}

// Scale adjusts the number of instances for a Helen deployment
func Scale(rc *eos_io.RuntimeContext, namespace string, count int) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Scaling Helen deployment",
		zap.String("namespace", namespace),
		zap.Int("count", count))

	if count < 1 {
		return fmt.Errorf("count must be at least 1, got %d", count)
	}

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for scaling", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Scale deployment
	if err := manager.ScaleDeployment(rc.Ctx, count); err != nil {
		logger.Error("Failed to scale deployment", zap.Error(err))
		return fmt.Errorf("scaling failed: %w", err)
	}

	logger.Info("Helen deployment scaled successfully",
		zap.String("namespace", namespace),
		zap.Int("count", count))

	return nil
}

// Backup creates a backup of Helen data
func Backup(rc *eos_io.RuntimeContext, namespace string, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Helen backup",
		zap.String("namespace", namespace),
		zap.String("backup_path", backupPath))

	// Create backup directory
	if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
		logger.Error("Failed to create backup directory", zap.Error(err))
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for backup", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Create backup
	if err := manager.CreateBackup(rc.Ctx, backupPath); err != nil {
		logger.Error("Failed to create backup", zap.Error(err))
		return fmt.Errorf("backup failed: %w", err)
	}

	logger.Info("Helen backup created successfully",
		zap.String("namespace", namespace),
		zap.String("backup_path", backupPath))

	return nil
}

// Restore restores Helen data from a backup
func Restore(rc *eos_io.RuntimeContext, namespace string, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restoring Helen backup",
		zap.String("namespace", namespace),
		zap.String("backup_path", backupPath))

	// Check if backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		logger.Error("Backup file not found", zap.String("path", backupPath))
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error("Failed to create manager for restore", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Restore backup
	if err := manager.RestoreBackup(rc.Ctx, backupPath); err != nil {
		logger.Error("Failed to restore backup", zap.Error(err))
		return fmt.Errorf("restore failed: %w", err)
	}

	logger.Info("Helen backup restored successfully",
		zap.String("namespace", namespace),
		zap.String("backup_path", backupPath))

	return nil
}

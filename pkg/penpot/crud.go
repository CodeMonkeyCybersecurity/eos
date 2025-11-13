package penpot

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Create provisions a new Penpot instance
func Create(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	span := trace.SpanFromContext(rc.Ctx)

	logger.Info(" Starting Penpot deployment",
		zap.String("namespace", config.Namespace),
		zap.Int("port", config.Port),
		zap.String("work_dir", config.WorkDir))

	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error(" Configuration validation failed", zap.Error(err))
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create manager
	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create Penpot manager", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Start status monitoring
	go func() {
		for status := range manager.GetStatusChannel() {
			if status.Success {
				logger.Info(" "+status.Message,
					zap.String("step", status.Step),
					zap.Any("details", status.Details))
			} else {
				logger.Error(" "+status.Message,
					zap.String("step", status.Step),
					zap.Any("details", status.Details))
			}
		}
	}()

	// Execute deployment
	if err := manager.Deploy(rc.Ctx); err != nil {
		logger.Error(" Penpot deployment failed", zap.Error(err))
		span.RecordError(err)
		return fmt.Errorf("deployment failed: %w", err)
	}

	logger.Info(" Penpot deployment completed successfully",
		zap.String("url", fmt.Sprintf("http://localhost:%d", config.Port)),
		zap.String("namespace", config.Namespace))

	return nil
}

// Read retrieves information about existing Penpot deployments
func Read(rc *eos_io.RuntimeContext, namespace string) (*DeploymentInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("📖 Reading Penpot deployment information",
		zap.String("namespace", namespace))

	// Create manager with default config for reading
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create manager for read operation", zap.Error(err))
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// Get deployment information
	info, err := manager.GetDeploymentInfo(rc.Ctx)
	if err != nil {
		logger.Error(" Failed to get deployment information", zap.Error(err))
		return nil, fmt.Errorf("failed to get deployment info: %w", err)
	}

	logger.Info(" Penpot deployment information retrieved",
		zap.String("status", info.Status),
		zap.Int("services", len(info.Services)),
		zap.Bool("healthy", info.Healthy))

	return info, nil
}

// Update modifies an existing Penpot deployment
func Update(rc *eos_io.RuntimeContext, namespace string, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Updating Penpot deployment",
		zap.String("namespace", namespace),
		zap.Int("port", config.Port))

	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error(" Configuration validation failed", zap.Error(err))
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Set namespace from parameter
	config.Namespace = namespace

	// Create manager
	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create manager for update", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Check if deployment exists
	exists, err := manager.DeploymentExists(rc.Ctx)
	if err != nil {
		logger.Error(" Failed to check deployment existence", zap.Error(err))
		return fmt.Errorf("failed to check deployment: %w", err)
	}

	if !exists {
		logger.Error(" Penpot deployment not found", zap.String("namespace", namespace))
		return fmt.Errorf("deployment not found in namespace: %s", namespace)
	}

	// Update deployment
	if err := manager.UpdateDeployment(rc.Ctx); err != nil {
		logger.Error(" Failed to update Penpot deployment", zap.Error(err))
		return fmt.Errorf("update failed: %w", err)
	}

	logger.Info(" Penpot deployment updated successfully",
		zap.String("namespace", namespace))

	return nil
}

// Delete removes a Penpot deployment
func Delete(rc *eos_io.RuntimeContext, namespace string, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deleting Penpot deployment",
		zap.String("namespace", namespace),
		zap.Bool("force", force))

	// Create manager with default config
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create manager for delete", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Check if deployment exists
	exists, err := manager.DeploymentExists(rc.Ctx)
	if err != nil {
		logger.Error(" Failed to check deployment existence", zap.Error(err))
		return fmt.Errorf("failed to check deployment: %w", err)
	}

	if !exists && !force {
		logger.Warn(" Penpot deployment not found", zap.String("namespace", namespace))
		return fmt.Errorf("deployment not found in namespace: %s", namespace)
	}

	// Delete deployment
	if err := manager.DeleteDeployment(rc.Ctx, force); err != nil {
		logger.Error(" Failed to delete Penpot deployment", zap.Error(err))
		return fmt.Errorf("delete failed: %w", err)
	}

	logger.Info(" Penpot deployment deleted successfully",
		zap.String("namespace", namespace))

	return nil
}

// List returns all Penpot deployments
func List(rc *eos_io.RuntimeContext) ([]*DeploymentInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Listing all Penpot deployments")

	// Create manager with default config
	config := DefaultConfig()
	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create manager for list", zap.Error(err))
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// List all deployments
	deployments, err := manager.ListDeployments(rc.Ctx)
	if err != nil {
		logger.Error(" Failed to list deployments", zap.Error(err))
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	logger.Info(" Found Penpot deployments",
		zap.Int("count", len(deployments)))

	return deployments, nil
}

// Status checks the health status of a Penpot deployment
func Status(rc *eos_io.RuntimeContext, namespace string) (*HealthStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Checking Penpot deployment status",
		zap.String("namespace", namespace))

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create manager for status check", zap.Error(err))
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// Get health status
	status, err := manager.GetHealthStatus(rc.Ctx)
	if err != nil {
		logger.Error(" Failed to get health status", zap.Error(err))
		return nil, fmt.Errorf("failed to get health status: %w", err)
	}

	logger.Info(" Penpot deployment status",
		zap.String("namespace", namespace),
		zap.String("overall_status", status.OverallStatus),
		zap.Bool("healthy", status.Healthy),
		zap.Int("services", len(status.Services)))

	return status, nil
}

// Restart restarts a Penpot deployment
func Restart(rc *eos_io.RuntimeContext, namespace string, services []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Restarting Penpot deployment",
		zap.String("namespace", namespace),
		zap.Strings("services", services))

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create manager for restart", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Restart services
	if err := manager.RestartServices(rc.Ctx, services); err != nil {
		logger.Error(" Failed to restart services", zap.Error(err))
		return fmt.Errorf("restart failed: %w", err)
	}

	logger.Info(" Penpot services restarted successfully",
		zap.String("namespace", namespace),
		zap.Strings("services", services))

	return nil
}

// Scale adjusts the number of instances for a Penpot deployment
func Scale(rc *eos_io.RuntimeContext, namespace string, count int) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Scaling Penpot deployment",
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
		logger.Error(" Failed to create manager for scaling", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Scale deployment
	if err := manager.ScaleDeployment(rc.Ctx, count); err != nil {
		logger.Error(" Failed to scale deployment", zap.Error(err))
		return fmt.Errorf("scaling failed: %w", err)
	}

	logger.Info(" Penpot deployment scaled successfully",
		zap.String("namespace", namespace),
		zap.Int("count", count))

	return nil
}

// Backup creates a backup of Penpot data
func Backup(rc *eos_io.RuntimeContext, namespace string, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Creating Penpot backup",
		zap.String("namespace", namespace),
		zap.String("backup_path", backupPath))

	// Create backup directory
	if err := os.MkdirAll(filepath.Dir(backupPath), shared.ServiceDirPerm); err != nil {
		logger.Error(" Failed to create backup directory", zap.Error(err))
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create manager for backup", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Create backup
	if err := manager.CreateBackup(rc.Ctx, backupPath); err != nil {
		logger.Error(" Failed to create backup", zap.Error(err))
		return fmt.Errorf("backup failed: %w", err)
	}

	logger.Info(" Penpot backup created successfully",
		zap.String("namespace", namespace),
		zap.String("backup_path", backupPath))

	return nil
}

// Restore restores Penpot data from a backup
func Restore(rc *eos_io.RuntimeContext, namespace string, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Restoring Penpot backup",
		zap.String("namespace", namespace),
		zap.String("backup_path", backupPath))

	// Check if backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		logger.Error(" Backup file not found", zap.String("path", backupPath))
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	// Create manager
	config := DefaultConfig()
	config.Namespace = namespace

	manager, err := NewManager(config)
	if err != nil {
		logger.Error(" Failed to create manager for restore", zap.Error(err))
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Restore backup
	if err := manager.RestoreBackup(rc.Ctx, backupPath); err != nil {
		logger.Error(" Failed to restore backup", zap.Error(err))
		return fmt.Errorf("restore failed: %w", err)
	}

	logger.Info(" Penpot backup restored successfully",
		zap.String("namespace", namespace),
		zap.String("backup_path", backupPath))

	return nil
}

// DeploymentInfo represents information about a Penpot deployment
type DeploymentInfo struct {
	Namespace string         `json:"namespace"`
	Status    string         `json:"status"`
	Healthy   bool           `json:"healthy"`
	Port      int            `json:"port"`
	Services  []ServiceInfo  `json:"services"`
	Resources ResourceConfig `json:"resources"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
	URL       string         `json:"url"`
	Version   string         `json:"version"`
}

// ServiceInfo represents information about a service
type ServiceInfo struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Healthy bool   `json:"healthy"`
	Port    int    `json:"port"`
	Image   string `json:"image"`
}

// HealthStatus represents the health status of a deployment
type HealthStatus struct {
	Namespace     string              `json:"namespace"`
	OverallStatus string              `json:"overall_status"`
	Healthy       bool                `json:"healthy"`
	Services      []ServiceHealthInfo `json:"services"`
	LastCheck     string              `json:"last_check"`
	CheckDuration string              `json:"check_duration"`
}

// ServiceHealthInfo represents health information for a service
type ServiceHealthInfo struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	Healthy       bool   `json:"healthy"`
	ChecksPassing int    `json:"checks_passing"`
	ChecksTotal   int    `json:"checks_total"`
	LastCheck     string `json:"last_check"`
	Message       string `json:"message,omitempty"`
}

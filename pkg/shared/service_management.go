// pkg/shared/service_management.go

package shared

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceManager provides enhanced service management capabilities
type ServiceManager struct {
	registry *DelphiServiceRegistry
}

// NewServiceManager creates a new service manager
func NewServiceManager() *ServiceManager {
	return &ServiceManager{
		registry: GetGlobalDelphiServiceRegistry(),
	}
}

// EnhancedServiceStatus provides comprehensive service status information
type EnhancedServiceStatus struct {
	ServiceInstallationStatus
	SystemdActive  bool   `json:"systemd_active"`
	SystemdEnabled bool   `json:"systemd_enabled"`
	SystemdStatus  string `json:"systemd_status"`
	CanInstall     bool   `json:"can_install"`
	InstallCommand string `json:"install_command"`
}

// GetEnhancedServiceStatus returns comprehensive status for a service
func (sm *ServiceManager) GetEnhancedServiceStatus(ctx context.Context, serviceName string) (EnhancedServiceStatus, error) {
	logger := otelzap.Ctx(ctx)
	
	// Get basic installation status
	basicStatus, err := sm.registry.CheckServiceInstallationStatus(serviceName)
	if err != nil {
		return EnhancedServiceStatus{}, err
	}
	
	enhancedStatus := EnhancedServiceStatus{
		ServiceInstallationStatus: basicStatus,
		CanInstall:               true,
		InstallCommand:           fmt.Sprintf("eos delphi services create %s", serviceName),
	}
	
	// Check systemd status if service is installed
	if basicStatus.ServiceInstalled {
		// Check if service is active
		if isActive, err := sm.isServiceActive(serviceName); err == nil {
			enhancedStatus.SystemdActive = isActive
		}
		
		// Check if service is enabled
		if isEnabled, err := sm.isServiceEnabled(serviceName); err == nil {
			enhancedStatus.SystemdEnabled = isEnabled
		}
		
		// Get detailed systemd status
		if status, err := sm.getServiceStatus(serviceName); err == nil {
			enhancedStatus.SystemdStatus = status
		}
	}
	
	logger.Debug("Enhanced service status check completed",
		zap.String("service", serviceName),
		zap.Bool("worker_installed", enhancedStatus.WorkerInstalled),
		zap.Bool("service_installed", enhancedStatus.ServiceInstalled),
		zap.Bool("systemd_active", enhancedStatus.SystemdActive),
		zap.Bool("systemd_enabled", enhancedStatus.SystemdEnabled))
	
	return enhancedStatus, nil
}

// GetServicesRequiringInstallation returns services that need installation with details
func (sm *ServiceManager) GetServicesRequiringInstallation(ctx context.Context) (map[string]EnhancedServiceStatus, error) {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("🔍 Scanning for services requiring installation")
	
	needingInstallation := make(map[string]EnhancedServiceStatus)
	
	for serviceName := range sm.registry.GetActiveServices() {
		status, err := sm.GetEnhancedServiceStatus(ctx, serviceName)
		if err != nil {
			logger.Warn("Failed to check service status",
				zap.String("service", serviceName),
				zap.Error(err))
			continue
		}
		
		if !status.WorkerInstalled || !status.ServiceInstalled {
			needingInstallation[serviceName] = status
		}
	}
	
	logger.Info("📊 Service installation scan completed",
		zap.Int("services_needing_installation", len(needingInstallation)),
		zap.Int("total_services", len(sm.registry.GetActiveServices())))
	
	return needingInstallation, nil
}

// PromptForServiceInstallation prompts user to install missing services
func (sm *ServiceManager) PromptForServiceInstallation(ctx context.Context, missingServices map[string]EnhancedServiceStatus) ([]string, error) {
	logger := otelzap.Ctx(ctx)
	
	if len(missingServices) == 0 {
		return []string{}, nil
	}
	
	logger.Info("🛠️  Missing services detected - installation required",
		zap.Int("missing_count", len(missingServices)))
	
	var servicesToInstall []string
	
	for serviceName, status := range missingServices {
		service, _ := sm.registry.GetService(serviceName)
		
		logger.Info("📋 Missing service details",
			zap.String("service", serviceName),
			zap.String("description", service.Description),
			zap.Bool("worker_installed", status.WorkerInstalled),
			zap.Bool("service_installed", status.ServiceInstalled),
			zap.String("install_command", status.InstallCommand))
		
		servicesToInstall = append(servicesToInstall, serviceName)
	}
	
	// For now, return all services for automatic installation
	// In the future, this could be enhanced with interactive prompts
	logger.Info("🚀 Preparing automatic installation",
		zap.Strings("services_to_install", servicesToInstall))
	
	return servicesToInstall, nil
}

// AutoInstallServices automatically installs missing services
func (sm *ServiceManager) AutoInstallServices(ctx context.Context, servicesToInstall []string) error {
	logger := otelzap.Ctx(ctx)
	
	if len(servicesToInstall) == 0 {
		return nil
	}
	
	logger.Info("🔧 Starting automatic service installation",
		zap.Strings("services", servicesToInstall),
		zap.Int("count", len(servicesToInstall)))
	
	for i, serviceName := range servicesToInstall {
		logger.Info("📦 Installing service",
			zap.String("service", serviceName),
			zap.Int("progress", i+1),
			zap.Int("total", len(servicesToInstall)))
		
		// Execute: eos delphi services create <service-name>
		cmd := exec.CommandContext(ctx, "eos", "delphi", "services", "create", serviceName)
		output, err := cmd.CombinedOutput()
		
		if err != nil {
			logger.Error("❌ Service installation failed",
				zap.String("service", serviceName),
				zap.ByteString("output", output),
				zap.Error(err))
			return fmt.Errorf("failed to install service %s: %w", serviceName, err)
		}
		
		logger.Info("✅ Service installation completed",
			zap.String("service", serviceName),
			zap.ByteString("output", output))
		
		// Enable the service
		enableCmd := exec.CommandContext(ctx, "eos", "delphi", "services", "enable", serviceName)
		enableOutput, enableErr := enableCmd.CombinedOutput()
		
		if enableErr != nil {
			logger.Warn("⚠️  Service enable failed (continuing)",
				zap.String("service", serviceName),
				zap.ByteString("output", enableOutput),
				zap.Error(enableErr))
		} else {
			logger.Info("✅ Service enabled",
				zap.String("service", serviceName))
		}
	}
	
	logger.Info("🎉 Automatic service installation completed",
		zap.Int("services_installed", len(servicesToInstall)))
	
	return nil
}

// Helper functions for systemd checks
func (sm *ServiceManager) isServiceActive(serviceName string) (bool, error) {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(output)) == "active", nil
}

func (sm *ServiceManager) isServiceEnabled(serviceName string) (bool, error) {
	cmd := exec.Command("systemctl", "is-enabled", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	status := strings.TrimSpace(string(output))
	return status == "enabled" || status == "static", nil
}

func (sm *ServiceManager) getServiceStatus(serviceName string) (string, error) {
	cmd := exec.Command("systemctl", "show", serviceName, "--property=ActiveState", "--value")
	output, err := cmd.Output()
	if err != nil {
		return "unknown", err
	}
	return strings.TrimSpace(string(output)), nil
}

// CheckServiceExists checks if a systemd service exists (enhanced version)
func (sm *ServiceManager) CheckServiceExists(serviceName string) bool {
	cmd := exec.Command("systemctl", "cat", serviceName)
	err := cmd.Run()
	return err == nil
}

// GetServiceWorkersForUpdate returns service worker information for update operations
func (sm *ServiceManager) GetServiceWorkersForUpdate() []ServiceWorkerInfo {
	var workers []ServiceWorkerInfo
	timestamp := time.Now().Format("20060102_150405")
	
	for _, service := range sm.registry.GetActiveServices() {
		backupPath := service.WorkerScript + "." + timestamp + ".bak"
		
		workers = append(workers, ServiceWorkerInfo{
			ServiceName:  service.Name,
			SourcePath:   service.SourceWorker,
			TargetPath:   service.WorkerScript,
			ServiceFile:  service.ServiceFile,
			Dependencies: service.Dependencies,
			BackupPath:   backupPath,
		})
	}
	
	return workers
}

// ServiceWorkerInfo represents worker information for compatibility
type ServiceWorkerInfo struct {
	ServiceName  string   `json:"service_name"`
	SourcePath   string   `json:"source_path"`
	TargetPath   string   `json:"target_path"`
	ServiceFile  string   `json:"service_file"`
	Dependencies []string `json:"dependencies"`
	BackupPath   string   `json:"backup_path"` // Generated dynamically with timestamp
}

// Global service manager instance
var globalServiceManager = NewServiceManager()

// GetGlobalServiceManager returns the global service manager
func GetGlobalServiceManager() *ServiceManager {
	return globalServiceManager
}
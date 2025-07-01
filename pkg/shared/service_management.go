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
	registry ServiceRegistryInterface
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
	statusStart := time.Now()

	logger.Debug(" Starting enhanced service status check",
		zap.String("service", serviceName))

	// Get basic installation status
	basicStatusStart := time.Now()
	basicStatus, err := sm.registry.CheckServiceInstallationStatus(serviceName)
	basicStatusDuration := time.Since(basicStatusStart)

	if err != nil {
		logger.Error(" Failed to get basic service status",
			zap.String("service", serviceName),
			zap.Duration("duration", basicStatusDuration),
			zap.Error(err))
		return EnhancedServiceStatus{}, err
	}

	logger.Debug(" Basic service status check completed",
		zap.String("service", serviceName),
		zap.Bool("worker_installed", basicStatus.WorkerInstalled),
		zap.Bool("service_installed", basicStatus.ServiceInstalled),
		zap.Duration("duration", basicStatusDuration))

	enhancedStatus := EnhancedServiceStatus{
		ServiceInstallationStatus: basicStatus,
		CanInstall:                true,
		InstallCommand:            fmt.Sprintf("eos delphi services create %s", serviceName),
	}

	// Check systemd status if service is installed
	if basicStatus.ServiceInstalled {
		systemdStart := time.Now()

		logger.Debug("🔧 Checking systemd status",
			zap.String("service", serviceName))

		// Check if service is active
		activeStart := time.Now()
		if isActive, err := sm.isServiceActive(serviceName); err == nil {
			enhancedStatus.SystemdActive = isActive
			logger.Debug(" Service active check completed",
				zap.String("service", serviceName),
				zap.Bool("is_active", isActive),
				zap.Duration("duration", time.Since(activeStart)))
		} else {
			logger.Warn("  Service active check failed",
				zap.String("service", serviceName),
				zap.Duration("duration", time.Since(activeStart)),
				zap.Error(err))
		}

		// Check if service is enabled
		enabledStart := time.Now()
		if isEnabled, err := sm.isServiceEnabled(serviceName); err == nil {
			enhancedStatus.SystemdEnabled = isEnabled
			logger.Debug(" Service enabled check completed",
				zap.String("service", serviceName),
				zap.Bool("is_enabled", isEnabled),
				zap.Duration("duration", time.Since(enabledStart)))
		} else {
			logger.Warn("  Service enabled check failed",
				zap.String("service", serviceName),
				zap.Duration("duration", time.Since(enabledStart)),
				zap.Error(err))
		}

		// Get detailed systemd status
		statusCheckStart := time.Now()
		if status, err := sm.getServiceStatus(serviceName); err == nil {
			enhancedStatus.SystemdStatus = status
			logger.Debug(" Service status check completed",
				zap.String("service", serviceName),
				zap.String("status", status),
				zap.Duration("duration", time.Since(statusCheckStart)))
		} else {
			logger.Warn("  Service status check failed",
				zap.String("service", serviceName),
				zap.Duration("duration", time.Since(statusCheckStart)),
				zap.Error(err))
		}

		logger.Debug(" All systemd checks completed",
			zap.String("service", serviceName),
			zap.Duration("systemd_checks_duration", time.Since(systemdStart)))
	} else {
		logger.Debug("⏭️  Skipping systemd checks (service not installed)",
			zap.String("service", serviceName))
	}

	totalDuration := time.Since(statusStart)

	logger.Info(" Enhanced service status check completed",
		zap.String("service", serviceName),
		zap.Bool("worker_installed", enhancedStatus.WorkerInstalled),
		zap.Bool("service_installed", enhancedStatus.ServiceInstalled),
		zap.Bool("systemd_active", enhancedStatus.SystemdActive),
		zap.Bool("systemd_enabled", enhancedStatus.SystemdEnabled),
		zap.String("systemd_status", enhancedStatus.SystemdStatus),
		zap.Duration("total_duration", totalDuration))

	return enhancedStatus, nil
}

// GetServicesRequiringInstallation returns services that need installation with details
func (sm *ServiceManager) GetServicesRequiringInstallation(ctx context.Context) (map[string]EnhancedServiceStatus, error) {
	logger := otelzap.Ctx(ctx)

	scanStart := time.Now()
	allServices := sm.registry.GetActiveServices()

	logger.Info(" Starting comprehensive service installation scan",
		zap.Int("total_services", len(allServices)),
		zap.String("scan_phase", "initialization"))

	needingInstallation := make(map[string]EnhancedServiceStatus)

	for i, serviceName := range sm.registry.GetActiveServiceNames() {
		serviceStart := time.Now()

		logger.Info(" Checking service installation status",
			zap.String("service", serviceName),
			zap.Int("progress", i+1),
			zap.Int("total", len(allServices)),
			zap.Duration("elapsed_total", time.Since(scanStart)))

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			logger.Error(" Service installation scan cancelled",
				zap.String("reason", "context_cancelled"),
				zap.Error(ctx.Err()),
				zap.Duration("scan_duration", time.Since(scanStart)),
				zap.Int("services_checked", i))
			return nil, ctx.Err()
		default:
			// Continue with scan
		}

		status, err := sm.GetEnhancedServiceStatus(ctx, serviceName)
		serviceDuration := time.Since(serviceStart)

		if err != nil {
			logger.Error(" Failed to check service status",
				zap.String("service", serviceName),
				zap.Duration("check_duration", serviceDuration),
				zap.Error(err))
			continue
		}

		logger.Info(" Service status check completed",
			zap.String("service", serviceName),
			zap.Bool("worker_installed", status.WorkerInstalled),
			zap.Bool("service_installed", status.ServiceInstalled),
			zap.Bool("systemd_active", status.SystemdActive),
			zap.Bool("systemd_enabled", status.SystemdEnabled),
			zap.Duration("check_duration", serviceDuration))

		if !status.WorkerInstalled || !status.ServiceInstalled {
			needingInstallation[serviceName] = status
			logger.Info(" Service requires installation",
				zap.String("service", serviceName),
				zap.Bool("worker_missing", !status.WorkerInstalled),
				zap.Bool("service_missing", !status.ServiceInstalled))
		}

		// Add progress logging every few services
		if i > 0 && (i+1)%3 == 0 {
			logger.Info(" Service scan progress update",
				zap.Int("services_checked", i+1),
				zap.Int("total_services", len(allServices)),
				zap.Int("needing_installation", len(needingInstallation)),
				zap.Duration("elapsed", time.Since(scanStart)),
				zap.Duration("avg_per_service", time.Since(scanStart)/time.Duration(i+1)))
		}
	}

	scanDuration := time.Since(scanStart)

	logger.Info(" Service installation scan completed",
		zap.Int("services_needing_installation", len(needingInstallation)),
		zap.Int("total_services", len(allServices)),
		zap.Duration("total_scan_duration", scanDuration),
		zap.Duration("avg_per_service", scanDuration/time.Duration(len(allServices))))

	// Log details of services needing installation
	if len(needingInstallation) > 0 {
		var missingServices []string
		for serviceName := range needingInstallation {
			missingServices = append(missingServices, serviceName)
		}
		logger.Info(" Services requiring installation",
			zap.Strings("services", missingServices))
	}

	return needingInstallation, nil
}

// PromptForServiceInstallation prompts user to install missing services
func (sm *ServiceManager) PromptForServiceInstallation(ctx context.Context, missingServices map[string]EnhancedServiceStatus) ([]string, error) {
	logger := otelzap.Ctx(ctx)

	if len(missingServices) == 0 {
		return []string{}, nil
	}

	logger.Info(" Missing services detected - installation required",
		zap.Int("missing_count", len(missingServices)))

	var servicesToInstall []string

	for serviceName, status := range missingServices {
		service, _ := sm.registry.GetService(serviceName)

		logger.Info(" Missing service details",
			zap.String("service", serviceName),
			zap.String("description", service.Description),
			zap.Bool("worker_installed", status.WorkerInstalled),
			zap.Bool("service_installed", status.ServiceInstalled),
			zap.String("install_command", status.InstallCommand))

		servicesToInstall = append(servicesToInstall, serviceName)
	}

	// For now, return all services for automatic installation
	// In the future, this could be enhanced with interactive prompts
	logger.Info(" Preparing automatic installation",
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
		logger.Info(" Installing service",
			zap.String("service", serviceName),
			zap.Int("progress", i+1),
			zap.Int("total", len(servicesToInstall)))

		// Execute: eos delphi services create <service-name>
		cmd := exec.CommandContext(ctx, "eos", "delphi", "services", "create", serviceName)
		output, err := cmd.CombinedOutput()

		if err != nil {
			logger.Error(" Service installation failed",
				zap.String("service", serviceName),
				zap.ByteString("output", output),
				zap.Error(err))
			return fmt.Errorf("failed to install service %s: %w", serviceName, err)
		}

		logger.Info(" Service installation completed",
			zap.String("service", serviceName),
			zap.ByteString("output", output))

		// Enable the service
		enableCmd := exec.CommandContext(ctx, "eos", "delphi", "services", "enable", serviceName)
		enableOutput, enableErr := enableCmd.CombinedOutput()

		if enableErr != nil {
			logger.Warn("  Service enable failed (continuing)",
				zap.String("service", serviceName),
				zap.ByteString("output", enableOutput),
				zap.Error(enableErr))
		} else {
			logger.Info(" Service enabled",
				zap.String("service", serviceName))
		}
	}

	logger.Info(" Automatic service installation completed",
		zap.Int("services_installed", len(servicesToInstall)))

	return nil
}

// Helper functions for systemd checks
func (sm *ServiceManager) isServiceActive(serviceName string) (bool, error) {
	start := time.Now()
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	duration := time.Since(start)

	if duration > 5*time.Second {
		// Log slow systemctl commands - this might indicate a problem
		fmt.Printf("SLOW: systemctl is-active %s took %v\n", serviceName, duration)
	}

	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(output)) == "active", nil
}

func (sm *ServiceManager) isServiceEnabled(serviceName string) (bool, error) {
	start := time.Now()
	cmd := exec.Command("systemctl", "is-enabled", serviceName)
	output, err := cmd.Output()
	duration := time.Since(start)

	if duration > 5*time.Second {
		fmt.Printf("SLOW: systemctl is-enabled %s took %v\n", serviceName, duration)
	}

	if err != nil {
		return false, err
	}
	status := strings.TrimSpace(string(output))
	return status == "enabled" || status == "static", nil
}

func (sm *ServiceManager) getServiceStatus(serviceName string) (string, error) {
	start := time.Now()
	cmd := exec.Command("systemctl", "show", serviceName, "--property=ActiveState", "--value")
	output, err := cmd.Output()
	duration := time.Since(start)

	if duration > 5*time.Second {
		fmt.Printf("SLOW: systemctl show %s took %v\n", serviceName, duration)
	}

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

		// Add dependency workers that need to be updated together
		workers = append(workers, sm.getDependencyWorkers(service, timestamp)...)
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

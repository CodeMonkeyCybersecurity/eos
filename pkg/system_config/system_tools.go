// pkg/system_config/system_tools.go
package system_config

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemToolsManager handles system tools installation and configuration
type SystemToolsManager struct {
	config *SystemToolsConfig
	rc     *eos_io.RuntimeContext
}

// NewSystemToolsManager creates a new SystemToolsManager instance
func NewSystemToolsManager(rc *eos_io.RuntimeContext, config *SystemToolsConfig) *SystemToolsManager {
	if config == nil {
		config = &SystemToolsConfig{
			UpdateSystem:    true,
			InstallPackages: true,
			InstallNpm:      false,
			InstallZx:       false,
			ConfigureUFW:    false,
			SetupSensors:    false,
			Interactive:     false,
			Packages: []string{
				"nfs-kernel-server", "nfs-common",
				"mailutils", "lm-sensors",
				"gh", "tree", "ncdu", "ssh", "nmap", "wireguard",
				"htop", "iftop", "iotop", "nload", "glances",
				"prometheus", "git", "fzf", "python3-pip",
				"nginx", "borgbackup", "etckeeper", "ufw",
			},
		}
	}
	return &SystemToolsManager{
		config: config,
		rc:     rc,
	}
}

// GetType returns the configuration type
func (stm *SystemToolsManager) GetType() ConfigurationType {
	return ConfigTypeSystemTools
}

// Validate validates the system tools configuration
func (stm *SystemToolsManager) Validate() error {
	// Check if running as root for system modifications
	if stm.config.UpdateSystem || stm.config.InstallPackages {
		if err := CheckRoot(); err != nil {
			return fmt.Errorf("system tools configuration requires root privileges: %w", err)
		}
	}

	// Check dependencies
	dependencies := []string{"apt", "systemctl"}
	if stm.config.InstallNpm {
		dependencies = append(dependencies, "npm")
	}

	depStatus := CheckDependencies(dependencies)
	for _, dep := range depStatus {
		if dep.Required && !dep.Available {
			return fmt.Errorf("required dependency not available: %s", dep.Name)
		}
	}

	return nil
}

// Backup creates a backup of system state before modifications
func (stm *SystemToolsManager) Backup() (*ConfigurationBackup, error) {
	logger := otelzap.Ctx(stm.rc.Ctx)
	
	backup := &ConfigurationBackup{
		ID:        fmt.Sprintf("system-tools-%d", time.Now().Unix()),
		Type:      ConfigTypeSystemTools,
		Timestamp: time.Now(),
		Files:     make(map[string]string),
		Services:  make(map[string]ServiceState),
		Packages:  make(map[string]PackageState),
		Metadata:  make(map[string]interface{}),
	}

	logger.Info("Creating system tools backup")

	// Backup package list
	if stm.config.InstallPackages {
		for _, pkg := range stm.config.Packages {
			state, err := CheckPackageInstalled(pkg)
			if err != nil {
				logger.Warn("Failed to check package state", zap.String("package", pkg), zap.Error(err))
			}
			backup.Packages[pkg] = state
		}
	}

	// Backup service states for packages that install services
	servicePackages := map[string]string{
		"nginx":             "nginx",
		"ufw":              "ufw",
		"nfs-kernel-server": "nfs-kernel-server",
		"prometheus":        "prometheus",
	}

	for pkg, service := range servicePackages {
		if contains(stm.config.Packages, pkg) {
			state, err := CheckServiceStatus(service)
			if err != nil {
				logger.Warn("Failed to check service state", zap.String("service", service), zap.Error(err))
			}
			backup.Services[service] = state
		}
	}

	return backup, nil
}

// Apply applies the system tools configuration
func (stm *SystemToolsManager) Apply() (*ConfigurationResult, error) {
	logger := otelzap.Ctx(stm.rc.Ctx)
	
	start := time.Now()
	result := &ConfigurationResult{
		Type:      ConfigTypeSystemTools,
		Timestamp: start,
		Steps:     make([]ConfigurationStep, 0),
		Changes:   make([]ConfigurationChange, 0),
		Warnings:  make([]string, 0),
	}

	logger.Info("Applying system tools configuration")

	// Step 1: Update system
	if stm.config.UpdateSystem {
		if err := stm.updateSystem(result); err != nil {
			result.Success = false
			result.Error = err.Error()
			result.Duration = time.Since(start)
			return result, err
		}
	}

	// Step 2: Install packages
	if stm.config.InstallPackages {
		if err := stm.installPackages(result); err != nil {
			result.Success = false
			result.Error = err.Error()
			result.Duration = time.Since(start)
			return result, err
		}
	}

	// Step 3: Install npm and zx (optional)
	if stm.config.InstallNpm {
		if err := stm.installNpmTools(result); err != nil {
			logger.Warn("Failed to install npm tools", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("npm tools installation failed: %v", err))
		}
	}

	// Step 4: Configure UFW (optional)
	if stm.config.ConfigureUFW {
		if err := stm.configureUFW(result); err != nil {
			logger.Warn("Failed to configure UFW", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("UFW configuration failed: %v", err))
		}
	}

	// Step 5: Setup sensors (optional)
	if stm.config.SetupSensors {
		if err := stm.setupSensors(result); err != nil {
			logger.Warn("Failed to setup sensors", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("sensors setup failed: %v", err))
		}
	}

	result.Success = true
	result.Message = "System tools configuration applied successfully"
	result.Duration = time.Since(start)

	logger.Info("System tools configuration completed", zap.Duration("duration", result.Duration))

	return result, nil
}

// updateSystem performs system update and cleanup
func (stm *SystemToolsManager) updateSystem(result *ConfigurationResult) error {
	step := ConfigurationStep{
		Name:        "System Update",
		Description: "Updating system packages and performing cleanup",
		Status:      "running",
	}
	stepStart := time.Now()

	if err := RunCommand(stm.rc, "apt update", "apt", "update"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	if err := RunCommand(stm.rc, "apt dist-upgrade", "apt", "dist-upgrade", "-y"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	if err := RunCommand(stm.rc, "apt autoremove", "apt", "autoremove", "-y"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	if err := RunCommand(stm.rc, "apt autoclean", "apt", "autoclean", "-y"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "system",
		Target:      "packages",
		Action:      "updated",
		Description: "System packages updated and cleaned",
	})

	return nil
}

// installPackages installs the configured packages
func (stm *SystemToolsManager) installPackages(result *ConfigurationResult) error {
	step := ConfigurationStep{
		Name:        "Install Packages",
		Description: "Installing required system packages",
		Status:      "running",
	}
	stepStart := time.Now()

	// Prepare apt install command
	args := []string{"install", "-y", "--fix-missing"}
	args = append(args, stm.config.Packages...)

	if err := RunCommand(stm.rc, "install packages", "apt", args...); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "packages",
		Target:      strings.Join(stm.config.Packages, ", "),
		Action:      "installed",
		Description: fmt.Sprintf("Installed %d packages", len(stm.config.Packages)),
	})

	return nil
}

// installNpmTools installs npm and zx if requested
func (stm *SystemToolsManager) installNpmTools(result *ConfigurationResult) error {
	step := ConfigurationStep{
		Name:        "Install NPM Tools",
		Description: "Installing npm and zx for scripting",
		Status:      "running",
	}
	stepStart := time.Now()

	// Install npm if not present
	if err := RunCommand(stm.rc, "install npm", "apt", "install", "-y", "npm"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	// Install zx if requested
	if stm.config.InstallZx {
		if err := RunCommand(stm.rc, "install zx", "npm", "install", "-g", "zx"); err != nil {
			step.Status = "failed"
			step.Error = err.Error()
			step.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, step)
			return err
		}
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "packages",
		Target:      "npm, zx",
		Action:      "installed",
		Description: "NPM and zx scripting tools installed",
	})

	return nil
}

// configureUFW configures UFW firewall
func (stm *SystemToolsManager) configureUFW(result *ConfigurationResult) error {
	step := ConfigurationStep{
		Name:        "Configure UFW",
		Description: "Configuring UFW firewall",
		Status:      "running",
	}
	stepStart := time.Now()

	// Enable UFW
	if err := RunCommand(stm.rc, "enable ufw", "ufw", "--force", "enable"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "service",
		Target:      "ufw",
		Action:      "enabled",
		Description: "UFW firewall enabled",
	})

	return nil
}

// setupSensors configures lm-sensors
func (stm *SystemToolsManager) setupSensors(result *ConfigurationResult) error {
	step := ConfigurationStep{
		Name:        "Setup Sensors",
		Description: "Configuring lm-sensors for hardware monitoring",
		Status:      "running",
	}
	stepStart := time.Now()

	// Run sensors-detect with default answers
	if err := RunCommand(stm.rc, "sensors-detect", "sensors-detect", "--auto"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}

	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)

	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "system",
		Target:      "sensors",
		Action:      "configured",
		Description: "Hardware sensors configured for monitoring",
	})

	return nil
}

// Rollback reverts system tools configuration changes
func (stm *SystemToolsManager) Rollback(backup *ConfigurationBackup) error {
	logger := otelzap.Ctx(stm.rc.Ctx)
	
	logger.Info("Rolling back system tools configuration", zap.String("backup_id", backup.ID))

	// Note: Full rollback of package installation is complex and potentially dangerous
	// For now, we log what would be rolled back
	logger.Warn("System tools rollback is limited - packages remain installed for safety")

	// Restore service states
	for serviceName, originalState := range backup.Services {
		currentState, err := CheckServiceStatus(serviceName)
		if err != nil {
			logger.Warn("Failed to check current service state", zap.String("service", serviceName), zap.Error(err))
			continue
		}

		// Restore enabled state
		if originalState.Enabled != currentState.Enabled {
			action := "disable"
			if originalState.Enabled {
				action = "enable"
			}
			if err := RunCommand(stm.rc, fmt.Sprintf("%s service", action), "systemctl", action, serviceName); err != nil {
				logger.Warn("Failed to restore service enabled state", zap.String("service", serviceName), zap.Error(err))
			}
		}

		// Restore active state
		if originalState.Active != currentState.Active {
			action := "stop"
			if originalState.Active {
				action = "start"
			}
			if err := RunCommand(stm.rc, fmt.Sprintf("%s service", action), "systemctl", action, serviceName); err != nil {
				logger.Warn("Failed to restore service active state", zap.String("service", serviceName), zap.Error(err))
			}
		}
	}

	return nil
}

// Status returns the current status of system tools configuration
func (stm *SystemToolsManager) Status() (*ConfigurationStatus, error) {
	status := &ConfigurationStatus{
		Type:       ConfigTypeSystemTools,
		Configured: true,
		Health: ConfigurationHealth{
			Status: "healthy",
			Checks: make([]HealthCheck, 0),
		},
		Dependencies: CheckDependencies([]string{"apt", "systemctl"}),
		Packages:     make([]PackageStatus, 0),
		Services:     make([]ServiceStatus, 0),
	}

	// Check package status
	for _, pkg := range stm.config.Packages {
		pkgState, err := CheckPackageInstalled(pkg)
		pkgStatus := PackageStatus{
			Name:      pkg,
			Installed: pkgState.Installed,
			Version:   pkgState.Version,
		}
		if err != nil {
			status.Health.Issues = append(status.Health.Issues, HealthIssue{
				Severity:    "warning",
				Description: fmt.Sprintf("Failed to check package %s: %v", pkg, err),
			})
		}
		status.Packages = append(status.Packages, pkgStatus)
	}

	// Check service status for relevant packages
	servicePackages := []string{"nginx", "ufw", "nfs-kernel-server", "prometheus"}
	for _, service := range servicePackages {
		if contains(stm.config.Packages, service) {
			serviceState, err := CheckServiceStatus(service)
			serviceStatus := ServiceStatus{
				Name:    service,
				Enabled: serviceState.Enabled,
				Active:  serviceState.Active,
			}
			if err != nil {
				status.Health.Issues = append(status.Health.Issues, HealthIssue{
					Severity:    "warning",
					Description: fmt.Sprintf("Failed to check service %s: %v", service, err),
				})
			}
			status.Services = append(status.Services, serviceStatus)
		}
	}

	return status, nil
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
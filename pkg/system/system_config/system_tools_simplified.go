// pkg/system_config/system_tools_simplified.go
package system_config

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureSystemTools applies system tools configuration following Assess → Intervene → Evaluate pattern
func ConfigureSystemTools(rc *eos_io.RuntimeContext, config *SystemToolsConfig) (*ConfigurationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing system tools configuration requirements")
	
	// Use default config if not provided
	if config == nil {
		config = DefaultSystemToolsConfig()
	}
	
	// Validate configuration
	if err := ValidateSystemToolsConfig(rc, config); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	
	// INTERVENE
	logger.Info("Applying system tools configuration")
	
	start := time.Now()
	result := &ConfigurationResult{
		Type:      ConfigTypeSystemTools,
		Timestamp: start,
		Steps:     make([]ConfigurationStep, 0),
		Changes:   make([]ConfigurationChange, 0),
		Warnings:  make([]string, 0),
	}
	
	// Update system if requested
	if config.UpdateSystem {
		if err := UpdateSystem(rc, result); err != nil {
			result.Success = false
			result.Error = err.Error()
			result.Duration = time.Since(start)
			return result, err
		}
	}
	
	// Install packages if requested
	if config.InstallPackages && len(config.Packages) > 0 {
		if err := InstallSystemPackages(rc, config.Packages, result); err != nil {
			result.Success = false
			result.Error = err.Error()
			result.Duration = time.Since(start)
			return result, err
		}
	}
	
	// Install npm tools if requested
	if config.InstallNpm {
		if err := InstallNpmTools(rc, config.InstallZx, result); err != nil {
			logger.Warn("Failed to install npm tools", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("npm tools installation failed: %v", err))
		}
	}
	
	// Configure UFW if requested
	if config.ConfigureUFW {
		if err := ConfigureUFW(rc, result); err != nil {
			logger.Warn("Failed to configure UFW", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("UFW configuration failed: %v", err))
		}
	}
	
	// Setup sensors if requested
	if config.SetupSensors {
		if err := SetupSensors(rc, result); err != nil {
			logger.Warn("Failed to setup sensors", zap.Error(err))
			result.Warnings = append(result.Warnings, fmt.Sprintf("sensors setup failed: %v", err))
		}
	}
	
	// EVALUATE
	result.Success = true
	result.Message = "System tools configuration applied successfully"
	result.Duration = time.Since(start)
	
	logger.Info("System tools configuration completed", 
		zap.Duration("duration", result.Duration),
		zap.Int("changes", len(result.Changes)),
		zap.Int("warnings", len(result.Warnings)))
	
	return result, nil
}

// DefaultSystemToolsConfig returns the default configuration
func DefaultSystemToolsConfig() *SystemToolsConfig {
	return &SystemToolsConfig{
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

// ValidateSystemToolsConfig validates the configuration
func ValidateSystemToolsConfig(rc *eos_io.RuntimeContext, config *SystemToolsConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Validating system tools configuration")
	
	// Check if running as root for system modifications
	if config.UpdateSystem || config.InstallPackages {
		if err := CheckRoot(); err != nil {
			return fmt.Errorf("system tools configuration requires root privileges: %w", err)
		}
	}
	
	// Check dependencies
	dependencies := []string{"apt", "systemctl"}
	if config.InstallNpm {
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

// UpdateSystem performs system update and cleanup
func UpdateSystem(rc *eos_io.RuntimeContext, result *ConfigurationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Preparing system update")
	
	step := ConfigurationStep{
		Name:        "System Update",
		Description: "Updating system packages and performing cleanup",
		Status:      "running",
	}
	stepStart := time.Now()
	
	// INTERVENE
	commands := []struct {
		name string
		args []string
	}{
		{"apt update", []string{"apt", "update"}},
		{"apt dist-upgrade", []string{"apt", "dist-upgrade", "-y"}},
		{"apt autoremove", []string{"apt", "autoremove", "-y"}},
		{"apt autoclean", []string{"apt", "autoclean", "-y"}},
	}
	
	for _, cmd := range commands {
		logger.Info("Running system update command", zap.String("command", cmd.name))
		if err := RunCommand(rc, cmd.name, cmd.args[0], cmd.args[1:]...); err != nil {
			step.Status = "failed"
			step.Error = fmt.Sprintf("%s failed: %v", cmd.name, err)
			step.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, step)
			return err
		}
	}
	
	// EVALUATE
	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)
	
	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "system",
		Target:      "packages",
		Action:      "updated",
		Description: "System packages updated and cleaned",
	})
	
	logger.Info("System update completed successfully", zap.Duration("duration", step.Duration))
	return nil
}

// InstallSystemPackages installs the specified packages
func InstallSystemPackages(rc *eos_io.RuntimeContext, packages []string, result *ConfigurationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Preparing to install packages", zap.Int("count", len(packages)))
	
	if len(packages) == 0 {
		return nil
	}
	
	step := ConfigurationStep{
		Name:        "Install Packages",
		Description: fmt.Sprintf("Installing %d system packages", len(packages)),
		Status:      "running",
	}
	stepStart := time.Now()
	
	// INTERVENE
	args := []string{"install", "-y", "--fix-missing"}
	args = append(args, packages...)
	
	logger.Info("Installing packages", zap.Strings("packages", packages))
	if err := RunCommand(rc, "install packages", "apt", args...); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}
	
	// EVALUATE
	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)
	
	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "packages",
		Target:      strings.Join(packages, ", "),
		Action:      "installed",
		Description: fmt.Sprintf("Installed %d packages", len(packages)),
	})
	
	logger.Info("Package installation completed", 
		zap.Int("count", len(packages)),
		zap.Duration("duration", step.Duration))
	
	return nil
}

// InstallNpmTools installs npm and optionally zx
func InstallNpmTools(rc *eos_io.RuntimeContext, installZx bool, result *ConfigurationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Preparing to install npm tools", zap.Bool("install_zx", installZx))
	
	step := ConfigurationStep{
		Name:        "Install NPM Tools",
		Description: "Installing npm and zx for scripting",
		Status:      "running",
	}
	stepStart := time.Now()
	
	// INTERVENE
	// Install npm if not present
	logger.Info("Installing npm")
	if err := RunCommand(rc, "install npm", "apt", "install", "-y", "npm"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}
	
	// Install zx if requested
	if installZx {
		logger.Info("Installing zx globally")
		if err := RunCommand(rc, "install zx", "npm", "install", "-g", "zx"); err != nil {
			step.Status = "failed"
			step.Error = err.Error()
			step.Duration = time.Since(stepStart)
			result.Steps = append(result.Steps, step)
			return err
		}
	}
	
	// EVALUATE
	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)
	
	tools := "npm"
	if installZx {
		tools = "npm, zx"
	}
	
	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "packages",
		Target:      tools,
		Action:      "installed",
		Description: fmt.Sprintf("%s scripting tools installed", tools),
	})
	
	return nil
}

// ConfigureUFW enables and configures UFW firewall
func ConfigureUFW(rc *eos_io.RuntimeContext, result *ConfigurationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Preparing to configure UFW firewall")
	
	step := ConfigurationStep{
		Name:        "Configure UFW",
		Description: "Configuring UFW firewall",
		Status:      "running",
	}
	stepStart := time.Now()
	
	// INTERVENE
	logger.Info("Enabling UFW firewall")
	if err := RunCommand(rc, "enable ufw", "ufw", "--force", "enable"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}
	
	// EVALUATE
	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)
	
	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "service",
		Target:      "ufw",
		Action:      "enabled",
		Description: "UFW firewall enabled",
	})
	
	logger.Info("UFW configuration completed")
	return nil
}

// SetupSensors configures lm-sensors for hardware monitoring
func SetupSensors(rc *eos_io.RuntimeContext, result *ConfigurationResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Preparing to setup hardware sensors")
	
	step := ConfigurationStep{
		Name:        "Setup Sensors",
		Description: "Configuring lm-sensors for hardware monitoring",
		Status:      "running",
	}
	stepStart := time.Now()
	
	// INTERVENE
	logger.Info("Running sensors-detect")
	if err := RunCommand(rc, "sensors-detect", "sensors-detect", "--auto"); err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		step.Duration = time.Since(stepStart)
		result.Steps = append(result.Steps, step)
		return err
	}
	
	// EVALUATE
	step.Status = "completed"
	step.Duration = time.Since(stepStart)
	result.Steps = append(result.Steps, step)
	
	result.Changes = append(result.Changes, ConfigurationChange{
		Type:        "system",
		Target:      "sensors",
		Action:      "configured",
		Description: "Hardware sensors configured for monitoring",
	})
	
	logger.Info("Sensors setup completed")
	return nil
}

// GetSystemToolsStatus returns the current status of system tools
func GetSystemToolsStatus(rc *eos_io.RuntimeContext, config *SystemToolsConfig) (*ConfigurationStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Getting system tools status")
	
	if config == nil {
		config = DefaultSystemToolsConfig()
	}
	
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
	for _, pkg := range config.Packages {
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
		if contains(config.Packages, service) {
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
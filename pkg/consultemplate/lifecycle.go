// pkg/consultemplate/lifecycle.go
//
// Consul Template Lifecycle Management
//
// Orchestrates the complete lifecycle of consul-template services:
// Installation → Configuration → Service Creation → Deployment
//
// Pattern: Assess → Intervene → Evaluate

package consultemplate

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LifecycleManager orchestrates consul-template lifecycle operations
type LifecycleManager struct {
	rc              *eos_io.RuntimeContext
	logger          otelzap.LoggerWithCtx
	installer       *Installer
	configBuilder   *ConfigBuilder
	templateManager *TemplateManager
	systemdManager  *SystemdManager
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(rc *eos_io.RuntimeContext) *LifecycleManager {
	return &LifecycleManager{
		rc:              rc,
		logger:          otelzap.Ctx(rc.Ctx),
		installer:       NewInstaller(rc),
		configBuilder:   NewConfigBuilder(rc),
		templateManager: NewTemplateManager(rc),
		systemdManager:  NewSystemdManager(rc),
	}
}

// DeploymentRequest contains everything needed to deploy a consul-template service
type DeploymentRequest struct {
	// Service configuration
	ServiceName     string
	Description     string
	VaultSecrets    []string          // Vault secret paths to use
	ConsulKeys      []string          // Consul KV keys to use
	OutputFile      string            // Where to render the config
	OutputPerms     os.FileMode       // Permissions for rendered file
	ReloadCommand   string            // Command to run after rendering (optional)
	EnableService   bool              // Enable systemd service to start on boot
	StartService    bool              // Start the service immediately
	ConsulAddr      string            // Consul address (optional, uses default)
	VaultAddr       string            // Vault address (optional, uses default)
	VaultTokenPath  string            // Vault token path (optional, uses default)

	// Advanced options
	CustomTemplate  *TemplateContent  // Custom template (if not using auto-generated .env)
	WaitMin         time.Duration     // Min wait before rendering
	WaitMax         time.Duration     // Max wait before rendering
	BackupExisting  bool              // Backup existing file before overwriting
}

// Deploy deploys a complete consul-template service for an application
//
// This is the main entry point for integrating consul-template with EOS services.
// It handles:
// 1. Ensuring consul-template binary is installed
// 2. Creating template files
// 3. Generating consul-template configuration
// 4. Creating systemd service
// 5. Starting the service
//
// Example:
//   lm := NewLifecycleManager(rc)
//   err := lm.Deploy(&DeploymentRequest{
//       ServiceName: "bionicgpt",
//       Description: "Configuration rendering for BionicGPT",
//       VaultSecrets: []string{
//           "secret/bionicgpt/postgres_password",
//           "secret/bionicgpt/jwt_secret",
//       },
//       ConsulKeys: []string{
//           "config/bionicgpt/log_level",
//           "config/bionicgpt/feature_flags/enable_rag",
//       },
//       OutputFile: "/opt/bionicgpt/.env",
//       OutputPerms: 0640,
//       ReloadCommand: "docker compose -f /opt/bionicgpt/docker-compose.yml up -d --force-recreate",
//       EnableService: true,
//       StartService: true,
//   })
func (lm *LifecycleManager) Deploy(req *DeploymentRequest) error {
	lm.logger.Info("Deploying consul-template service",
		zap.String("service", req.ServiceName))

	// ASSESS - Check prerequisites
	if err := lm.assessDeployment(req); err != nil {
		return fmt.Errorf("deployment assessment failed: %w", err)
	}

	// INTERVENE - Perform deployment
	if err := lm.interveneDeployment(req); err != nil {
		return fmt.Errorf("deployment failed: %w", err)
	}

	// EVALUATE - Verify deployment
	if err := lm.evaluateDeployment(req); err != nil {
		return fmt.Errorf("deployment verification failed: %w", err)
	}

	lm.logger.Info("Consul-template service deployed successfully",
		zap.String("service", req.ServiceName))

	return nil
}

// assessDeployment validates deployment prerequisites
func (lm *LifecycleManager) assessDeployment(req *DeploymentRequest) error {
	lm.logger.Info("Assessing deployment prerequisites",
		zap.String("service", req.ServiceName))

	// Validate request
	if req.ServiceName == "" {
		return fmt.Errorf("service name is required")
	}

	if req.OutputFile == "" {
		return fmt.Errorf("output file is required")
	}

	if req.OutputPerms == 0 {
		req.OutputPerms = RenderedConfigPerm
	}

	// Set defaults
	if req.ConsulAddr == "" {
		req.ConsulAddr = DefaultConsulAddr
	}
	if req.VaultAddr == "" {
		req.VaultAddr = DefaultVaultAddr
	}
	if req.VaultTokenPath == "" {
		req.VaultTokenPath = DefaultVaultTokenPath
	}
	if req.WaitMin == 0 {
		req.WaitMin = DefaultMinWait
	}
	if req.WaitMax == 0 {
		req.WaitMax = DefaultMaxWait
	}

	// Check if consul-template is installed
	if _, err := os.Stat(BinaryPath); err != nil {
		lm.logger.Warn("Consul-template binary not found, will install",
			zap.String("path", BinaryPath))

		// Install consul-template
		installConfig := DefaultInstallConfig()
		if err := lm.installer.Install(installConfig); err != nil {
			return fmt.Errorf("failed to install consul-template: %w", err)
		}
	}

	lm.logger.Info("Deployment prerequisites validated")
	return nil
}

// interveneDeployment performs the actual deployment steps
func (lm *LifecycleManager) interveneDeployment(req *DeploymentRequest) error {
	lm.logger.Info("Performing deployment",
		zap.String("service", req.ServiceName))

	// Step 1: Create template
	var templateContent *TemplateContent
	if req.CustomTemplate != nil {
		templateContent = req.CustomTemplate
	} else {
		// Generate standard .env template
		templateContent = BuildEnvFileTemplate(req.ServiceName, req.VaultSecrets, req.ConsulKeys)
		templateContent.Destination = req.OutputFile
		templateContent.Perms = req.OutputPerms
		templateContent.Command = req.ReloadCommand
	}

	if err := lm.templateManager.CreateTemplate(req.ServiceName, templateContent); err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}

	// Step 2: Build consul-template configuration
	serviceConfig := DefaultServiceConfig(req.ServiceName)
	serviceConfig.ConsulAddr = req.ConsulAddr
	serviceConfig.VaultAddr = req.VaultAddr
	serviceConfig.VaultTokenPath = req.VaultTokenPath
	serviceConfig.WaitMin = req.WaitMin
	serviceConfig.WaitMax = req.WaitMax

	// Add template configuration
	templatePath := GetTemplatePath(req.ServiceName, templateContent.Name+".ctmpl")
	serviceConfig.Templates = []TemplateConfig{
		{
			Source:      templatePath,
			Destination: templateContent.Destination,
			Perms:       templateContent.Perms,
			Command:     templateContent.Command,
			Backup:      req.BackupExisting,
		},
	}

	// Write configuration
	configPath := GetConfigPath(req.ServiceName)
	if err := lm.configBuilder.WriteConfig(serviceConfig, configPath); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Step 3: Create systemd service
	systemdConfig := DefaultSystemdServiceConfig(req.ServiceName)
	if req.Description != "" {
		systemdConfig.Description = req.Description
	}

	if err := lm.systemdManager.CreateService(systemdConfig); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}

	// Step 4: Enable service if requested
	if req.EnableService {
		if err := lm.systemdManager.EnableService(req.ServiceName); err != nil {
			return fmt.Errorf("failed to enable service: %w", err)
		}
	}

	// Step 5: Start service if requested
	if req.StartService {
		if err := lm.systemdManager.StartService(req.ServiceName); err != nil {
			return fmt.Errorf("failed to start service: %w", err)
		}
	}

	lm.logger.Info("Deployment steps completed successfully")
	return nil
}

// evaluateDeployment verifies the deployment was successful
func (lm *LifecycleManager) evaluateDeployment(req *DeploymentRequest) error {
	lm.logger.Info("Verifying deployment",
		zap.String("service", req.ServiceName))

	// Check template file exists
	templates, err := lm.templateManager.ListTemplates(req.ServiceName)
	if err != nil {
		return fmt.Errorf("failed to list templates: %w", err)
	}
	if len(templates) == 0 {
		return fmt.Errorf("no templates found for service")
	}

	// Check configuration file exists
	configPath := GetConfigPath(req.ServiceName)
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("configuration file not found: %w", err)
	}

	// Check systemd service exists
	if !lm.systemdManager.IsServiceEnabled(req.ServiceName) && req.EnableService {
		return fmt.Errorf("service should be enabled but is not")
	}

	// If service should be started, check it's active
	if req.StartService {
		if !lm.systemdManager.IsServiceActive(req.ServiceName) {
			// Give it a moment to start
			time.Sleep(2 * time.Second)
			if !lm.systemdManager.IsServiceActive(req.ServiceName) {
				// Get logs for troubleshooting
				logs, _ := lm.systemdManager.GetServiceLogs(req.ServiceName, 50)
				return fmt.Errorf("service is not active\n\nRecent logs:\n%s", logs)
			}
		}

		lm.logger.Info("Service is active",
			zap.String("service", req.ServiceName))
	}

	lm.logger.Info("Deployment verification passed")
	return nil
}

// Undeploy removes a consul-template service completely
func (lm *LifecycleManager) Undeploy(serviceName string) error {
	lm.logger.Info("Undeploying consul-template service",
		zap.String("service", serviceName))

	// Stop and remove systemd service
	if err := lm.systemdManager.RemoveService(serviceName); err != nil {
		lm.logger.Warn("Failed to remove systemd service",
			zap.String("service", serviceName),
			zap.Error(err))
	}

	// Remove configuration file
	configPath := GetConfigPath(serviceName)
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		lm.logger.Warn("Failed to remove configuration",
			zap.String("path", configPath),
			zap.Error(err))
	}

	// Remove template directory
	templateDir := GetTemplatePath(serviceName, "")
	if err := os.RemoveAll(templateDir); err != nil {
		lm.logger.Warn("Failed to remove template directory",
			zap.String("path", templateDir),
			zap.Error(err))
	}

	lm.logger.Info("Service undeployed successfully",
		zap.String("service", serviceName))

	return nil
}

// UpdateService updates an existing consul-template service
func (lm *LifecycleManager) UpdateService(req *DeploymentRequest) error {
	lm.logger.Info("Updating consul-template service",
		zap.String("service", req.ServiceName))

	// Redeploy with new configuration
	if err := lm.Deploy(req); err != nil {
		return fmt.Errorf("failed to update service: %w", err)
	}

	// Restart to apply changes
	if err := lm.systemdManager.RestartService(req.ServiceName); err != nil {
		return fmt.Errorf("failed to restart service: %w", err)
	}

	lm.logger.Info("Service updated successfully",
		zap.String("service", req.ServiceName))

	return nil
}

// GetServiceStatus returns the status of a consul-template service
func (lm *LifecycleManager) GetServiceStatus(serviceName string) (*ServiceStatus, error) {
	status := &ServiceStatus{
		ServiceName: serviceName,
	}

	// Check if config exists
	configPath := GetConfigPath(serviceName)
	if _, err := os.Stat(configPath); err == nil {
		status.ConfigExists = true
		status.ConfigPath = configPath
	}

	// Check templates
	templates, err := lm.templateManager.ListTemplates(serviceName)
	if err == nil {
		status.Templates = templates
	}

	// Check systemd service
	status.SystemdEnabled = lm.systemdManager.IsServiceEnabled(serviceName)
	status.SystemdActive = lm.systemdManager.IsServiceActive(serviceName)

	serviceStatus, _ := lm.systemdManager.GetServiceStatus(serviceName)
	status.SystemdStatus = serviceStatus

	return status, nil
}

// ServiceStatus represents the status of a consul-template service
type ServiceStatus struct {
	ServiceName    string
	ConfigExists   bool
	ConfigPath     string
	Templates      []string
	SystemdEnabled bool
	SystemdActive  bool
	SystemdStatus  string
}

// ListServices lists all deployed consul-template services
func (lm *LifecycleManager) ListServices() ([]string, error) {
	return lm.systemdManager.ListServices()
}

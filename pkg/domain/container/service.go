// Package container implements domain services for container management
package container

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ContainerService orchestrates container operations with business logic and auditing
type ContainerService struct {
	containerMgr    ContainerManager
	imageMgr        ImageManager
	volumeMgr       VolumeManager
	networkMgr      NetworkManager
	composeMgr      ComposeManager
	executor        ContainerExecutor
	runtimeMgr      RuntimeManager
	securityMgr     SecurityManager
	monitoringMgr   MonitoringManager
	backupMgr       BackupManager
	templateMgr     TemplateManager
	policyMgr       PolicyManager
	validator       ContainerValidator
	auditRepo       AuditRepository
	configRepo      ConfigRepository
	logger          *zap.Logger
}

// NewContainerService creates a new container domain service
func NewContainerService(
	containerMgr ContainerManager,
	imageMgr ImageManager,
	volumeMgr VolumeManager,
	networkMgr NetworkManager,
	composeMgr ComposeManager,
	executor ContainerExecutor,
	runtimeMgr RuntimeManager,
	securityMgr SecurityManager,
	monitoringMgr MonitoringManager,
	backupMgr BackupManager,
	templateMgr TemplateManager,
	policyMgr PolicyManager,
	validator ContainerValidator,
	auditRepo AuditRepository,
	configRepo ConfigRepository,
	logger *zap.Logger,
) *ContainerService {
	return &ContainerService{
		containerMgr:  containerMgr,
		imageMgr:      imageMgr,
		volumeMgr:     volumeMgr,
		networkMgr:    networkMgr,
		composeMgr:    composeMgr,
		executor:      executor,
		runtimeMgr:    runtimeMgr,
		securityMgr:   securityMgr,
		monitoringMgr: monitoringMgr,
		backupMgr:     backupMgr,
		templateMgr:   templateMgr,
		policyMgr:     policyMgr,
		validator:     validator,
		auditRepo:     auditRepo,
		configRepo:    configRepo,
		logger:        logger,
	}
}

// Container lifecycle operations with validation and auditing

// CreateContainerWithValidation creates a container with comprehensive validation
func (s *ContainerService) CreateContainerWithValidation(ctx context.Context, userID string, spec *ContainerSpec) (*Container, error) {
	start := time.Now()
	
	// Audit the attempt
	defer func() {
		s.auditContainerOperation(ctx, userID, "container.create", spec.Name, start, nil)
	}()

	s.logger.Info("Creating container with validation",
		zap.String("user", userID),
		zap.String("name", spec.Name),
		zap.String("image", spec.Image),
	)

	// Validate container specification
	if err := s.validator.ValidateContainerSpec(spec); err != nil {
		s.logger.Error("Container spec validation failed",
			zap.String("name", spec.Name),
			zap.Error(err),
		)
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Apply security policy if available
	if s.policyMgr != nil {
		config, _ := s.configRepo.GetContainerConfig(ctx)
		if config != nil && config.DefaultSecurityConfig != nil {
			policy := &SecurityPolicy{
				AllowPrivileged: !config.DefaultSecurityConfig.Privileged,
				ReadOnlyRootfs:  config.DefaultSecurityConfig.ReadOnlyRootfs,
			}
			
			result, err := s.policyMgr.EvaluateContainerPolicy(ctx, spec, policy)
			if err != nil {
				return nil, fmt.Errorf("policy evaluation failed: %w", err)
			}
			
			if !result.Allowed {
				s.logger.Warn("Container creation denied by policy",
					zap.String("name", spec.Name),
					zap.Strings("violations", result.Violations),
				)
				return nil, fmt.Errorf("policy violations: %v", result.Violations)
			}
			
			if len(result.Warnings) > 0 {
				s.logger.Warn("Container creation has policy warnings",
					zap.String("name", spec.Name),
					zap.Strings("warnings", result.Warnings),
				)
			}
		}
	}

	// Security validation if available
	if s.securityMgr != nil {
		if err := s.securityMgr.ValidateContainerSecurity(ctx, spec); err != nil {
			s.logger.Error("Security validation failed",
				zap.String("name", spec.Name),
				zap.Error(err),
			)
			return nil, fmt.Errorf("security validation failed: %w", err)
		}

		if err := s.securityMgr.ValidateImageSecurity(ctx, spec.Image); err != nil {
			s.logger.Warn("Image security validation failed",
				zap.String("image", spec.Image),
				zap.Error(err),
			)
			// Continue with warning - don't fail
		}
	}

	// Create the container
	container, err := s.containerMgr.CreateContainer(ctx, spec)
	if err != nil {
		s.logger.Error("Container creation failed",
			zap.String("name", spec.Name),
			zap.Error(err),
		)
		return nil, fmt.Errorf("container creation failed: %w", err)
	}

	s.logger.Info("Container created successfully",
		zap.String("container_id", container.ID),
		zap.String("name", container.Name),
		zap.Duration("duration", time.Since(start)),
	)

	return container, nil
}

// DeployComposeWithValidation deploys a Docker Compose stack with validation
func (s *ContainerService) DeployComposeWithValidation(ctx context.Context, userID string, config *ComposeConfig) error {
	start := time.Now()
	
	defer func() {
		s.auditContainerOperation(ctx, userID, "compose.deploy", getComposeProjectName(config), start, nil)
	}()

	s.logger.Info("Deploying compose stack with validation",
		zap.String("user", userID),
		zap.String("project", getComposeProjectName(config)),
		zap.Int("services", len(config.Services)),
	)

	// Validate compose configuration
	if err := s.validator.ValidateComposeConfig(config); err != nil {
		s.logger.Error("Compose config validation failed", zap.Error(err))
		return fmt.Errorf("validation failed: %w", err)
	}

	// Validate each service's security
	if s.securityMgr != nil {
		for serviceName, service := range config.Services {
			if service.Image != "" {
				if err := s.securityMgr.ValidateImageSecurity(ctx, service.Image); err != nil {
					s.logger.Warn("Service image security validation failed",
						zap.String("service", serviceName),
						zap.String("image", service.Image),
						zap.Error(err),
					)
				}
			}
		}
	}

	// Deploy the compose stack
	if err := s.composeMgr.Deploy(ctx, config); err != nil {
		s.logger.Error("Compose deployment failed", zap.Error(err))
		return fmt.Errorf("deployment failed: %w", err)
	}

	s.logger.Info("Compose stack deployed successfully",
		zap.String("project", getComposeProjectName(config)),
		zap.Duration("duration", time.Since(start)),
	)

	return nil
}

// ExecuteCommandWithPolicy executes a command in a container with policy enforcement
func (s *ContainerService) ExecuteCommandWithPolicy(ctx context.Context, userID, containerID string, config *ExecConfig) (*ExecResult, error) {
	start := time.Now()
	
	defer func() {
		s.auditContainerOperation(ctx, userID, "container.exec", containerID, start, nil)
	}()

	s.logger.Info("Executing command with policy enforcement",
		zap.String("user", userID),
		zap.String("container", containerID),
		zap.Strings("command", config.Command),
	)

	// Validate execution configuration
	if err := s.validator.ValidateExecConfig(config); err != nil {
		s.logger.Error("Exec config validation failed", zap.Error(err))
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Apply execution policy if available
	if s.policyMgr != nil && len(config.PolicyRules) > 0 {
		// Create a basic policy from the rules
		policy := &SecurityPolicy{
			AllowPrivileged: !config.Privileged,
			Rules: make([]PolicyRule, len(config.PolicyRules)),
		}
		
		for i, rule := range config.PolicyRules {
			policy.Rules[i] = PolicyRule{
				Name:      fmt.Sprintf("exec_rule_%d", i),
				Condition: rule,
				Action:    PolicyActionDeny,
				Severity:  PolicySeverityMedium,
			}
		}
		
		result, err := s.policyMgr.EvaluateExecPolicy(ctx, config, policy)
		if err != nil {
			return nil, fmt.Errorf("policy evaluation failed: %w", err)
		}
		
		if !result.Allowed {
			s.logger.Warn("Command execution denied by policy",
				zap.String("container", containerID),
				zap.Strings("violations", result.Violations),
			)
			return nil, fmt.Errorf("policy violations: %v", result.Violations)
		}
	}

	// Execute the command
	result, err := s.executor.ExecuteCommand(ctx, containerID, config)
	if err != nil {
		s.logger.Error("Command execution failed",
			zap.String("container", containerID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("execution failed: %w", err)
	}

	s.logger.Info("Command executed successfully",
		zap.String("container", containerID),
		zap.Int("exit_code", result.ExitCode),
		zap.Duration("duration", result.Duration),
	)

	return result, nil
}

// Monitoring and health operations

// GetContainerHealthStatus retrieves comprehensive container health information
func (s *ContainerService) GetContainerHealthStatus(ctx context.Context, userID, containerID string) (*ContainerHealthReport, error) {
	start := time.Now()
	
	defer func() {
		s.auditContainerOperation(ctx, userID, "container.health", containerID, start, nil)
	}()

	s.logger.Info("Getting container health status",
		zap.String("user", userID),
		zap.String("container", containerID),
	)

	report := &ContainerHealthReport{
		ContainerID: containerID,
		Timestamp:   time.Now(),
	}

	// Get basic container information
	container, err := s.containerMgr.GetContainer(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}
	report.Container = container

	// Get health status if monitoring manager is available
	if s.monitoringMgr != nil {
		health, err := s.monitoringMgr.GetContainerHealth(ctx, containerID)
		if err != nil {
			s.logger.Warn("Failed to get health status", zap.Error(err))
		} else {
			report.Health = health
		}

		// Get resource statistics
		stats, err := s.monitoringMgr.GetContainerStats(ctx, containerID)
		if err != nil {
			s.logger.Warn("Failed to get container stats", zap.Error(err))
		} else {
			report.Stats = stats
		}
	}

	// Perform security scan if available
	if s.securityMgr != nil {
		scan, err := s.securityMgr.ScanContainer(ctx, containerID)
		if err != nil {
			s.logger.Warn("Failed to perform security scan", zap.Error(err))
		} else {
			report.SecurityScan = scan
		}
	}

	s.logger.Info("Container health status retrieved",
		zap.String("container", containerID),
		zap.Duration("duration", time.Since(start)),
	)

	return report, nil
}

// Backup and restore operations

// BackupContainerWithVolumes creates a comprehensive backup of a container and its volumes
func (s *ContainerService) BackupContainerWithVolumes(ctx context.Context, userID, containerID, backupPath string) error {
	start := time.Now()
	
	defer func() {
		s.auditContainerOperation(ctx, userID, "container.backup", containerID, start, nil)
	}()

	s.logger.Info("Creating container backup with volumes",
		zap.String("user", userID),
		zap.String("container", containerID),
		zap.String("backup_path", backupPath),
	)

	if s.backupMgr == nil {
		return fmt.Errorf("backup manager not available")
	}

	// Get container information to identify volumes
	container, err := s.containerMgr.GetContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to get container: %w", err)
	}

	// Backup the container itself
	if err := s.backupMgr.BackupContainer(ctx, containerID, backupPath); err != nil {
		s.logger.Error("Container backup failed", zap.Error(err))
		return fmt.Errorf("container backup failed: %w", err)
	}

	// Backup associated volumes
	if len(container.Volumes) > 0 {
		volumeNames := make([]string, 0, len(container.Volumes))
		for _, vol := range container.Volumes {
			if vol.Type == "volume" {
				volumeNames = append(volumeNames, vol.Source)
			}
		}
		
		if len(volumeNames) > 0 {
			if err := s.backupMgr.BackupVolumes(ctx, volumeNames, backupPath); err != nil {
				s.logger.Error("Volume backup failed", zap.Error(err))
				return fmt.Errorf("volume backup failed: %w", err)
			}
		}
	}

	s.logger.Info("Container backup completed successfully",
		zap.String("container", containerID),
		zap.Duration("duration", time.Since(start)),
	)

	return nil
}

// Network operations with validation

// CreateNetworkWithValidation creates a network with validation and configuration
func (s *ContainerService) CreateNetworkWithValidation(ctx context.Context, userID string, spec *NetworkSpec) (*Network, error) {
	start := time.Now()
	
	defer func() {
		s.auditContainerOperation(ctx, userID, "network.create", spec.Name, start, nil)
	}()

	s.logger.Info("Creating network with validation",
		zap.String("user", userID),
		zap.String("name", spec.Name),
		zap.String("driver", spec.Driver),
	)

	// Apply default configuration if not specified
	config, err := s.configRepo.GetNetworkConfig(ctx)
	if err != nil {
		s.logger.Warn("Failed to get network config", zap.Error(err))
	} else if config != nil {
		if spec.Driver == "" {
			spec.Driver = "bridge" // Default driver
		}
		
		// Apply default IPAM configuration if not specified
		if spec.IPAM == nil && config.DefaultIPv4Subnet != "" {
			spec.IPAM = &NetworkIPAM{
				Driver: "default",
				Config: []NetworkIPAMConfig{
					{
						Subnet: config.DefaultIPv4Subnet,
					},
				},
			}
		}
	}

	// Create the network
	network, err := s.networkMgr.CreateNetwork(ctx, spec)
	if err != nil {
		s.logger.Error("Network creation failed",
			zap.String("name", spec.Name),
			zap.Error(err),
		)
		return nil, fmt.Errorf("network creation failed: %w", err)
	}

	s.logger.Info("Network created successfully",
		zap.String("network_id", network.ID),
		zap.String("name", network.Name),
		zap.Duration("duration", time.Since(start)),
	)

	return network, nil
}

// Template processing operations

// DeployFromTemplate deploys containers from a template with variable substitution
func (s *ContainerService) DeployFromTemplate(ctx context.Context, userID, templatePath string, variables map[string]interface{}) error {
	start := time.Now()
	
	defer func() {
		s.auditContainerOperation(ctx, userID, "template.deploy", templatePath, start, nil)
	}()

	s.logger.Info("Deploying from template",
		zap.String("user", userID),
		zap.String("template", templatePath),
		zap.Int("variables", len(variables)),
	)

	if s.templateMgr == nil {
		return fmt.Errorf("template manager not available")
	}

	// Validate template
	if err := s.templateMgr.ValidateTemplate(ctx, templatePath); err != nil {
		s.logger.Error("Template validation failed", zap.Error(err))
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Process compose template
	config, err := s.templateMgr.ProcessComposeTemplate(ctx, templatePath, variables)
	if err != nil {
		s.logger.Error("Template processing failed", zap.Error(err))
		return fmt.Errorf("template processing failed: %w", err)
	}

	// Deploy the processed configuration
	if err := s.DeployComposeWithValidation(ctx, userID, config); err != nil {
		return fmt.Errorf("template deployment failed: %w", err)
	}

	s.logger.Info("Template deployed successfully",
		zap.String("template", templatePath),
		zap.Duration("duration", time.Since(start)),
	)

	return nil
}

// System operations

// GetSystemStatus retrieves comprehensive system status
func (s *ContainerService) GetSystemStatus(ctx context.Context, userID string) (*SystemStatusReport, error) {
	start := time.Now()
	
	defer func() {
		s.auditContainerOperation(ctx, userID, "system.status", "system", start, nil)
	}()

	s.logger.Info("Getting system status",
		zap.String("user", userID),
	)

	report := &SystemStatusReport{
		Timestamp: time.Now(),
	}

	// Get runtime information
	if s.runtimeMgr != nil {
		runtime, err := s.runtimeMgr.GetRuntimeInfo(ctx)
		if err != nil {
			s.logger.Warn("Failed to get runtime info", zap.Error(err))
		} else {
			report.Runtime = runtime
		}

		// Get system usage
		usage, err := s.runtimeMgr.GetSystemUsage(ctx)
		if err != nil {
			s.logger.Warn("Failed to get system usage", zap.Error(err))
		} else {
			report.Usage = usage
		}
	}

	// Get container summary
	containers, err := s.containerMgr.ListContainers(ctx, nil)
	if err != nil {
		s.logger.Warn("Failed to list containers", zap.Error(err))
	} else {
		report.ContainerSummary = s.summarizeContainers(containers)
	}

	// Get image summary
	if s.imageMgr != nil {
		images, err := s.imageMgr.ListImages(ctx, nil)
		if err != nil {
			s.logger.Warn("Failed to list images", zap.Error(err))
		} else {
			report.ImageSummary = s.summarizeImages(images)
		}
	}

	// Get volume summary
	if s.volumeMgr != nil {
		volumes, err := s.volumeMgr.ListVolumes(ctx, nil)
		if err != nil {
			s.logger.Warn("Failed to list volumes", zap.Error(err))
		} else {
			report.VolumeSummary = s.summarizeVolumes(volumes)
		}
	}

	// Get network summary
	if s.networkMgr != nil {
		networks, err := s.networkMgr.ListNetworks(ctx, nil)
		if err != nil {
			s.logger.Warn("Failed to list networks", zap.Error(err))
		} else {
			report.NetworkSummary = s.summarizeNetworks(networks)
		}
	}

	s.logger.Info("System status retrieved",
		zap.Duration("duration", time.Since(start)),
	)

	return report, nil
}

// Helper methods

func (s *ContainerService) auditContainerOperation(ctx context.Context, userID, action, resource string, start time.Time, err error) {
	if s.auditRepo == nil {
		return
	}

	result := "success"
	errorMsg := ""
	if err != nil {
		result = "failure"
		errorMsg = err.Error()
	}

	event := &ContainerAuditEvent{
		ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp:  time.Now(),
		User:       userID,
		Action:     action,
		Resource:   resource,
		Details:    map[string]string{
			"duration": time.Since(start).String(),
		},
		Result:   result,
		Error:    errorMsg,
		Duration: time.Since(start),
	}

	if auditErr := s.auditRepo.RecordContainerEvent(ctx, event); auditErr != nil {
		s.logger.Error("Failed to record audit event", zap.Error(auditErr))
	}
}

func getComposeProjectName(config *ComposeConfig) string {
	// Extract project name from compose config
	// This would typically be derived from the directory name or specified in the config
	return "compose-project"
}

func (s *ContainerService) summarizeContainers(containers []*Container) *ContainerSummary {
	summary := &ContainerSummary{}
	
	for _, container := range containers {
		summary.Total++
		switch container.Status {
		case ContainerStatusRunning:
			summary.Running++
		case ContainerStatusExited:
			summary.Stopped++
		case ContainerStatusPaused:
			summary.Paused++
		}
	}
	
	return summary
}

func (s *ContainerService) summarizeImages(images []*Image) *ImageSummary {
	summary := &ImageSummary{
		Total: len(images),
	}
	
	var totalSize int64
	for _, image := range images {
		totalSize += image.Size
	}
	summary.TotalSize = totalSize
	
	return summary
}

func (s *ContainerService) summarizeVolumes(volumes []*Volume) *VolumeSummary {
	return &VolumeSummary{
		Total: len(volumes),
	}
}

func (s *ContainerService) summarizeNetworks(networks []*Network) *NetworkSummary {
	summary := &NetworkSummary{
		Total: len(networks),
	}
	
	drivers := make(map[string]int)
	for _, network := range networks {
		drivers[network.Driver]++
	}
	summary.ByDriver = drivers
	
	return summary
}

// Report types for comprehensive status information

// ContainerHealthReport provides comprehensive container health information
type ContainerHealthReport struct {
	ContainerID  string                 `json:"container_id"`
	Timestamp    time.Time              `json:"timestamp"`
	Container    *Container             `json:"container"`
	Health       *HealthStatus          `json:"health,omitempty"`
	Stats        *ContainerStats        `json:"stats,omitempty"`
	SecurityScan *SecurityScanResult    `json:"security_scan,omitempty"`
}

// SystemStatusReport provides comprehensive system status information
type SystemStatusReport struct {
	Timestamp        time.Time         `json:"timestamp"`
	Runtime          *RuntimeInfo      `json:"runtime,omitempty"`
	Usage            *SystemUsage      `json:"usage,omitempty"`
	ContainerSummary *ContainerSummary `json:"container_summary,omitempty"`
	ImageSummary     *ImageSummary     `json:"image_summary,omitempty"`
	VolumeSummary    *VolumeSummary    `json:"volume_summary,omitempty"`
	NetworkSummary   *NetworkSummary   `json:"network_summary,omitempty"`
}

// Summary types for different resource types

type ContainerSummary struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Stopped int `json:"stopped"`
	Paused  int `json:"paused"`
}

type ImageSummary struct {
	Total     int   `json:"total"`
	TotalSize int64 `json:"total_size"`
}

type VolumeSummary struct {
	Total int `json:"total"`
}

type NetworkSummary struct {
	Total    int            `json:"total"`
	ByDriver map[string]int `json:"by_driver"`
}
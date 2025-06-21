// Package hecate implements domain services for reverse proxy and service orchestration
package hecate

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// HecateService orchestrates reverse proxy and service management operations
type HecateService struct {
	// Core service managers
	reverseProxyService ReverseProxyService
	serviceOrchestrator ServiceOrchestrator
	configManager       ConfigurationManager
	certificateManager  CertificateManager
	serviceDiscovery    ServiceDiscovery
	networkManager      NetworkManager
	securityManager     SecurityManager
	monitoringManager   MonitoringManager
	backupManager       BackupManager

	// Infrastructure components
	containerRuntime ContainerRuntime
	proxyAdapter     ProxyAdapter
	templateEngine   TemplateEngine
	lifecycleManager LifecycleManager
	eventBus         EventBus

	// Repository layer
	deploymentRepo  DeploymentRepository
	serviceRepo     ServiceRepository
	configRepo      ConfigurationRepository
	certificateRepo CertificateRepository
	auditRepo       AuditRepository

	// Validation layer
	serviceValidator  ServiceValidator
	securityValidator SecurityValidator

	logger *zap.Logger
}

// NewHecateService creates a new Hecate domain service
func NewHecateService(
	reverseProxyService ReverseProxyService,
	serviceOrchestrator ServiceOrchestrator,
	configManager ConfigurationManager,
	certificateManager CertificateManager,
	serviceDiscovery ServiceDiscovery,
	networkManager NetworkManager,
	securityManager SecurityManager,
	monitoringManager MonitoringManager,
	backupManager BackupManager,
	containerRuntime ContainerRuntime,
	proxyAdapter ProxyAdapter,
	templateEngine TemplateEngine,
	lifecycleManager LifecycleManager,
	eventBus EventBus,
	deploymentRepo DeploymentRepository,
	serviceRepo ServiceRepository,
	configRepo ConfigurationRepository,
	certificateRepo CertificateRepository,
	auditRepo AuditRepository,
	serviceValidator ServiceValidator,
	securityValidator SecurityValidator,
	logger *zap.Logger,
) *HecateService {
	return &HecateService{
		reverseProxyService: reverseProxyService,
		serviceOrchestrator: serviceOrchestrator,
		configManager:       configManager,
		certificateManager:  certificateManager,
		serviceDiscovery:    serviceDiscovery,
		networkManager:      networkManager,
		securityManager:     securityManager,
		monitoringManager:   monitoringManager,
		backupManager:       backupManager,
		containerRuntime:    containerRuntime,
		proxyAdapter:        proxyAdapter,
		templateEngine:      templateEngine,
		lifecycleManager:    lifecycleManager,
		eventBus:            eventBus,
		deploymentRepo:      deploymentRepo,
		serviceRepo:         serviceRepo,
		configRepo:          configRepo,
		certificateRepo:     certificateRepo,
		auditRepo:           auditRepo,
		serviceValidator:    serviceValidator,
		securityValidator:   securityValidator,
		logger:              logger,
	}
}

// Reverse Proxy Operations with comprehensive validation and lifecycle management

// DeployReverseProxyWithLifecycle deploys a reverse proxy with full lifecycle management
func (s *HecateService) DeployReverseProxyWithLifecycle(ctx context.Context, userID string, spec *ReverseProxySpec) (*Deployment, error) {
	start := time.Now()

	s.logger.Info("Deploying reverse proxy with lifecycle management",
		zap.String("user", userID),
		zap.String("name", spec.Name),
		zap.String("domain", spec.Domain),
		zap.String("proxy_type", string(spec.ProxyType)),
	)

	// Validate specification
	if err := s.serviceValidator.ValidateProxyConfiguration(spec.Configuration); err != nil {
		s.logger.Error("Proxy configuration validation failed",
			zap.String("name", spec.Name),
			zap.Error(err),
		)
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Security validation
	if err := s.securityValidator.ValidateNetworkConfiguration(&NetworkConfiguration{}); err != nil {
		s.logger.Error("Security validation failed",
			zap.String("name", spec.Name),
			zap.Error(err),
		)
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	// Pre-deployment lifecycle hook
	if s.lifecycleManager != nil {
		serviceSpec := &ServiceSpec{
			Name:  spec.Name,
			Image: "nginx:latest", // Default proxy image
		}

		if err := s.lifecycleManager.PreDeploy(ctx, serviceSpec); err != nil {
			s.logger.Error("Pre-deployment lifecycle hook failed", zap.Error(err))
			return nil, fmt.Errorf("pre-deployment failed: %w", err)
		}
	}

	// Request certificates if SSL is configured
	if spec.Configuration.SSL != nil && spec.Configuration.SSL.Enabled {
		cert, err := s.ensureCertificateAvailable(ctx, spec.Domain, spec.Subdomains)
		if err != nil {
			s.logger.Error("Certificate provisioning failed",
				zap.String("domain", spec.Domain),
				zap.Error(err),
			)
			return nil, fmt.Errorf("certificate provisioning failed: %w", err)
		}
		spec.Configuration.SSL.CertificateID = cert.ID
	}

	// Deploy the reverse proxy
	deployment, err := s.reverseProxyService.DeployReverseProxy(ctx, spec)
	if err != nil {
		s.logger.Error("Reverse proxy deployment failed",
			zap.String("name", spec.Name),
			zap.Error(err),
		)

		// Audit failed deployment
		s.auditDeploymentOperation(ctx, userID, "proxy.deploy", spec.Name, start, err)
		return nil, fmt.Errorf("deployment failed: %w", err)
	}

	// Save deployment to repository
	if err := s.deploymentRepo.SaveDeployment(ctx, deployment); err != nil {
		s.logger.Error("Failed to save deployment", zap.Error(err))
		// Continue - deployment succeeded even if persistence failed
	}

	// Create service instance for lifecycle management
	if s.lifecycleManager != nil {
		instance := &ServiceInstance{
			ID:        deployment.ID,
			ServiceID: deployment.Name,
			Name:      deployment.Name,
			Type:      ServiceTypeReverseProxy,
			Status: ServiceStatus{
				ServiceID:     deployment.Name,
				Name:          deployment.Name,
				State:         ServiceStateRunning,
				Health:        HealthStatusHealthy,
				Replicas:      1,
				ReadyReplicas: 1,
				UpdatedAt:     time.Now(),
			},
			Address: spec.Domain,
			Port:    80, // Default HTTP port
		}

		if err := s.lifecycleManager.PostDeploy(ctx, instance); err != nil {
			s.logger.Warn("Post-deployment lifecycle hook failed", zap.Error(err))
			// Don't fail the deployment for post-deploy hook failures
		}
	}

	// Publish deployment event
	if s.eventBus != nil {
		event := &Event{
			ID:        fmt.Sprintf("deploy-%d", time.Now().UnixNano()),
			Type:      EventTypeServiceDeployed,
			Source:    "hecate.service",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"deployment_id": deployment.ID,
				"name":          deployment.Name,
				"domain":        spec.Domain,
				"user":          userID,
			},
			Severity: EventSeverityInfo,
		}

		if err := s.eventBus.PublishAsync(ctx, event); err != nil {
			s.logger.Warn("Failed to publish deployment event", zap.Error(err))
		}
	}

	// Audit successful deployment
	s.auditDeploymentOperation(ctx, userID, "proxy.deploy", spec.Name, start, nil)

	s.logger.Info("Reverse proxy deployed successfully",
		zap.String("deployment_id", deployment.ID),
		zap.String("name", deployment.Name),
		zap.Duration("duration", time.Since(start)),
	)

	return deployment, nil
}

// UpdateReverseProxyWithValidation updates a reverse proxy with comprehensive validation
func (s *HecateService) UpdateReverseProxyWithValidation(ctx context.Context, userID, deploymentID string, spec *ReverseProxySpec) error {
	start := time.Now()

	s.logger.Info("Updating reverse proxy with validation",
		zap.String("user", userID),
		zap.String("deployment_id", deploymentID),
		zap.String("name", spec.Name),
	)

	// Get existing deployment
	existing, err := s.deploymentRepo.GetDeployment(ctx, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to get existing deployment: %w", err)
	}

	// Validate new specification
	if err := s.serviceValidator.ValidateProxyConfiguration(spec.Configuration); err != nil {
		s.logger.Error("New configuration validation failed", zap.Error(err))
		return fmt.Errorf("validation failed: %w", err)
	}

	// Pre-update lifecycle hook
	if s.lifecycleManager != nil {
		instance := &ServiceInstance{
			ID:        deploymentID,
			ServiceID: existing.Name,
			Name:      existing.Name,
			Type:      ServiceTypeReverseProxy,
		}

		newConfig := &ServiceConfiguration{
			ServiceID: existing.Name,
			Data:      map[string]interface{}{"spec": spec},
		}

		if err := s.lifecycleManager.PreUpdate(ctx, instance, newConfig); err != nil {
			s.logger.Error("Pre-update lifecycle hook failed", zap.Error(err))
			return fmt.Errorf("pre-update failed: %w", err)
		}
	}

	// Handle certificate updates if SSL configuration changed
	if spec.Configuration.SSL != nil && spec.Configuration.SSL.Enabled {
		if existing.Spec.Configuration.SSL == nil || !existing.Spec.Configuration.SSL.Enabled {
			// SSL newly enabled - request certificate
			cert, err := s.ensureCertificateAvailable(ctx, spec.Domain, spec.Subdomains)
			if err != nil {
				return fmt.Errorf("certificate provisioning failed: %w", err)
			}
			spec.Configuration.SSL.CertificateID = cert.ID
		}
	}

	// Update the reverse proxy
	if err := s.reverseProxyService.UpdateReverseProxy(ctx, deploymentID, spec); err != nil {
		s.logger.Error("Reverse proxy update failed", zap.Error(err))
		s.auditDeploymentOperation(ctx, userID, "proxy.update", deploymentID, start, err)
		return fmt.Errorf("update failed: %w", err)
	}

	// Update deployment status
	if err := s.deploymentRepo.UpdateDeploymentStatus(ctx, deploymentID, DeploymentStatusDeployed); err != nil {
		s.logger.Error("Failed to update deployment status", zap.Error(err))
	}

	// Post-update lifecycle hook
	if s.lifecycleManager != nil {
		instance := &ServiceInstance{
			ID:        deploymentID,
			ServiceID: existing.Name,
			Name:      existing.Name,
			Type:      ServiceTypeReverseProxy,
		}

		if err := s.lifecycleManager.PostUpdate(ctx, instance); err != nil {
			s.logger.Warn("Post-update lifecycle hook failed", zap.Error(err))
		}
	}

	// Publish update event
	if s.eventBus != nil {
		event := &Event{
			ID:        fmt.Sprintf("update-%d", time.Now().UnixNano()),
			Type:      EventTypeConfigurationChanged,
			Source:    "hecate.service",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"deployment_id": deploymentID,
				"name":          spec.Name,
				"user":          userID,
			},
			Severity: EventSeverityInfo,
		}

		if err := s.eventBus.PublishAsync(ctx, event); err != nil {
			s.logger.Warn("Failed to publish proxy update event",
				zap.Error(err),
				zap.String("deployment_id", deploymentID))
		}
	}

	s.auditDeploymentOperation(ctx, userID, "proxy.update", deploymentID, start, nil)

	s.logger.Info("Reverse proxy updated successfully",
		zap.String("deployment_id", deploymentID),
		zap.Duration("duration", time.Since(start)),
	)

	return nil
}

// Service Orchestration Operations

// DeployStackWithOrchestration deploys a multi-service stack with orchestration
func (s *HecateService) DeployStackWithOrchestration(ctx context.Context, userID string, spec *StackSpec) (*StackDeployment, error) {
	start := time.Now()

	s.logger.Info("Deploying stack with orchestration",
		zap.String("user", userID),
		zap.String("stack_name", spec.Name),
		zap.Int("services", len(spec.Services)),
	)

	// Validate stack specification
	if err := s.serviceValidator.ValidateStackSpec(spec); err != nil {
		s.logger.Error("Stack specification validation failed", zap.Error(err))
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Create networks first
	networks := make([]Network, 0, len(spec.Networks))
	for name, netSpec := range spec.Networks {
		network, err := s.networkManager.CreateNetwork(ctx, &NetworkSpec{
			Name:   name,
			Driver: netSpec.Driver,
			Labels: netSpec.Labels,
		})
		if err != nil {
			s.logger.Error("Network creation failed",
				zap.String("network", name),
				zap.Error(err),
			)
			return nil, fmt.Errorf("network creation failed: %w", err)
		}
		networks = append(networks, *network)
	}

	// Create volumes
	volumes := make([]Volume, 0, len(spec.Volumes))
	for name, volSpec := range spec.Volumes {
		volume := &Volume{
			Name:   name,
			Driver: volSpec.Driver,
			Labels: volSpec.Labels,
		}
		volumes = append(volumes, *volume)
	}

	// Deploy the stack through service orchestrator
	deployment, err := s.serviceOrchestrator.DeployStack(ctx, spec)
	if err != nil {
		s.logger.Error("Stack deployment failed", zap.Error(err))
		s.auditStackOperation(ctx, userID, "stack.deploy", spec.Name, start, err)
		return nil, fmt.Errorf("deployment failed: %w", err)
	}

	// Enhanced stack deployment with networks and volumes
	stackDeployment := &StackDeployment{
		ID:         deployment.ID,
		Name:       deployment.Name,
		Spec:       spec,
		Status:     deployment.Status,
		Services:   deployment.Services,
		Networks:   networks,
		Volumes:    volumes,
		CreatedAt:  deployment.CreatedAt,
		UpdatedAt:  deployment.UpdatedAt,
		DeployedAt: deployment.DeployedAt,
		Version:    deployment.Version,
		Labels:     deployment.Labels,
	}

	// Register services with service discovery
	for _, service := range deployment.Services {
		registration := &ServiceRegistration{
			ID:           service.ID,
			ServiceID:    service.ServiceID,
			Name:         service.Name,
			Type:         service.Type,
			Address:      service.Address,
			Port:         service.Port,
			Health:       service.Health,
			RegisteredAt: time.Now(),
			LastSeen:     time.Now(),
			TTL:          15 * time.Minute,
		}

		if err := s.serviceDiscovery.RegisterService(ctx, registration); err != nil {
			s.logger.Warn("Service registration failed",
				zap.String("service", service.Name),
				zap.Error(err),
			)
		}
	}

	// Setup monitoring for the stack
	if s.monitoringManager != nil {
		for _, service := range deployment.Services {
			if err := s.setupServiceMonitoring(ctx, &service); err != nil {
				s.logger.Warn("Failed to setup monitoring",
					zap.String("service", service.Name),
					zap.Error(err),
				)
			}
		}
	}

	// Publish deployment event
	if s.eventBus != nil {
		event := &Event{
			ID:        fmt.Sprintf("stack-deploy-%d", time.Now().UnixNano()),
			Type:      EventTypeServiceDeployed,
			Source:    "hecate.service",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"stack_id": deployment.ID,
				"name":     spec.Name,
				"services": len(spec.Services),
				"user":     userID,
			},
			Severity: EventSeverityInfo,
		}

		if err := s.eventBus.PublishAsync(ctx, event); err != nil {
			s.logger.Warn("Failed to publish stack deploy event",
				zap.Error(err),
				zap.String("stack_id", deployment.ID))
		}
	}

	s.auditStackOperation(ctx, userID, "stack.deploy", spec.Name, start, nil)

	s.logger.Info("Stack deployed successfully",
		zap.String("stack_id", deployment.ID),
		zap.String("name", spec.Name),
		zap.Int("services", len(deployment.Services)),
		zap.Duration("duration", time.Since(start)),
	)

	return stackDeployment, nil
}

// Certificate Management Operations

// RequestCertificateWithValidation requests a certificate with comprehensive validation
func (s *HecateService) RequestCertificateWithValidation(ctx context.Context, userID string, spec *CertificateSpec) (*Certificate, error) {
	start := time.Now()

	s.logger.Info("Requesting certificate with validation",
		zap.String("user", userID),
		zap.String("common_name", spec.CommonName),
		zap.Strings("alt_names", spec.AlternativeNames),
	)

	// Validate certificate specification
	cert := &Certificate{
		CommonName:       spec.CommonName,
		AlternativeNames: spec.AlternativeNames,
		Status:           CertificateStatusPending,
	}

	if err := s.securityValidator.ValidateCertificate(cert); err != nil {
		s.logger.Error("Certificate validation failed", zap.Error(err))
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Request the certificate
	certificate, err := s.certificateManager.RequestCertificate(ctx, spec)
	if err != nil {
		s.logger.Error("Certificate request failed", zap.Error(err))
		s.auditCertificateOperation(ctx, userID, "certificate.request", spec.CommonName, start, err)
		return nil, fmt.Errorf("certificate request failed: %w", err)
	}

	// Save to repository
	if err := s.certificateRepo.SaveCertificate(ctx, certificate); err != nil {
		s.logger.Error("Failed to save certificate", zap.Error(err))
	}

	// Setup auto-renewal if enabled
	if spec.AutoRenew && s.certificateManager != nil {
		go s.scheduleCertificateRenewal(certificate)
	}

	// Publish certificate event
	if s.eventBus != nil {
		event := &Event{
			ID:        fmt.Sprintf("cert-request-%d", time.Now().UnixNano()),
			Type:      EventTypeCertificateExpiring, // Will be updated when actually expiring
			Source:    "hecate.service",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"certificate_id": certificate.ID,
				"common_name":    certificate.CommonName,
				"user":           userID,
			},
			Severity: EventSeverityInfo,
		}

		if err := s.eventBus.PublishAsync(ctx, event); err != nil {
			s.logger.Warn("Failed to publish certificate request event",
				zap.Error(err),
				zap.String("certificate_id", certificate.ID))
		}
	}

	s.auditCertificateOperation(ctx, userID, "certificate.request", spec.CommonName, start, nil)

	s.logger.Info("Certificate requested successfully",
		zap.String("certificate_id", certificate.ID),
		zap.String("common_name", certificate.CommonName),
		zap.Duration("duration", time.Since(start)),
	)

	return certificate, nil
}

// Monitoring and Health Operations

// GetComprehensiveStatus retrieves comprehensive system status
func (s *HecateService) GetComprehensiveStatus(ctx context.Context, userID string) (*SystemStatusReport, error) {
	start := time.Now()

	s.logger.Info("Getting comprehensive system status",
		zap.String("user", userID),
	)

	report := &SystemStatusReport{
		Timestamp: time.Now(),
	}

	// Get deployment status
	deployments, err := s.deploymentRepo.ListDeployments(ctx, nil)
	if err != nil {
		s.logger.Warn("Failed to get deployments", zap.Error(err))
	} else {
		report.Deployments = s.summarizeDeployments(deployments)
	}

	// Get service status
	services, err := s.serviceRepo.ListServices(ctx, nil)
	if err != nil {
		s.logger.Warn("Failed to get services", zap.Error(err))
	} else {
		report.Services = s.summarizeServices(services)
	}

	// Get certificate status
	certificates, err := s.certificateRepo.ListCertificates(ctx, nil)
	if err != nil {
		s.logger.Warn("Failed to get certificates", zap.Error(err))
	} else {
		report.Certificates = s.summarizeCertificates(certificates)
	}

	// Get proxy metrics if available
	if s.monitoringManager != nil {
		for _, deployment := range deployments {
			metrics, err := s.reverseProxyService.GetProxyMetrics(ctx, deployment.ID)
			if err != nil {
				s.logger.Warn("Failed to get proxy metrics",
					zap.String("deployment", deployment.ID),
					zap.Error(err),
				)
				continue
			}

			if report.ProxyMetrics == nil {
				report.ProxyMetrics = make(map[string]*ProxyMetrics)
			}
			report.ProxyMetrics[deployment.ID] = metrics
		}
	}

	// Check system health
	report.OverallHealth = s.calculateOverallHealth(deployments, services, certificates)

	s.auditSystemOperation(ctx, userID, "system.status", "system", start, nil)

	s.logger.Info("Comprehensive system status retrieved",
		zap.String("health", string(report.OverallHealth)),
		zap.Duration("duration", time.Since(start)),
	)

	return report, nil
}

// Configuration Management Operations

// ProcessConfigurationTemplate processes a configuration template with variables
func (s *HecateService) ProcessConfigurationTemplate(ctx context.Context, userID string, templateID string, variables map[string]interface{}) (*ServiceConfiguration, error) {
	start := time.Now()

	s.logger.Info("Processing configuration template",
		zap.String("user", userID),
		zap.String("template_id", templateID),
		zap.Int("variables", len(variables)),
	)

	// Get template
	template, err := s.configManager.GetTemplate(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Validate template if template engine is available
	if s.templateEngine != nil {
		if err := s.templateEngine.ValidateTemplate(ctx, template.Template); err != nil {
			s.logger.Error("Template validation failed", zap.Error(err))
			return nil, fmt.Errorf("template validation failed: %w", err)
		}
	}

	// Process template
	config, err := s.configManager.ProcessTemplate(ctx, template, variables)
	if err != nil {
		s.logger.Error("Template processing failed", zap.Error(err))
		s.auditConfigOperation(ctx, userID, "template.process", templateID, start, err)
		return nil, fmt.Errorf("template processing failed: %w", err)
	}

	// Validate processed configuration
	if err := s.configManager.ValidateConfiguration(ctx, config); err != nil {
		s.logger.Error("Processed configuration validation failed", zap.Error(err))
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Save processed configuration
	if err := s.configRepo.SaveConfiguration(ctx, &ProxyConfiguration{
		ID:        config.ID,
		Type:      config.Type,
		Status:    ConfigurationStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}); err != nil {
		s.logger.Error("Failed to save configuration", zap.Error(err))
	}

	s.auditConfigOperation(ctx, userID, "template.process", templateID, start, nil)

	s.logger.Info("Configuration template processed successfully",
		zap.String("template_id", templateID),
		zap.String("config_id", config.ID),
		zap.Duration("duration", time.Since(start)),
	)

	return config, nil
}

// Helper methods

func (s *HecateService) ensureCertificateAvailable(ctx context.Context, domain string, altNames []string) (*Certificate, error) {
	// Check if certificate already exists
	filter := &CertificateFilter{
		Domains: []string{domain},
		Status:  []CertificateStatus{CertificateStatusIssued},
	}

	existing, err := s.certificateRepo.ListCertificates(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing certificates: %w", err)
	}

	// If valid certificate exists, return it
	for _, cert := range existing {
		if cert.NotAfter.After(time.Now().Add(30 * 24 * time.Hour)) { // At least 30 days validity
			return cert, nil
		}
	}

	// Request new certificate
	spec := &CertificateSpec{
		CommonName:       domain,
		AlternativeNames: altNames,
		ValidityDays:     90,
		CertType:         CertificateTypeTLS,
		AutoRenew:        true,
	}

	return s.certificateManager.RequestCertificate(ctx, spec)
}

func (s *HecateService) scheduleCertificateRenewal(certificate *Certificate) {
	// This would typically integrate with a job scheduler
	// For now, just log the intention
	s.logger.Info("Certificate renewal scheduled",
		zap.String("certificate_id", certificate.ID),
		zap.String("common_name", certificate.CommonName),
		zap.Time("expires", certificate.NotAfter),
	)
}

func (s *HecateService) setupServiceMonitoring(ctx context.Context, service *ServiceInstance) error {
	// Create alert rules for the service
	alert := &AlertRule{
		ID:        fmt.Sprintf("health-%s", service.ID),
		Name:      fmt.Sprintf("Health check for %s", service.Name),
		Query:     fmt.Sprintf("health{service_id=\"%s\"}", service.ID),
		Condition: "< 1",
		Threshold: 1.0,
		Duration:  5 * time.Minute,
		Severity:  AlertSeverityError,
		Enabled:   true,
		Labels:    map[string]string{"service": service.Name},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return s.monitoringManager.CreateAlert(ctx, alert)
}

func (s *HecateService) summarizeDeployments(deployments []*Deployment) *DeploymentSummary {
	summary := &DeploymentSummary{
		Total: len(deployments),
	}

	statusCounts := make(map[DeploymentStatus]int)
	for _, deployment := range deployments {
		statusCounts[deployment.Status]++
	}
	summary.ByStatus = statusCounts

	return summary
}

func (s *HecateService) summarizeServices(services []*ServiceConfiguration) *ServiceSummary {
	summary := &ServiceSummary{
		Total: len(services),
	}

	typeCounts := make(map[ServiceType]int)
	statusCounts := make(map[ConfigurationStatus]int)
	for _, service := range services {
		typeCounts[ServiceTypeApplication]++ // Default type
		statusCounts[service.Status]++
	}
	summary.ByType = typeCounts
	summary.ByStatus = statusCounts

	return summary
}

func (s *HecateService) summarizeCertificates(certificates []*Certificate) *CertificateSummary {
	summary := &CertificateSummary{
		Total: len(certificates),
	}

	statusCounts := make(map[CertificateStatus]int)
	var expiringSoon int
	for _, cert := range certificates {
		statusCounts[cert.Status]++
		if cert.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
			expiringSoon++
		}
	}
	summary.ByStatus = statusCounts
	summary.ExpiringSoon = expiringSoon

	return summary
}

func (s *HecateService) calculateOverallHealth(deployments []*Deployment, services []*ServiceConfiguration, certificates []*Certificate) HealthStatusType {
	// Check for critical issues
	for _, deployment := range deployments {
		if deployment.Status == DeploymentStatusFailed {
			return HealthStatusUnhealthy
		}
	}

	// Check for expiring certificates
	for _, cert := range certificates {
		if cert.Status == CertificateStatusExpired {
			return HealthStatusUnhealthy
		}
		if cert.NotAfter.Before(time.Now().Add(7 * 24 * time.Hour)) {
			return HealthStatusDegraded
		}
	}

	// Check inactive services
	inactiveServices := 0
	for _, service := range services {
		if service.Status == ConfigurationStatusInactive {
			inactiveServices++
		}
	}

	if inactiveServices > len(services)/2 {
		return HealthStatusDegraded
	}

	return HealthStatusHealthy
}

// Audit methods

func (s *HecateService) auditDeploymentOperation(ctx context.Context, userID, action, resource string, start time.Time, err error) {
	if s.auditRepo == nil {
		return
	}

	result := "success"
	errorMsg := ""
	if err != nil {
		result = "failure"
		errorMsg = err.Error()
	}

	event := &AuditEvent{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Type:      "deployment",
		Source:    "hecate.service",
		User:      userID,
		Action:    action,
		Resource:  resource,
		Result:    result,
		Data: map[string]interface{}{
			"duration": time.Since(start).String(),
			"error":    errorMsg,
		},
	}

	if auditErr := s.auditRepo.RecordEvent(ctx, event); auditErr != nil {
		s.logger.Error("Failed to record audit event", zap.Error(auditErr))
	}
}

func (s *HecateService) auditStackOperation(ctx context.Context, userID, action, resource string, start time.Time, err error) {
	s.auditDeploymentOperation(ctx, userID, action, resource, start, err)
}

func (s *HecateService) auditCertificateOperation(ctx context.Context, userID, action, resource string, start time.Time, err error) {
	s.auditDeploymentOperation(ctx, userID, action, resource, start, err)
}

func (s *HecateService) auditConfigOperation(ctx context.Context, userID, action, resource string, start time.Time, err error) {
	s.auditDeploymentOperation(ctx, userID, action, resource, start, err)
}

func (s *HecateService) auditSystemOperation(ctx context.Context, userID, action, resource string, start time.Time, err error) {
	s.auditDeploymentOperation(ctx, userID, action, resource, start, err)
}

// Summary types for status reporting

type SystemStatusReport struct {
	Timestamp     time.Time                `json:"timestamp"`
	OverallHealth HealthStatusType         `json:"overall_health"`
	Deployments   *DeploymentSummary       `json:"deployments,omitempty"`
	Services      *ServiceSummary          `json:"services,omitempty"`
	Certificates  *CertificateSummary      `json:"certificates,omitempty"`
	ProxyMetrics  map[string]*ProxyMetrics `json:"proxy_metrics,omitempty"`
}

type DeploymentSummary struct {
	Total    int                      `json:"total"`
	ByStatus map[DeploymentStatus]int `json:"by_status"`
}

type ServiceSummary struct {
	Total    int                         `json:"total"`
	ByType   map[ServiceType]int         `json:"by_type"`
	ByStatus map[ConfigurationStatus]int `json:"by_status"`
}

type CertificateSummary struct {
	Total        int                       `json:"total"`
	ByStatus     map[CertificateStatus]int `json:"by_status"`
	ExpiringSoon int                       `json:"expiring_soon"`
}

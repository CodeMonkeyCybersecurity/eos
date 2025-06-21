// Package hecate defines domain interfaces for reverse proxy and service orchestration
package hecate

import (
	"context"
	"io"
	"time"
)

// Core service interfaces for reverse proxy management

// ReverseProxyService defines reverse proxy management operations
type ReverseProxyService interface {
	// Deployment operations
	DeployReverseProxy(ctx context.Context, spec *ReverseProxySpec) (*Deployment, error)
	UpdateReverseProxy(ctx context.Context, deploymentID string, spec *ReverseProxySpec) error
	RemoveReverseProxy(ctx context.Context, deploymentID string) error
	
	// Configuration operations
	UpdateConfiguration(ctx context.Context, deploymentID string, config *ProxyConfiguration) error
	GetConfiguration(ctx context.Context, deploymentID string) (*ProxyConfiguration, error)
	ValidateConfiguration(ctx context.Context, config *ProxyConfiguration) error
	
	// Status and monitoring
	GetProxyStatus(ctx context.Context, deploymentID string) (*ProxyStatus, error)
	GetProxyMetrics(ctx context.Context, deploymentID string) (*ProxyMetrics, error)
	WatchProxyEvents(ctx context.Context, deploymentID string) (<-chan *ProxyEvent, error)
	
	// Rollback and recovery
	RollbackDeployment(ctx context.Context, deploymentID string, version int) error
	GetDeploymentHistory(ctx context.Context, deploymentID string) ([]*DeploymentVersion, error)
}

// ServiceOrchestrator defines service orchestration and lifecycle management
type ServiceOrchestrator interface {
	// Service registration and discovery
	RegisterService(ctx context.Context, provider ServiceProvider) error
	UnregisterService(ctx context.Context, serviceID string) error
	GetRegisteredServices(ctx context.Context) ([]*ServiceRegistration, error)
	
	// Stack deployment and management
	DeployStack(ctx context.Context, spec *StackSpec) (*StackDeployment, error)
	UpdateStack(ctx context.Context, stackID string, spec *StackSpec) error
	RemoveStack(ctx context.Context, stackID string) error
	GetStackStatus(ctx context.Context, stackID string) (*StackStatus, error)
	
	// Service operations
	ScaleService(ctx context.Context, serviceID string, replicas int) error
	RestartService(ctx context.Context, serviceID string) error
	GetServiceLogs(ctx context.Context, serviceID string, options *LogOptions) (io.ReadCloser, error)
	
	// Health monitoring
	HealthCheck(ctx context.Context, serviceID string) (*HealthReport, error)
	GetServiceMetrics(ctx context.Context, serviceID string) (*ServiceMetrics, error)
}

// ConfigurationManager defines configuration management operations
type ConfigurationManager interface {
	// Configuration operations
	SaveConfiguration(ctx context.Context, config *ServiceConfiguration) error
	GetConfiguration(ctx context.Context, serviceID string) (*ServiceConfiguration, error)
	ListConfigurations(ctx context.Context, filter *ConfigurationFilter) ([]*ServiceConfiguration, error)
	DeleteConfiguration(ctx context.Context, configID string) error
	
	// Validation and templates
	ValidateConfiguration(ctx context.Context, config *ServiceConfiguration) error
	ProcessTemplate(ctx context.Context, template *ConfigurationTemplate, variables map[string]interface{}) (*ServiceConfiguration, error)
	GetTemplate(ctx context.Context, templateID string) (*ConfigurationTemplate, error)
	
	// Configuration history and backup
	GetConfigurationHistory(ctx context.Context, serviceID string) ([]*ConfigurationVersion, error)
	BackupConfiguration(ctx context.Context, serviceID string) (*ConfigurationBackup, error)
	RestoreConfiguration(ctx context.Context, backupID string) error
}

// CertificateManager defines certificate management operations
type CertificateManager interface {
	// Certificate lifecycle
	RequestCertificate(ctx context.Context, spec *CertificateSpec) (*Certificate, error)
	RenewCertificate(ctx context.Context, certificateID string) (*Certificate, error)
	RevokeCertificate(ctx context.Context, certificateID string) error
	
	// Certificate operations
	GetCertificate(ctx context.Context, certificateID string) (*Certificate, error)
	ListCertificates(ctx context.Context, filter *CertificateFilter) ([]*Certificate, error)
	ValidateCertificate(ctx context.Context, certificateID string) (*CertificateValidation, error)
	
	// Certificate monitoring
	GetExpiringCertificates(ctx context.Context, days int) ([]*Certificate, error)
	WatchCertificateEvents(ctx context.Context) (<-chan *CertificateEvent, error)
}

// ServiceDiscovery defines service discovery and registration
type ServiceDiscovery interface {
	// Service registration
	RegisterService(ctx context.Context, registration *ServiceRegistration) error
	DeregisterService(ctx context.Context, serviceID string) error
	UpdateServiceHealth(ctx context.Context, serviceID string, health *HealthStatus) error
	
	// Service discovery
	DiscoverServices(ctx context.Context, filter *ServiceFilter) ([]*ServiceInstance, error)
	DiscoverBackends(ctx context.Context, serviceName string) ([]*Backend, error)
	WatchServices(ctx context.Context, filter *ServiceFilter) (<-chan *ServiceEvent, error)
	
	// Load balancing
	SelectBackend(ctx context.Context, serviceName string, policy LoadBalancePolicy) (*Backend, error)
	GetServiceTopology(ctx context.Context, serviceName string) (*ServiceTopology, error)
}

// NetworkManager defines network management for reverse proxy
type NetworkManager interface {
	// Network operations
	CreateNetwork(ctx context.Context, spec *NetworkSpec) (*Network, error)
	RemoveNetwork(ctx context.Context, networkID string) error
	GetNetwork(ctx context.Context, networkID string) (*Network, error)
	ListNetworks(ctx context.Context, filter *NetworkFilter) ([]*Network, error)
	
	// Network configuration
	AttachService(ctx context.Context, networkID, serviceID string) error
	DetachService(ctx context.Context, networkID, serviceID string) error
	UpdateNetworkPolicy(ctx context.Context, networkID string, policy *NetworkPolicy) error
	
	// Traffic management
	ConfigureLoadBalancer(ctx context.Context, spec *LoadBalancerSpec) (*LoadBalancer, error)
	UpdateTrafficRules(ctx context.Context, networkID string, rules []*TrafficRule) error
}

// SecurityManager defines security management for reverse proxy
type SecurityManager interface {
	// Security policies
	CreateSecurityPolicy(ctx context.Context, policy *SecurityPolicy) error
	ApplySecurityPolicy(ctx context.Context, serviceID string, policyID string) error
	ValidateSecurityPolicy(ctx context.Context, policy *SecurityPolicy) error
	
	// Access control
	CreateAccessRule(ctx context.Context, rule *AccessRule) error
	EvaluateAccess(ctx context.Context, request *AccessRequest) (*AccessDecision, error)
	GetAccessLogs(ctx context.Context, filter *AccessLogFilter) ([]*AccessLog, error)
	
	// Security scanning
	ScanService(ctx context.Context, serviceID string) (*SecurityScanResult, error)
	GetSecurityRecommendations(ctx context.Context, serviceID string) ([]*SecurityRecommendation, error)
}

// MonitoringManager defines monitoring and observability
type MonitoringManager interface {
	// Metrics collection
	CollectMetrics(ctx context.Context, serviceID string) (*ServiceMetrics, error)
	GetMetricHistory(ctx context.Context, serviceID string, timeRange *TimeRange) ([]*MetricPoint, error)
	CreateAlert(ctx context.Context, alert *AlertRule) error
	
	// Health monitoring
	PerformHealthCheck(ctx context.Context, serviceID string) (*HealthReport, error)
	GetHealthHistory(ctx context.Context, serviceID string, timeRange *TimeRange) ([]*HealthCheck, error)
	WatchHealthEvents(ctx context.Context, serviceID string) (<-chan *HealthEvent, error)
	
	// Logging
	GetLogs(ctx context.Context, serviceID string, options *LogOptions) (io.ReadCloser, error)
	SearchLogs(ctx context.Context, query *LogQuery) ([]*LogEntry, error)
	CreateLogAlert(ctx context.Context, alert *LogAlert) error
}

// BackupManager defines backup and restore operations
type BackupManager interface {
	// Backup operations
	CreateBackup(ctx context.Context, spec *BackupSpec) (*Backup, error)
	RestoreBackup(ctx context.Context, backupID string, options *RestoreOptions) error
	DeleteBackup(ctx context.Context, backupID string) error
	
	// Backup management
	ListBackups(ctx context.Context, filter *BackupFilter) ([]*Backup, error)
	ValidateBackup(ctx context.Context, backupID string) (*BackupValidation, error)
	ScheduleBackup(ctx context.Context, schedule *BackupSchedule) error
}

// EventBus defines event-driven communication
type EventBus interface {
	// Event publishing
	Publish(ctx context.Context, event *Event) error
	PublishAsync(ctx context.Context, event *Event) error
	
	// Event subscription
	Subscribe(ctx context.Context, eventType string, handler EventHandler) (*Subscription, error)
	SubscribePattern(ctx context.Context, pattern string, handler EventHandler) (*Subscription, error)
	Unsubscribe(ctx context.Context, subscription *Subscription) error
	
	// Event querying
	GetEventHistory(ctx context.Context, filter *EventFilter) ([]*Event, error)
	WatchEvents(ctx context.Context, filter *EventFilter) (<-chan *Event, error)
}

// Repository interfaces for persistence

// DeploymentRepository defines deployment state persistence
type DeploymentRepository interface {
	SaveDeployment(ctx context.Context, deployment *Deployment) error
	GetDeployment(ctx context.Context, deploymentID string) (*Deployment, error)
	ListDeployments(ctx context.Context, filter *DeploymentFilter) ([]*Deployment, error)
	DeleteDeployment(ctx context.Context, deploymentID string) error
	UpdateDeploymentStatus(ctx context.Context, deploymentID string, status DeploymentStatus) error
}

// ServiceRepository defines service configuration persistence
type ServiceRepository interface {
	SaveService(ctx context.Context, service *ServiceConfiguration) error
	GetService(ctx context.Context, serviceID string) (*ServiceConfiguration, error)
	ListServices(ctx context.Context, filter *ServiceFilter) ([]*ServiceConfiguration, error)
	DeleteService(ctx context.Context, serviceID string) error
	UpdateServiceStatus(ctx context.Context, serviceID string, status ServiceStatus) error
}

// ConfigurationRepository defines configuration persistence
type ConfigurationRepository interface {
	SaveConfiguration(ctx context.Context, config *ProxyConfiguration) error
	GetConfiguration(ctx context.Context, configID string) (*ProxyConfiguration, error)
	GetConfigurationByDeployment(ctx context.Context, deploymentID string) (*ProxyConfiguration, error)
	ListConfigurations(ctx context.Context, filter *ConfigurationFilter) ([]*ProxyConfiguration, error)
	DeleteConfiguration(ctx context.Context, configID string) error
	SaveConfigurationVersion(ctx context.Context, version *ConfigurationVersion) error
}

// CertificateRepository defines certificate persistence
type CertificateRepository interface {
	SaveCertificate(ctx context.Context, certificate *Certificate) error
	GetCertificate(ctx context.Context, certificateID string) (*Certificate, error)
	ListCertificates(ctx context.Context, filter *CertificateFilter) ([]*Certificate, error)
	DeleteCertificate(ctx context.Context, certificateID string) error
	UpdateCertificateStatus(ctx context.Context, certificateID string, status CertificateStatus) error
}

// AuditRepository defines audit logging
type AuditRepository interface {
	RecordEvent(ctx context.Context, event *AuditEvent) error
	QueryEvents(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error)
	GetEventsByResource(ctx context.Context, resourceType, resourceID string) ([]*AuditEvent, error)
}

// Validation interfaces

// ServiceValidator defines service validation operations
type ServiceValidator interface {
	ValidateServiceSpec(spec *ServiceSpec) error
	ValidateStackSpec(spec *StackSpec) error
	ValidateProxyConfiguration(config *ProxyConfiguration) error
	ValidateNetworkPolicy(policy *NetworkPolicy) error
}

// SecurityValidator defines security validation
type SecurityValidator interface {
	ValidateSecurityPolicy(policy *SecurityPolicy) error
	ValidateAccessRule(rule *AccessRule) error
	ValidateCertificate(certificate *Certificate) error
	ValidateNetworkConfiguration(config *NetworkConfiguration) error
}

// Infrastructure interfaces

// ContainerRuntime defines container runtime operations
type ContainerRuntime interface {
	// Container lifecycle
	CreateContainer(ctx context.Context, spec *ContainerSpec) (*Container, error)
	StartContainer(ctx context.Context, containerID string) error
	StopContainer(ctx context.Context, containerID string) error
	RemoveContainer(ctx context.Context, containerID string) error
	
	// Container operations
	ExecuteCommand(ctx context.Context, containerID string, command []string) (*ExecutionResult, error)
	GetContainerLogs(ctx context.Context, containerID string, options *LogOptions) (io.ReadCloser, error)
	GetContainerStats(ctx context.Context, containerID string) (*ContainerStats, error)
}

// ProxyAdapter defines proxy implementation adapters
type ProxyAdapter interface {
	// Proxy configuration
	ApplyConfiguration(ctx context.Context, config *ProxyConfiguration) error
	ValidateConfiguration(ctx context.Context, config *ProxyConfiguration) error
	ReloadConfiguration(ctx context.Context) error
	
	// Proxy operations
	GetStatus(ctx context.Context) (*ProxyStatus, error)
	GetMetrics(ctx context.Context) (*ProxyMetrics, error)
	GetLogs(ctx context.Context, options *LogOptions) (io.ReadCloser, error)
}

// TemplateEngine defines template processing
type TemplateEngine interface {
	ProcessTemplate(ctx context.Context, template string, variables map[string]interface{}) (string, error)
	ValidateTemplate(ctx context.Context, template string) error
	GetTemplateVariables(ctx context.Context, template string) ([]string, error)
}

// ServiceProviderInterface defines pluggable service implementations
type ServiceProviderInterface interface {
	// Service metadata
	GetServiceName() string
	GetServiceType() ServiceType
	GetDependencies() []string
	GetCapabilities() []string
	
	// Service lifecycle
	Deploy(ctx context.Context, config *ServiceConfiguration) (*ServiceInstance, error)
	Update(ctx context.Context, instanceID string, config *ServiceConfiguration) error
	Remove(ctx context.Context, instanceID string) error
	
	// Service operations
	Start(ctx context.Context, instanceID string) error
	Stop(ctx context.Context, instanceID string) error
	Restart(ctx context.Context, instanceID string) error
	
	// Service monitoring
	GetStatus(ctx context.Context, instanceID string) (*ServiceInstanceStatus, error)
	GetMetrics(ctx context.Context, instanceID string) (*ServiceMetrics, error)
	HealthCheck(ctx context.Context, instanceID string) (*HealthReport, error)
	
	// Configuration
	ValidateConfiguration(ctx context.Context, config *ServiceConfiguration) error
	GetDefaultConfiguration() *ServiceConfiguration
}

// LifecycleManager defines service lifecycle hooks
type LifecycleManager interface {
	// Deployment lifecycle
	PreDeploy(ctx context.Context, spec *ServiceSpec) error
	PostDeploy(ctx context.Context, instance *ServiceInstance) error
	PreUpdate(ctx context.Context, instance *ServiceInstance, newConfig *ServiceConfiguration) error
	PostUpdate(ctx context.Context, instance *ServiceInstance) error
	PreDestroy(ctx context.Context, instance *ServiceInstance) error
	PostDestroy(ctx context.Context, instanceID string) error
	
	// Health lifecycle
	OnHealthChange(ctx context.Context, instance *ServiceInstance, oldHealth, newHealth *HealthStatus) error
	OnFailure(ctx context.Context, instance *ServiceInstance, error error) error
	OnRecovery(ctx context.Context, instance *ServiceInstance) error
}

// Filter and option types

// ServiceFilter defines service filtering criteria
type ServiceFilter struct {
	Names       []string
	Types       []ServiceType
	Status      []ServiceStatus
	Labels      map[string]string
	HealthStatus []HealthStatusType
	CreatedAfter *time.Time
	CreatedBefore *time.Time
}

// ConfigurationFilter defines configuration filtering criteria
type ConfigurationFilter struct {
	ServiceIDs  []string
	Types       []ConfigurationType
	Status      []ConfigurationStatus
	CreatedAfter *time.Time
	CreatedBefore *time.Time
}

// CertificateFilter defines certificate filtering criteria
type CertificateFilter struct {
	Domains     []string
	Status      []CertificateStatus
	ExpiresAfter *time.Time
	ExpiresBefore *time.Time
	Issuers     []string
}

// NetworkFilter defines network filtering criteria
type NetworkFilter struct {
	Names   []string
	Types   []NetworkType
	Labels  map[string]string
	Subnets []string
}

// DeploymentFilter defines deployment filtering criteria
type DeploymentFilter struct {
	StackIDs    []string
	Status      []DeploymentStatus
	CreatedAfter *time.Time
	CreatedBefore *time.Time
}

// BackupFilter defines backup filtering criteria
type BackupFilter struct {
	ServiceIDs  []string
	Types       []BackupType
	CreatedAfter *time.Time
	CreatedBefore *time.Time
}

// LogOptions defines log retrieval options
type LogOptions struct {
	Follow     bool
	Timestamps bool
	Tail       int
	Since      *time.Time
	Until      *time.Time
	Level      LogLevel
}

// RestoreOptions defines backup restore options
type RestoreOptions struct {
	Force           bool
	TargetServiceID string
	ConfigOverrides map[string]interface{}
}

// TimeRange defines time range for queries
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Callback and handler types

// EventHandler defines event handling function
type EventHandler func(ctx context.Context, event *Event) error

// HealthChecker defines health checking function
type HealthChecker func(ctx context.Context, instance *ServiceInstance) (*HealthReport, error)

// MetricCollector defines metrics collection function
type MetricCollector func(ctx context.Context, instance *ServiceInstance) (*ServiceMetrics, error)

// Enumeration types

type ServiceType string
const (
	ServiceTypeReverseProxy ServiceType = "reverse_proxy"
	ServiceTypeDatabase     ServiceType = "database"
	ServiceTypeApplication  ServiceType = "application"
	ServiceTypeMonitoring   ServiceType = "monitoring"
	ServiceTypeSecurity     ServiceType = "security"
)

type ServiceState string
const (
	ServiceStatePending  ServiceState = "pending"
	ServiceStateDeploying ServiceState = "deploying"
	ServiceStateRunning  ServiceState = "running"
	ServiceStateStopped  ServiceState = "stopped"
	ServiceStateFailed   ServiceState = "failed"
	ServiceStateUpdating ServiceState = "updating"
)

type DeploymentStatus string
const (
	DeploymentStatusPending    DeploymentStatus = "pending"
	DeploymentStatusDeploying  DeploymentStatus = "deploying"
	DeploymentStatusDeployed   DeploymentStatus = "deployed"
	DeploymentStatusFailed     DeploymentStatus = "failed"
	DeploymentStatusRollingBack DeploymentStatus = "rolling_back"
)

type HealthStatusType string
const (
	HealthStatusHealthy   HealthStatusType = "healthy"
	HealthStatusUnhealthy HealthStatusType = "unhealthy"
	HealthStatusUnknown   HealthStatusType = "unknown"
	HealthStatusDegraded  HealthStatusType = "degraded"
)

type CertificateStatus string
const (
	CertificateStatusPending  CertificateStatus = "pending"
	CertificateStatusIssued   CertificateStatus = "issued"
	CertificateStatusExpired  CertificateStatus = "expired"
	CertificateStatusRevoked  CertificateStatus = "revoked"
	CertificateStatusRenewing CertificateStatus = "renewing"
)

type ConfigurationType string
const (
	ConfigurationTypeProxy      ConfigurationType = "proxy"
	ConfigurationTypeService    ConfigurationType = "service"
	ConfigurationTypeNetwork    ConfigurationType = "network"
	ConfigurationTypeSecurity   ConfigurationType = "security"
	ConfigurationTypeMonitoring ConfigurationType = "monitoring"
)

type ConfigurationStatus string
const (
	ConfigurationStatusDraft    ConfigurationStatus = "draft"
	ConfigurationStatusActive   ConfigurationStatus = "active"
	ConfigurationStatusInactive ConfigurationStatus = "inactive"
	ConfigurationStatusArchived ConfigurationStatus = "archived"
)

type NetworkType string
const (
	NetworkTypeBridge  NetworkType = "bridge"
	NetworkTypeOverlay NetworkType = "overlay"
	NetworkTypeHost    NetworkType = "host"
	NetworkTypeNone    NetworkType = "none"
)

type BackupType string
const (
	BackupTypeConfiguration BackupType = "configuration"
	BackupTypeData          BackupType = "data"
	BackupTypeFull          BackupType = "full"
)

type LogLevel string
const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

type LoadBalancePolicy string
const (
	LoadBalancePolicyRoundRobin LoadBalancePolicy = "round_robin"
	LoadBalancePolicyLeastConn  LoadBalancePolicy = "least_connections"
	LoadBalancePolicyIPHash     LoadBalancePolicy = "ip_hash"
	LoadBalancePolicyWeighted   LoadBalancePolicy = "weighted"
)

type EventType string
const (
	EventTypeServiceDeployed   EventType = "service.deployed"
	EventTypeServiceFailed     EventType = "service.failed"
	EventTypeConfigurationChanged EventType = "configuration.changed"
	EventTypeCertificateExpiring EventType = "certificate.expiring"
	EventTypeHealthChanged     EventType = "health.changed"
	EventTypeSecurityAlert     EventType = "security.alert"
)
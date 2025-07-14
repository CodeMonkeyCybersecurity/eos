package environments

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/deploy"
)

// Environment represents a deployment environment (dev, staging, prod, etc.)
type Environment struct {
	Name        string            `yaml:"name" json:"name"`
	DisplayName string            `yaml:"display_name" json:"display_name"`
	Description string            `yaml:"description" json:"description"`
	Type        EnvironmentType   `yaml:"type" json:"type"`
	Status      EnvironmentStatus `yaml:"status" json:"status"`
	
	// Infrastructure configuration
	Infrastructure InfrastructureConfig `yaml:"infrastructure" json:"infrastructure"`
	
	// Deployment configuration
	Deployment DeploymentConfig `yaml:"deployment" json:"deployment"`
	
	// Security and access control
	Security SecurityConfig `yaml:"security" json:"security"`
	
	// Monitoring and alerting
	Monitoring MonitoringConfig `yaml:"monitoring" json:"monitoring"`
	
	// Metadata
	Metadata   EnvironmentMetadata `yaml:"metadata" json:"metadata"`
	CreatedAt  time.Time           `yaml:"created_at" json:"created_at"`
	UpdatedAt  time.Time           `yaml:"updated_at" json:"updated_at"`
}

// EnvironmentType defines the type of environment
type EnvironmentType string

const (
	EnvironmentTypeDevelopment EnvironmentType = "development"
	EnvironmentTypeStaging     EnvironmentType = "staging"
	EnvironmentTypeProduction  EnvironmentType = "production"
	EnvironmentTypeTesting     EnvironmentType = "testing"
	EnvironmentTypePreview     EnvironmentType = "preview"
	EnvironmentTypeDisaster    EnvironmentType = "disaster_recovery"
)

// EnvironmentStatus defines the current status of an environment
type EnvironmentStatus string

const (
	EnvironmentStatusActive      EnvironmentStatus = "active"
	EnvironmentStatusInactive    EnvironmentStatus = "inactive"
	EnvironmentStatusMaintenance EnvironmentStatus = "maintenance"
	EnvironmentStatusDestroyed   EnvironmentStatus = "destroyed"
	EnvironmentStatusCreating    EnvironmentStatus = "creating"
	EnvironmentStatusUpdating    EnvironmentStatus = "updating"
)

// InfrastructureConfig holds infrastructure-specific configuration
type InfrastructureConfig struct {
	// HashiCorp stack configuration
	Nomad  NomadConfig  `yaml:"nomad" json:"nomad"`
	Consul ConsulConfig `yaml:"consul" json:"consul"`
	Vault  VaultConfig  `yaml:"vault" json:"vault"`
	
	// Terraform configuration
	Terraform TerraformConfig `yaml:"terraform" json:"terraform"`
	
	// SaltStack configuration
	Salt SaltConfig `yaml:"salt" json:"salt"`
	
	// Cloud provider configuration
	Provider ProviderConfig `yaml:"provider" json:"provider"`
	
	// Network configuration
	Network NetworkConfig `yaml:"network" json:"network"`
}

// NomadConfig holds Nomad-specific configuration
type NomadConfig struct {
	Address     string            `yaml:"address" json:"address"`
	Region      string            `yaml:"region" json:"region"`
	Datacenter  string            `yaml:"datacenter" json:"datacenter"`
	Namespace   string            `yaml:"namespace" json:"namespace"`
	Token       string            `yaml:"token,omitempty" json:"token,omitempty"`
	TLS         TLSConfig         `yaml:"tls" json:"tls"`
	Meta        map[string]string `yaml:"meta" json:"meta"`
}

// ConsulConfig holds Consul-specific configuration
type ConsulConfig struct {
	Address    string            `yaml:"address" json:"address"`
	Datacenter string            `yaml:"datacenter" json:"datacenter"`
	Token      string            `yaml:"token,omitempty" json:"token,omitempty"`
	TLS        TLSConfig         `yaml:"tls" json:"tls"`
	Tags       []string          `yaml:"tags" json:"tags"`
	Meta       map[string]string `yaml:"meta" json:"meta"`
}

// VaultConfig holds Vault-specific configuration
type VaultConfig struct {
	Address   string            `yaml:"address" json:"address"`
	Token     string            `yaml:"token,omitempty" json:"token,omitempty"`
	Namespace string            `yaml:"namespace" json:"namespace"`
	TLS       TLSConfig         `yaml:"tls" json:"tls"`
	Policies  []string          `yaml:"policies" json:"policies"`
	Mounts    map[string]string `yaml:"mounts" json:"mounts"`
}

// TerraformConfig holds Terraform-specific configuration
type TerraformConfig struct {
	Backend       string            `yaml:"backend" json:"backend"`
	BackendConfig map[string]string `yaml:"backend_config" json:"backend_config"`
	Workspace     string            `yaml:"workspace" json:"workspace"`
	Variables     map[string]string `yaml:"variables" json:"variables"`
	ModulePath    string            `yaml:"module_path" json:"module_path"`
}

// SaltConfig holds SaltStack-specific configuration
type SaltConfig struct {
	Master      string            `yaml:"master" json:"master"`
	Environment string            `yaml:"environment" json:"environment"`
	Targets     []string          `yaml:"targets" json:"targets"`
	Pillar      map[string]string `yaml:"pillar" json:"pillar"`
}

// ProviderConfig holds cloud provider configuration
type ProviderConfig struct {
	Name   string            `yaml:"name" json:"name"` // hetzner, aws, gcp, azure
	Region string            `yaml:"region" json:"region"`
	Zone   string            `yaml:"zone" json:"zone"`
	Config map[string]string `yaml:"config" json:"config"`
}

// NetworkConfig holds network-specific configuration
type NetworkConfig struct {
	VPC     string   `yaml:"vpc" json:"vpc"`
	Subnets []string `yaml:"subnets" json:"subnets"`
	Domain  string   `yaml:"domain" json:"domain"`
	DNS     []string `yaml:"dns" json:"dns"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	CertFile   string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	KeyFile    string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	CAFile     string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	SkipVerify bool   `yaml:"skip_verify" json:"skip_verify"`
}

// DeploymentConfig holds deployment-specific configuration
type DeploymentConfig struct {
	Strategy         DeploymentStrategy `yaml:"strategy" json:"strategy"`
	Resources        ResourceLimits     `yaml:"resources" json:"resources"`
	HealthChecks     HealthCheckConfig  `yaml:"health_checks" json:"health_checks"`
	RollbackPolicy   RollbackPolicy     `yaml:"rollback_policy" json:"rollback_policy"`
	UpdatePolicy     UpdatePolicy       `yaml:"update_policy" json:"update_policy"`
	AutoScaling      AutoScalingConfig  `yaml:"auto_scaling" json:"auto_scaling"`
}

// DeploymentStrategy defines deployment strategy settings
type DeploymentStrategy struct {
	Type              string        `yaml:"type" json:"type"` // rolling, blue-green, canary
	MaxParallel       int           `yaml:"max_parallel" json:"max_parallel"`
	MinHealthyTime    time.Duration `yaml:"min_healthy_time" json:"min_healthy_time"`
	HealthyDeadline   time.Duration `yaml:"healthy_deadline" json:"healthy_deadline"`
	ProgressDeadline  time.Duration `yaml:"progress_deadline" json:"progress_deadline"`
	AutoRevert        bool          `yaml:"auto_revert" json:"auto_revert"`
	AutoPromote       bool          `yaml:"auto_promote" json:"auto_promote"`
	CanaryReplicas    int           `yaml:"canary_replicas" json:"canary_replicas"`
	CanaryDuration    time.Duration `yaml:"canary_duration" json:"canary_duration"`
}

// ResourceLimits defines default resource limits for the environment
type ResourceLimits struct {
	CPU       int `yaml:"cpu" json:"cpu"`             // MHz
	Memory    int `yaml:"memory" json:"memory"`       // MB
	MemoryMax int `yaml:"memory_max" json:"memory_max"` // MB
	Disk      int `yaml:"disk" json:"disk"`           // MB
	Network   int `yaml:"network" json:"network"`     // Mbps
}

// HealthCheckConfig defines health check settings
type HealthCheckConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	Path            string        `yaml:"path" json:"path"`
	Interval        time.Duration `yaml:"interval" json:"interval"`
	Timeout         time.Duration `yaml:"timeout" json:"timeout"`
	Retries         int           `yaml:"retries" json:"retries"`
	GracePeriod     time.Duration `yaml:"grace_period" json:"grace_period"`
	FailureThreshold int          `yaml:"failure_threshold" json:"failure_threshold"`
}

// RollbackPolicy defines rollback behavior
type RollbackPolicy struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	AutoRollback   bool          `yaml:"auto_rollback" json:"auto_rollback"`
	RollbackWindow time.Duration `yaml:"rollback_window" json:"rollback_window"`
	RetainVersions int           `yaml:"retain_versions" json:"retain_versions"`
}

// UpdatePolicy defines update behavior
type UpdatePolicy struct {
	MaxUnavailable   string        `yaml:"max_unavailable" json:"max_unavailable"`
	MaxSurge         string        `yaml:"max_surge" json:"max_surge"`
	MinReadySeconds  int           `yaml:"min_ready_seconds" json:"min_ready_seconds"`
	PodDisruption    int           `yaml:"pod_disruption" json:"pod_disruption"`
	UpdateTimeout    time.Duration `yaml:"update_timeout" json:"update_timeout"`
}

// AutoScalingConfig defines auto-scaling settings
type AutoScalingConfig struct {
	Enabled     bool               `yaml:"enabled" json:"enabled"`
	MinReplicas int                `yaml:"min_replicas" json:"min_replicas"`
	MaxReplicas int                `yaml:"max_replicas" json:"max_replicas"`
	Metrics     []ScalingMetric    `yaml:"metrics" json:"metrics"`
	Behavior    ScalingBehavior    `yaml:"behavior" json:"behavior"`
}

// ScalingMetric defines a metric for auto-scaling
type ScalingMetric struct {
	Type       string `yaml:"type" json:"type"` // cpu, memory, custom
	Target     int    `yaml:"target" json:"target"`
	MetricName string `yaml:"metric_name,omitempty" json:"metric_name,omitempty"`
}

// ScalingBehavior defines scaling behavior
type ScalingBehavior struct {
	ScaleUp   ScalingPolicy `yaml:"scale_up" json:"scale_up"`
	ScaleDown ScalingPolicy `yaml:"scale_down" json:"scale_down"`
}

// ScalingPolicy defines scaling policy
type ScalingPolicy struct {
	StabilizationWindow time.Duration `yaml:"stabilization_window" json:"stabilization_window"`
	Policies            []ScalingRule `yaml:"policies" json:"policies"`
}

// ScalingRule defines a scaling rule
type ScalingRule struct {
	Type          string        `yaml:"type" json:"type"` // pods, percent
	Value         int           `yaml:"value" json:"value"`
	PeriodSeconds time.Duration `yaml:"period_seconds" json:"period_seconds"`
}

// SecurityConfig holds security-specific configuration
type SecurityConfig struct {
	AccessControl  AccessControlConfig  `yaml:"access_control" json:"access_control"`
	NetworkPolicy  NetworkPolicyConfig  `yaml:"network_policy" json:"network_policy"`
	Encryption     EncryptionConfig     `yaml:"encryption" json:"encryption"`
	Compliance     ComplianceConfig     `yaml:"compliance" json:"compliance"`
	SecretScanning SecretScanningConfig `yaml:"secret_scanning" json:"secret_scanning"`
}

// AccessControlConfig defines access control settings
type AccessControlConfig struct {
	RBAC        RBACConfig        `yaml:"rbac" json:"rbac"`
	MFA         MFAConfig         `yaml:"mfa" json:"mfa"`
	Approval    ApprovalConfig    `yaml:"approval" json:"approval"`
	Audit       AuditConfig       `yaml:"audit" json:"audit"`
}

// RBACConfig defines role-based access control
type RBACConfig struct {
	Enabled bool                `yaml:"enabled" json:"enabled"`
	Roles   map[string]RoleSpec `yaml:"roles" json:"roles"`
	Users   map[string]UserSpec `yaml:"users" json:"users"`
}

// RoleSpec defines a role specification
type RoleSpec struct {
	Permissions []string `yaml:"permissions" json:"permissions"`
	Resources   []string `yaml:"resources" json:"resources"`
}

// UserSpec defines a user specification
type UserSpec struct {
	Roles   []string `yaml:"roles" json:"roles"`
	Groups  []string `yaml:"groups" json:"groups"`
	Enabled bool     `yaml:"enabled" json:"enabled"`
}

// MFAConfig defines multi-factor authentication settings
type MFAConfig struct {
	Required   bool     `yaml:"required" json:"required"`
	Providers  []string `yaml:"providers" json:"providers"`
	GracePeriod time.Duration `yaml:"grace_period" json:"grace_period"`
}

// ApprovalConfig defines approval workflow settings
type ApprovalConfig struct {
	Required     bool     `yaml:"required" json:"required"`
	Approvers    []string `yaml:"approvers" json:"approvers"`
	MinApprovals int      `yaml:"min_approvals" json:"min_approvals"`
	Timeout      time.Duration `yaml:"timeout" json:"timeout"`
}

// AuditConfig defines audit logging settings
type AuditConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Backend   string `yaml:"backend" json:"backend"`
	Retention int    `yaml:"retention" json:"retention"` // days
}

// NetworkPolicyConfig defines network policy settings
type NetworkPolicyConfig struct {
	Enabled       bool              `yaml:"enabled" json:"enabled"`
	DefaultDeny   bool              `yaml:"default_deny" json:"default_deny"`
	AllowedEgress []NetworkRule     `yaml:"allowed_egress" json:"allowed_egress"`
	AllowedIngress []NetworkRule    `yaml:"allowed_ingress" json:"allowed_ingress"`
}

// NetworkRule defines a network rule
type NetworkRule struct {
	Protocol string   `yaml:"protocol" json:"protocol"`
	Ports    []int    `yaml:"ports" json:"ports"`
	Sources  []string `yaml:"sources" json:"sources"`
	Targets  []string `yaml:"targets" json:"targets"`
}

// EncryptionConfig defines encryption settings
type EncryptionConfig struct {
	InTransit  EncryptionSpec `yaml:"in_transit" json:"in_transit"`
	AtRest     EncryptionSpec `yaml:"at_rest" json:"at_rest"`
	KeyManagement KeyManagementConfig `yaml:"key_management" json:"key_management"`
}

// EncryptionSpec defines encryption specification
type EncryptionSpec struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Algorithm  string `yaml:"algorithm" json:"algorithm"`
	KeySize    int    `yaml:"key_size" json:"key_size"`
	Provider   string `yaml:"provider" json:"provider"`
}

// KeyManagementConfig defines key management settings
type KeyManagementConfig struct {
	Provider   string        `yaml:"provider" json:"provider"` // vault, kms, etc.
	RotationPeriod time.Duration `yaml:"rotation_period" json:"rotation_period"`
	BackupEnabled  bool         `yaml:"backup_enabled" json:"backup_enabled"`
}

// ComplianceConfig defines compliance settings
type ComplianceConfig struct {
	Standards []string          `yaml:"standards" json:"standards"` // SOC2, PCI-DSS, etc.
	Policies  map[string]string `yaml:"policies" json:"policies"`
	Scanning  ScanningConfig    `yaml:"scanning" json:"scanning"`
}

// ScanningConfig defines security scanning settings
type ScanningConfig struct {
	Enabled   bool          `yaml:"enabled" json:"enabled"`
	Schedule  string        `yaml:"schedule" json:"schedule"`
	Types     []string      `yaml:"types" json:"types"` // vulnerability, compliance, etc.
	Threshold string        `yaml:"threshold" json:"threshold"` // low, medium, high, critical
}

// SecretScanningConfig defines secret scanning settings
type SecretScanningConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Patterns    []string `yaml:"patterns" json:"patterns"`
	Exclusions  []string `yaml:"exclusions" json:"exclusions"`
	Action      string   `yaml:"action" json:"action"` // warn, block, quarantine
}

// MonitoringConfig holds monitoring and alerting configuration
type MonitoringConfig struct {
	Metrics    MetricsConfig    `yaml:"metrics" json:"metrics"`
	Logging    LoggingConfig    `yaml:"logging" json:"logging"`
	Tracing    TracingConfig    `yaml:"tracing" json:"tracing"`
	Alerting   AlertingConfig   `yaml:"alerting" json:"alerting"`
	Dashboards DashboardConfig  `yaml:"dashboards" json:"dashboards"`
}

// MetricsConfig defines metrics collection settings
type MetricsConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Provider  string            `yaml:"provider" json:"provider"` // prometheus, datadog, etc.
	Endpoint  string            `yaml:"endpoint" json:"endpoint"`
	Interval  time.Duration     `yaml:"interval" json:"interval"`
	Labels    map[string]string `yaml:"labels" json:"labels"`
	Retention time.Duration     `yaml:"retention" json:"retention"`
}

// LoggingConfig defines logging settings
type LoggingConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Level     string            `yaml:"level" json:"level"`
	Format    string            `yaml:"format" json:"format"`
	Output    []string          `yaml:"output" json:"output"`
	Rotation  LogRotationConfig `yaml:"rotation" json:"rotation"`
	Shipping  LogShippingConfig `yaml:"shipping" json:"shipping"`
}

// LogRotationConfig defines log rotation settings
type LogRotationConfig struct {
	MaxSize    int           `yaml:"max_size" json:"max_size"` // MB
	MaxAge     time.Duration `yaml:"max_age" json:"max_age"`
	MaxBackups int           `yaml:"max_backups" json:"max_backups"`
	Compress   bool          `yaml:"compress" json:"compress"`
}

// LogShippingConfig defines log shipping settings
type LogShippingConfig struct {
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	Destination string            `yaml:"destination" json:"destination"`
	Format      string            `yaml:"format" json:"format"`
	Buffer      LogBufferConfig   `yaml:"buffer" json:"buffer"`
	Tags        map[string]string `yaml:"tags" json:"tags"`
}

// LogBufferConfig defines log buffer settings
type LogBufferConfig struct {
	Size      int           `yaml:"size" json:"size"`
	FlushTime time.Duration `yaml:"flush_time" json:"flush_time"`
}

// TracingConfig defines distributed tracing settings
type TracingConfig struct {
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	Provider    string            `yaml:"provider" json:"provider"` // jaeger, zipkin, etc.
	Endpoint    string            `yaml:"endpoint" json:"endpoint"`
	SampleRate  float64           `yaml:"sample_rate" json:"sample_rate"`
	Tags        map[string]string `yaml:"tags" json:"tags"`
}

// AlertingConfig defines alerting settings
type AlertingConfig struct {
	Enabled      bool                  `yaml:"enabled" json:"enabled"`
	Provider     string                `yaml:"provider" json:"provider"`
	Channels     []AlertChannel        `yaml:"channels" json:"channels"`
	Rules        []AlertRule           `yaml:"rules" json:"rules"`
	Escalation   EscalationPolicy      `yaml:"escalation" json:"escalation"`
	Maintenance  MaintenanceWindow     `yaml:"maintenance" json:"maintenance"`
}

// AlertChannel defines an alert channel
type AlertChannel struct {
	Name     string            `yaml:"name" json:"name"`
	Type     string            `yaml:"type" json:"type"` // slack, email, pagerduty, etc.
	Config   map[string]string `yaml:"config" json:"config"`
	Severity []string          `yaml:"severity" json:"severity"`
}

// AlertRule defines an alert rule
type AlertRule struct {
	Name        string            `yaml:"name" json:"name"`
	Condition   string            `yaml:"condition" json:"condition"`
	Threshold   float64           `yaml:"threshold" json:"threshold"`
	Duration    time.Duration     `yaml:"duration" json:"duration"`
	Severity    string            `yaml:"severity" json:"severity"`
	Labels      map[string]string `yaml:"labels" json:"labels"`
	Annotations map[string]string `yaml:"annotations" json:"annotations"`
}

// EscalationPolicy defines alert escalation
type EscalationPolicy struct {
	Enabled bool                 `yaml:"enabled" json:"enabled"`
	Levels  []EscalationLevel    `yaml:"levels" json:"levels"`
}

// EscalationLevel defines an escalation level
type EscalationLevel struct {
	Level     int           `yaml:"level" json:"level"`
	Delay     time.Duration `yaml:"delay" json:"delay"`
	Channels  []string      `yaml:"channels" json:"channels"`
	Condition string        `yaml:"condition" json:"condition"`
}

// MaintenanceWindow defines maintenance window settings
type MaintenanceWindow struct {
	Enabled   bool                 `yaml:"enabled" json:"enabled"`
	Windows   []MaintenanceSlot    `yaml:"windows" json:"windows"`
	AlertsOff bool                 `yaml:"alerts_off" json:"alerts_off"`
}

// MaintenanceSlot defines a maintenance time slot
type MaintenanceSlot struct {
	Start    string   `yaml:"start" json:"start"` // "Monday 02:00"
	Duration time.Duration `yaml:"duration" json:"duration"`
	Timezone string   `yaml:"timezone" json:"timezone"`
	Recurring bool    `yaml:"recurring" json:"recurring"`
}

// DashboardConfig defines dashboard settings
type DashboardConfig struct {
	Enabled    bool              `yaml:"enabled" json:"enabled"`
	Provider   string            `yaml:"provider" json:"provider"` // grafana, etc.
	URL        string            `yaml:"url" json:"url"`
	Templates  []string          `yaml:"templates" json:"templates"`
	Variables  map[string]string `yaml:"variables" json:"variables"`
}

// EnvironmentMetadata holds environment metadata
type EnvironmentMetadata struct {
	Owner       string            `yaml:"owner" json:"owner"`
	Team        string            `yaml:"team" json:"team"`
	Project     string            `yaml:"project" json:"project"`
	CostCenter  string            `yaml:"cost_center" json:"cost_center"`
	Purpose     string            `yaml:"purpose" json:"purpose"`
	Tags        map[string]string `yaml:"tags" json:"tags"`
	Labels      map[string]string `yaml:"labels" json:"labels"`
	Annotations map[string]string `yaml:"annotations" json:"annotations"`
}

// Context represents the current eos context
type Context struct {
	CurrentEnvironment string                 `yaml:"current_environment" json:"current_environment"`
	Environments       map[string]Environment `yaml:"environments" json:"environments"`
	Config             ContextConfig          `yaml:"config" json:"config"`
	UpdatedAt          time.Time              `yaml:"updated_at" json:"updated_at"`
}

// ContextConfig holds context-specific configuration
type ContextConfig struct {
	ConfigPath     string        `yaml:"config_path" json:"config_path"`
	CacheTimeout   time.Duration `yaml:"cache_timeout" json:"cache_timeout"`
	DefaultTimeout time.Duration `yaml:"default_timeout" json:"default_timeout"`
	AutoRefresh    bool          `yaml:"auto_refresh" json:"auto_refresh"`
	Validation     ValidationConfig `yaml:"validation" json:"validation"`
}

// ValidationConfig defines validation settings
type ValidationConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled"`
	Strict      bool     `yaml:"strict" json:"strict"`
	SkipWarnings bool    `yaml:"skip_warnings" json:"skip_warnings"`
	Rules       []string `yaml:"rules" json:"rules"`
}

// EnvironmentManager manages environment operations
type EnvironmentManager struct {
	configPath      string
	context         *Context
	deployManager   *deploy.DeploymentManager
	cache           map[string]*Environment
	cacheExpiry     time.Time
}

// EnvironmentError represents an error during environment operations
type EnvironmentError struct {
	Type        string                 `json:"type"`
	Environment string                 `json:"environment"`
	Operation   string                 `json:"operation"`
	Message     string                 `json:"message"`
	Cause       error                  `json:"cause,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
	Retryable   bool                   `json:"retryable"`
}

func (e *EnvironmentError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s/%s/%s] %s: %v", e.Type, e.Environment, e.Operation, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s/%s/%s] %s", e.Type, e.Environment, e.Operation, e.Message)
}

// Default configurations

// DefaultDevelopmentEnvironment returns a default development environment
func DefaultDevelopmentEnvironment() *Environment {
	return &Environment{
		Name:        "development",
		DisplayName: "Development",
		Description: "Development environment for testing new features",
		Type:        EnvironmentTypeDevelopment,
		Status:      EnvironmentStatusActive,
		Infrastructure: InfrastructureConfig{
			Nomad: NomadConfig{
				Address:    "http://localhost:4646",
				Region:     "global",
				Datacenter: "dc1",
				Namespace:  "development",
			},
			Consul: ConsulConfig{
				Address:    "localhost:8500",
				Datacenter: "dc1",
			},
			Vault: VaultConfig{
				Address: "http://localhost:8179",
			},
			Terraform: TerraformConfig{
				Backend: "consul",
				BackendConfig: map[string]string{
					"address": "localhost:8500",
					"path":    "terraform/development/state",
				},
				Workspace: "development",
			},
			Salt: SaltConfig{
				Master:      "salt-master.cybermonkey.net.au",
				Environment: "development",
				Targets:     []string{"*"},
			},
		},
		Deployment: DeploymentConfig{
			Strategy: DeploymentStrategy{
				Type:              "rolling",
				MaxParallel:       1,
				MinHealthyTime:    30 * time.Second,
				HealthyDeadline:   5 * time.Minute,
				ProgressDeadline:  10 * time.Minute,
				AutoRevert:        true,
				AutoPromote:       true,
			},
			Resources: ResourceLimits{
				CPU:       500,
				Memory:    256,
				MemoryMax: 512,
			},
		},
		Security: SecurityConfig{
			AccessControl: AccessControlConfig{
				RBAC: RBACConfig{
					Enabled: false, // Less strict for development
				},
				MFA: MFAConfig{
					Required: false,
				},
				Approval: ApprovalConfig{
					Required: false,
				},
			},
		},
		Monitoring: MonitoringConfig{
			Metrics: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Interval: 15 * time.Second,
			},
			Logging: LoggingConfig{
				Enabled: true,
				Level:   "debug",
				Format:  "json",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// DefaultProductionEnvironment returns a default production environment
func DefaultProductionEnvironment() *Environment {
	return &Environment{
		Name:        "production",
		DisplayName: "Production",
		Description: "Production environment for live services",
		Type:        EnvironmentTypeProduction,
		Status:      EnvironmentStatusActive,
		Infrastructure: InfrastructureConfig{
			Nomad: NomadConfig{
				Address:    "http://nomad-prod.cybermonkey.net.au:4646",
				Region:     "global",
				Datacenter: "prod",
				Namespace:  "production",
			},
			Consul: ConsulConfig{
				Address:    "consul-prod.cybermonkey.net.au:8500",
				Datacenter: "prod",
			},
			Vault: VaultConfig{
				Address: "http://vault-prod.cybermonkey.net.au:8179",
			},
			Terraform: TerraformConfig{
				Backend: "consul",
				BackendConfig: map[string]string{
					"address": "consul-prod.cybermonkey.net.au:8500",
					"path":    "terraform/production/state",
				},
				Workspace: "production",
			},
			Salt: SaltConfig{
				Master:      "salt-master-prod.cybermonkey.net.au",
				Environment: "production",
				Targets:     []string{"*"},
			},
		},
		Deployment: DeploymentConfig{
			Strategy: DeploymentStrategy{
				Type:              "blue-green",
				MaxParallel:       2,
				MinHealthyTime:    2 * time.Minute,
				HealthyDeadline:   10 * time.Minute,
				ProgressDeadline:  30 * time.Minute,
				AutoRevert:        true,
				AutoPromote:       false, // Require manual promotion
			},
			Resources: ResourceLimits{
				CPU:       1000,
				Memory:    1024,
				MemoryMax: 2048,
			},
		},
		Security: SecurityConfig{
			AccessControl: AccessControlConfig{
				RBAC: RBACConfig{
					Enabled: true,
				},
				MFA: MFAConfig{
					Required: true,
				},
				Approval: ApprovalConfig{
					Required:     true,
					MinApprovals: 2,
					Timeout:      4 * time.Hour,
				},
			},
			NetworkPolicy: NetworkPolicyConfig{
				Enabled:     true,
				DefaultDeny: true,
			},
			Encryption: EncryptionConfig{
				InTransit: EncryptionSpec{
					Enabled: true,
				},
				AtRest: EncryptionSpec{
					Enabled: true,
				},
			},
		},
		Monitoring: MonitoringConfig{
			Metrics: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Interval: 10 * time.Second,
			},
			Logging: LoggingConfig{
				Enabled: true,
				Level:   "info",
				Format:  "json",
			},
			Alerting: AlertingConfig{
				Enabled: true,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// DefaultContext returns a default eos context
func DefaultContext() *Context {
	return &Context{
		CurrentEnvironment: "development",
		Environments: map[string]Environment{
			"development": *DefaultDevelopmentEnvironment(),
			"production":  *DefaultProductionEnvironment(),
		},
		Config: ContextConfig{
			ConfigPath:     "~/.eos/config.yaml",
			CacheTimeout:   5 * time.Minute,
			DefaultTimeout: 30 * time.Second,
			AutoRefresh:    true,
			Validation: ValidationConfig{
				Enabled:     true,
				Strict:      false,
				SkipWarnings: false,
			},
		},
		UpdatedAt: time.Now(),
	}
}
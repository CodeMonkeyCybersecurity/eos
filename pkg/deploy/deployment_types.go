package deploy

import (
	"time"
)

// Deployment strategy enums
type DeploymentStrategy string

const (
	DeploymentStrategyRolling   DeploymentStrategy = "rolling"
	DeploymentStrategyBlueGreen DeploymentStrategy = "blue-green"
	DeploymentStrategyCanary    DeploymentStrategy = "canary"
	DeploymentStrategyImmutable DeploymentStrategy = "immutable"
)

// Stack deployment strategy enums
type StackDeploymentStrategy string

const (
	StackDeploymentStrategySequential     StackDeploymentStrategy = "sequential"
	StackDeploymentStrategyParallel       StackDeploymentStrategy = "parallel"
	StackDeploymentStrategyDependencyOrder StackDeploymentStrategy = "dependency-order"
)

// Application deployment configuration
type AppDeploymentConfig struct {
	AppName           string
	Environment       string
	Strategy          DeploymentStrategy
	Version           string
	Timeout           time.Duration
	DryRun            bool
	Force             bool
	SkipValidation    bool
	SkipHealthCheck   bool
	RollbackOnFailure bool
	StrategyConfig    StrategyConfig
	HealthCheck       HealthCheckConfig
}

// Service deployment configuration
type ServiceDeploymentConfig struct {
	ServiceName  string
	Environment  string
	Strategy     DeploymentStrategy
	Version      string
	Replicas     int
	Timeout      time.Duration
	DryRun       bool
	Force        bool
	Resources    ResourceConfig
	ServiceMesh  ServiceMeshConfig
	Configuration ConfigurationConfig
	HealthCheck  HealthCheckConfig
	Dependencies DependencyConfig
}

// Stack deployment configuration
type StackDeploymentConfig struct {
	StackName             string
	Environment           string
	Strategy              StackDeploymentStrategy
	Version               string
	Components            []string
	Timeout               time.Duration
	DryRun                bool
	Force                 bool
	ContinueOnError       bool
	RollbackOnFailure     bool
	Parallel              bool
	WaitBetweenComponents time.Duration
	HealthCheck           StackHealthCheckConfig
}

// Strategy-specific configurations
type StrategyConfig struct {
	Rolling   RollingConfig
	BlueGreen BlueGreenConfig
	Canary    CanaryConfig
}

type RollingConfig struct {
	BatchSize        int
	MaxSurge         int
	MaxUnavailable   int
	ProgressDeadline time.Duration
}

type BlueGreenConfig struct {
	PrePromotionAnalysis  time.Duration
	ScaleDownDelay        time.Duration
	AutoPromotionEnabled  bool
}

type CanaryConfig struct {
	InitialPercentage int
	StepPercentage    int
	StepDuration      time.Duration
	MaxSteps          int
	AnalysisDelay     time.Duration
}

// Resource configuration
type ResourceConfig struct {
	CPU    string
	Memory string
}

// Service mesh configuration
type ServiceMeshConfig struct {
	Enabled     bool
	ProxyCPU    string
	ProxyMemory string
}

// Configuration management
type ConfigurationConfig struct {
	ConfigFile  string
	SecretsPath string
}

// Health check configuration
type HealthCheckConfig struct {
	Enabled      bool
	Path         string
	Port         int
	Timeout      time.Duration
	Interval     time.Duration
	InitialDelay time.Duration
	Retries      int
}

// Stack health check configuration
type StackHealthCheckConfig struct {
	Enabled               bool
	ComponentTimeout      time.Duration
	StackValidationDelay  time.Duration
	CrossComponentChecks  bool
}

// Dependency configuration
type DependencyConfig struct {
	VerifyDependencies bool
	DependencyTimeout  time.Duration
}

// Deployment results
type DeploymentResult struct {
	Success              bool
	Version              string
	Duration             time.Duration
	DeploymentID         string
	ServiceURL           string
	StepsExecuted        []DeploymentStep
	HealthCheckResults   []HealthCheckResult
	RollbackPlan         *RollbackPlan
	RollbackAttempted    bool
	RollbackSuccessful   bool
}

// Service deployment results
type ServiceDeploymentResult struct {
	Success           bool
	Version           string
	Replicas          int
	Duration          time.Duration
	DeploymentID      string
	ServiceURL        string
	ServiceAddress    string
	ServiceMeshConfig *ServiceMeshResult
	DependencyResults []DependencyResult
	StepsExecuted     []DeploymentStep
	HealthCheckResults []HealthCheckResult
	Endpoints         []ServiceEndpoint
}

// Stack deployment results
type StackDeploymentResult struct {
	Success             bool
	Duration            time.Duration
	StartTime           time.Time
	ComponentsDeployed  int
	ComponentsFailed    int
	ComponentResults    []ComponentDeploymentResult
	StackHealthResults  []HealthCheckResult
	ServiceEndpoints    map[string][]ServiceEndpoint
	StackRollbackPlan   *StackRollbackPlan
	RollbackAttempted   bool
	RollbackSuccessful  bool
}

// Component deployment result
type ComponentDeploymentResult struct {
	ComponentName string
	Success       bool
	Version       string
	Duration      time.Duration
	Error         string
}

// Deployment step
type DeploymentStep struct {
	Name        string
	Description string
	Status      string
	Duration    time.Duration
	Output      string
	Error       string
}

// Health check result
type HealthCheckResult struct {
	Check   string
	Passed  bool
	Message string
	Level   string
}

// Service mesh result
type ServiceMeshResult struct {
	Identity    string
	ProxyStatus string
	Intentions  []string
}

// Dependency result
type DependencyResult struct {
	Name    string
	Healthy bool
	Status  string
}

// Service endpoint
type ServiceEndpoint struct {
	Address  string
	Port     int
	Protocol string
}

// Rollback plan
type RollbackPlan struct {
	PreviousVersion string
	EstimatedTime   time.Duration
	Steps           []RollbackStep
}

// Stack rollback plan
type StackRollbackPlan struct {
	EstimatedTime       time.Duration
	ComponentRollbacks  []ComponentRollback
}

// Component rollback
type ComponentRollback struct {
	ComponentName   string
	PreviousVersion string
	EstimatedTime   time.Duration
}

// Rollback step
type RollbackStep struct {
	Name        string
	Description string
	Command     string
	Args        []string
	Timeout     time.Duration
	Required    bool
}

// Job status for Nomad integration
type JobStatus struct {
	Status  string
	Running int
	Desired int
	Failed  int
}

// Allocation for Nomad integration
type Allocation struct {
	ID     string
	NodeID string
	Status string
	Tasks  map[string]string
}

// Terraform state for integration
type TerraformState struct {
	Resources []TerraformStateResource
	Outputs   map[string]interface{}
}

// Terraform state resource
type TerraformStateResource struct {
	Type    string
	Name    string
	Status  string
	Address string
}
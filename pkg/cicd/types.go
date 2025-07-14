package cicd

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// PipelineConfig represents the configuration for a CI/CD pipeline
type PipelineConfig struct {
	AppName string `yaml:"app_name" json:"app_name"`
	Version string `yaml:"version" json:"version"`

	// Source configuration
	Git GitConfig `yaml:"git" json:"git"`

	// Build configuration
	Build BuildConfig `yaml:"build" json:"build"`

	// Deployment configuration
	Deployment DeploymentConfig `yaml:"deployment" json:"deployment"`

	// Infrastructure configuration
	Infrastructure InfrastructureConfig `yaml:"infrastructure" json:"infrastructure"`

	// Pipeline settings
	Pipeline PipelineSettings `yaml:"pipeline" json:"pipeline"`
}

// GitConfig holds Git repository configuration
type GitConfig struct {
	Repository string `yaml:"repository" json:"repository"`
	Branch     string `yaml:"branch" json:"branch"`
	Commit     string `yaml:"commit" json:"commit"`
	Tag        string `yaml:"tag" json:"tag"`
}

// BuildConfig holds build-specific configuration
type BuildConfig struct {
	Type       string            `yaml:"type" json:"type"` // hugo, docker, etc.
	DockerFile string            `yaml:"dockerfile" json:"dockerfile"`
	Context    string            `yaml:"context" json:"context"`
	Registry   string            `yaml:"registry" json:"registry"`
	Image      string            `yaml:"image" json:"image"`
	Tags       []string          `yaml:"tags" json:"tags"`
	Args       map[string]string `yaml:"args" json:"args"`
	Hugo       HugoConfig        `yaml:"hugo" json:"hugo"`
}

// HugoConfig holds Hugo-specific build settings
type HugoConfig struct {
	Environment string `yaml:"environment" json:"environment"`
	Minify      bool   `yaml:"minify" json:"minify"`
	OutputDir   string `yaml:"output_dir" json:"output_dir"`
	ConfigFile  string `yaml:"config_file" json:"config_file"`
	BaseURL     string `yaml:"base_url" json:"base_url"`
}

// DeploymentConfig holds deployment configuration
type DeploymentConfig struct {
	Environment string                 `yaml:"environment" json:"environment"`
	Namespace   string                 `yaml:"namespace" json:"namespace"`
	Domain      string                 `yaml:"domain" json:"domain"`
	Resources   ResourceConfig         `yaml:"resources" json:"resources"`
	Strategy    DeploymentStrategy     `yaml:"strategy" json:"strategy"`
	Health      HealthCheckConfig      `yaml:"health" json:"health"`
	Secrets     map[string]SecretRef   `yaml:"secrets" json:"secrets"`
	ConfigMaps  map[string]ConfigMapRef `yaml:"config_maps" json:"config_maps"`
}

// ResourceConfig defines resource allocation
type ResourceConfig struct {
	CPU       int `yaml:"cpu" json:"cpu"`             // MHz
	Memory    int `yaml:"memory" json:"memory"`       // MB
	MemoryMax int `yaml:"memory_max" json:"memory_max"` // MB burst capacity
}

// DeploymentStrategy defines how deployments should be handled
type DeploymentStrategy struct {
	Type              string        `yaml:"type" json:"type"` // rolling, blue-green, canary
	MaxParallel       int           `yaml:"max_parallel" json:"max_parallel"`
	MinHealthyTime    time.Duration `yaml:"min_healthy_time" json:"min_healthy_time"`
	HealthyDeadline   time.Duration `yaml:"healthy_deadline" json:"healthy_deadline"`
	ProgressDeadline  time.Duration `yaml:"progress_deadline" json:"progress_deadline"`
	AutoRevert        bool          `yaml:"auto_revert" json:"auto_revert"`
	AutoPromote       bool          `yaml:"auto_promote" json:"auto_promote"`
	Canary            int           `yaml:"canary" json:"canary"`
}

// HealthCheckConfig defines health check settings
type HealthCheckConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Path     string        `yaml:"path" json:"path"`
	Interval time.Duration `yaml:"interval" json:"interval"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
	Retries  int           `yaml:"retries" json:"retries"`
}

// SecretRef references a secret in Vault
type SecretRef struct {
	VaultPath string `yaml:"vault_path" json:"vault_path"`
	Key       string `yaml:"key" json:"key"`
	EnvVar    string `yaml:"env_var" json:"env_var"`
}

// ConfigMapRef references a configuration value
type ConfigMapRef struct {
	Source string `yaml:"source" json:"source"`
	Key    string `yaml:"key" json:"key"`
	EnvVar string `yaml:"env_var" json:"env_var"`
}

// InfrastructureConfig holds infrastructure settings
type InfrastructureConfig struct {
	Provider    string                 `yaml:"provider" json:"provider"` // hetzner, aws, gcp
	Region      string                 `yaml:"region" json:"region"`
	ServerType  string                 `yaml:"server_type" json:"server_type"`
	Image       string                 `yaml:"image" json:"image"`
	Firewall    FirewallConfig         `yaml:"firewall" json:"firewall"`
	DNS         DNSConfig              `yaml:"dns" json:"dns"`
	Consul      ConsulConfig           `yaml:"consul" json:"consul"`
	Nomad       NomadConfig            `yaml:"nomad" json:"nomad"`
	Vault       VaultConfig            `yaml:"vault" json:"vault"`
	Terraform   TerraformConfig        `yaml:"terraform" json:"terraform"`
	Salt        SaltStackConfig        `yaml:"salt" json:"salt"`
}

// FirewallConfig holds firewall rule configuration
type FirewallConfig struct {
	Enabled bool              `yaml:"enabled" json:"enabled"`
	Rules   []FirewallRule    `yaml:"rules" json:"rules"`
}

// FirewallRule defines a single firewall rule
type FirewallRule struct {
	Direction string   `yaml:"direction" json:"direction"` // in, out
	Protocol  string   `yaml:"protocol" json:"protocol"`   // tcp, udp
	Port      string   `yaml:"port" json:"port"`
	SourceIPs []string `yaml:"source_ips" json:"source_ips"`
}

// DNSConfig holds DNS configuration
type DNSConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	ZoneID   string `yaml:"zone_id" json:"zone_id"`
	Record   string `yaml:"record" json:"record"`
	Type     string `yaml:"type" json:"type"`
	TTL      int    `yaml:"ttl" json:"ttl"`
}

// ConsulConfig holds Consul configuration
type ConsulConfig struct {
	Address    string            `yaml:"address" json:"address"`
	Datacenter string            `yaml:"datacenter" json:"datacenter"`
	Tags       []string          `yaml:"tags" json:"tags"`
	Meta       map[string]string `yaml:"meta" json:"meta"`
}

// NomadConfig holds Nomad configuration
type NomadConfig struct {
	Address     string   `yaml:"address" json:"address"`
	Region      string   `yaml:"region" json:"region"`
	Datacenter  string   `yaml:"datacenter" json:"datacenter"`
	Constraints []string `yaml:"constraints" json:"constraints"`
}

// VaultConfig holds Vault configuration
type VaultConfig struct {
	Address  string   `yaml:"address" json:"address"`
	Policies []string `yaml:"policies" json:"policies"`
}

// TerraformConfig holds Terraform configuration
type TerraformConfig struct {
	Backend       string            `yaml:"backend" json:"backend"`
	BackendConfig map[string]string `yaml:"backend_config" json:"backend_config"`
	Variables     map[string]string `yaml:"variables" json:"variables"`
}

// SaltStackConfig holds SaltStack configuration
type SaltStackConfig struct {
	Master   string   `yaml:"master" json:"master"`
	Targets  []string `yaml:"targets" json:"targets"`
	States   []string `yaml:"states" json:"states"`
	Pillar   string   `yaml:"pillar" json:"pillar"`
}

// PipelineSettings holds pipeline behavior settings
type PipelineSettings struct {
	Timeout             time.Duration   `yaml:"timeout" json:"timeout"`
	RetryAttempts       int             `yaml:"retry_attempts" json:"retry_attempts"`
	FailFast            bool            `yaml:"fail_fast" json:"fail_fast"`
	NotificationChannel string          `yaml:"notification_channel" json:"notification_channel"`
	Stages              []StageConfig   `yaml:"stages" json:"stages"`
	Triggers            []TriggerConfig `yaml:"triggers" json:"triggers"`
}

// StageConfig defines a pipeline stage
type StageConfig struct {
	Name         string            `yaml:"name" json:"name"`
	Type         string            `yaml:"type" json:"type"` // build, test, deploy, verify
	Enabled      bool              `yaml:"enabled" json:"enabled"`
	Dependencies []string          `yaml:"dependencies" json:"dependencies"`
	Timeout      time.Duration     `yaml:"timeout" json:"timeout"`
	Environment  map[string]string `yaml:"environment" json:"environment"`
	Commands     []string          `yaml:"commands" json:"commands"`
	Artifacts    []string          `yaml:"artifacts" json:"artifacts"`
}

// TriggerConfig defines what triggers the pipeline
type TriggerConfig struct {
	Type      string            `yaml:"type" json:"type"` // git_push, webhook, schedule
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Branches  []string          `yaml:"branches" json:"branches"`
	Schedule  string            `yaml:"schedule" json:"schedule"` // cron format
	Webhook   WebhookConfig     `yaml:"webhook" json:"webhook"`
	Conditions map[string]string `yaml:"conditions" json:"conditions"`
}

// WebhookConfig defines webhook trigger settings
type WebhookConfig struct {
	URL        string            `yaml:"url" json:"url"`
	Secret     string            `yaml:"secret" json:"secret"`
	Headers    map[string]string `yaml:"headers" json:"headers"`
	Events     []string          `yaml:"events" json:"events"`
}

// PipelineExecution represents a running pipeline execution
type PipelineExecution struct {
	ID          string                       `json:"id"`
	PipelineID  string                       `json:"pipeline_id"`
	Status      ExecutionStatus              `json:"status"`
	Trigger     TriggerInfo                  `json:"trigger"`
	StartTime   time.Time                    `json:"start_time"`
	EndTime     *time.Time                   `json:"end_time,omitempty"`
	Duration    time.Duration                `json:"duration"`
	Stages      []StageExecution             `json:"stages"`
	Artifacts   []ArtifactInfo               `json:"artifacts"`
	Environment map[string]string            `json:"environment"`
	Config      *PipelineConfig              `json:"config"`
}

// ExecutionStatus represents the status of a pipeline execution
type ExecutionStatus string

const (
	StatusPending    ExecutionStatus = "pending"
	StatusRunning    ExecutionStatus = "running"
	StatusSucceeded  ExecutionStatus = "succeeded"
	StatusFailed     ExecutionStatus = "failed"
	StatusCancelled  ExecutionStatus = "cancelled"
	StatusRolledBack ExecutionStatus = "rolled_back"
)

// TriggerInfo contains information about what triggered the pipeline
type TriggerInfo struct {
	Type      string            `json:"type"`
	Source    string            `json:"source"`
	User      string            `json:"user"`
	Message   string            `json:"message"`
	Metadata  map[string]string `json:"metadata"`
	Timestamp time.Time         `json:"timestamp"`
}

// StageExecution represents the execution of a single stage
type StageExecution struct {
	Name      string                 `json:"name"`
	Status    ExecutionStatus        `json:"status"`
	StartTime time.Time              `json:"start_time"`
	EndTime   *time.Time             `json:"end_time,omitempty"`
	Duration  time.Duration          `json:"duration"`
	Logs      []LogEntry             `json:"logs"`
	Artifacts []ArtifactInfo         `json:"artifacts"`
	Metadata  map[string]interface{} `json:"metadata"`
	Error     string                 `json:"error,omitempty"`
}

// LogEntry represents a log entry from stage execution
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	Stage     string    `json:"stage"`
}

// ArtifactInfo represents information about a build artifact
type ArtifactInfo struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"` // docker_image, file, archive
	Location    string            `json:"location"`
	Size        int64             `json:"size"`
	Checksum    string            `json:"checksum"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
}

// PipelineOrchestrator manages pipeline execution
type PipelineOrchestrator struct {
	config          *PipelineConfig
	execution       *PipelineExecution
	currentStage    int
	saltClient      SaltClient
	terraformClient TerraformClient
	nomadClient     NomadClient
	vaultClient     VaultClient
	consulClient    ConsulClient
	buildClient     BuildClient
	statusChan      chan StatusUpdate
}

// SaltClient interface for SaltStack operations
type SaltClient interface {
	ExecuteState(ctx context.Context, targets []string, state string, pillar map[string]interface{}) error
	ExecuteOrchestrate(ctx context.Context, orchestrate string, pillar map[string]interface{}) error
	GetJobStatus(ctx context.Context, jobID string) (*SaltJobStatus, error)
	Ping(ctx context.Context, targets []string) error
}

// TerraformClient interface for Terraform operations
type TerraformClient interface {
	Plan(ctx context.Context, workdir string, vars map[string]string) (*TerraformPlan, error)
	Apply(ctx context.Context, workdir string, vars map[string]string) (*TerraformOutput, error)
	Destroy(ctx context.Context, workdir string, vars map[string]string) error
	GetState(ctx context.Context, workdir string) (*TerraformState, error)
}

// NomadClient interface for Nomad operations
type NomadClient interface {
	SubmitJob(ctx context.Context, jobSpec string) (*NomadJobStatus, error)
	GetJobStatus(ctx context.Context, jobID string) (*NomadJobStatus, error)
	StopJob(ctx context.Context, jobID string, purge bool) error
	GetAllocations(ctx context.Context, jobID string) ([]*NomadAllocation, error)
}

// VaultClient interface for Vault operations
type VaultClient interface {
	ReadSecret(ctx context.Context, path string) (map[string]interface{}, error)
	WriteSecret(ctx context.Context, path string, data map[string]interface{}) error
	DeleteSecret(ctx context.Context, path string) error
	ListSecrets(ctx context.Context, path string) ([]string, error)
}

// ConsulClient interface for Consul operations
type ConsulClient interface {
	GetKV(ctx context.Context, key string) (string, error)
	PutKV(ctx context.Context, key, value string) error
	DeleteKV(ctx context.Context, key string) error
	RegisterService(ctx context.Context, service *ConsulService) error
	DeregisterService(ctx context.Context, serviceID string) error
}

// BuildClient interface for build operations
type BuildClient interface {
	BuildHugo(ctx context.Context, config HugoConfig) (*BuildResult, error)
	BuildDockerImage(ctx context.Context, config BuildConfig) (*BuildResult, error)
	PushDockerImage(ctx context.Context, image, registry string) error
}

// StatusUpdate represents a pipeline status update
type StatusUpdate struct {
	ExecutionID string                 `json:"execution_id"`
	Stage       string                 `json:"stage"`
	Status      ExecutionStatus        `json:"status"`
	Message     string                 `json:"message"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Supporting types for client interfaces

// SaltJobStatus represents the status of a Salt job
type SaltJobStatus struct {
	ID       string            `json:"id"`
	Status   string            `json:"status"`
	Result   map[string]interface{} `json:"result"`
	Success  bool              `json:"success"`
	Duration time.Duration     `json:"duration"`
}

// TerraformPlan represents a Terraform plan
type TerraformPlan struct {
	ResourceActions []ResourceAction `json:"resource_actions"`
	HasChanges      bool             `json:"has_changes"`
	Output          string           `json:"output"`
}

// ResourceAction represents a planned action on a resource
type ResourceAction struct {
	Resource string `json:"resource"`
	Action   string `json:"action"` // create, update, delete
}

// TerraformOutput represents Terraform apply output
type TerraformOutput struct {
	Success   bool              `json:"success"`
	Outputs   map[string]string `json:"outputs"`
	Resources []ResourceInfo    `json:"resources"`
}

// ResourceInfo represents information about a Terraform resource
type ResourceInfo struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Address    string `json:"address"`
	Status     string `json:"status"`
}

// TerraformState represents Terraform state
type TerraformState struct {
	Version   int            `json:"version"`
	Resources []ResourceInfo `json:"resources"`
	Outputs   map[string]string `json:"outputs"`
}

// NomadJobStatus represents the status of a Nomad job
type NomadJobStatus struct {
	ID          string             `json:"id"`
	Status      string             `json:"status"`
	Running     int                `json:"running"`
	Desired     int                `json:"desired"`
	Failed      int                `json:"failed"`
	Allocations []*NomadAllocation `json:"allocations"`
}

// NomadAllocation represents a Nomad allocation
type NomadAllocation struct {
	ID        string            `json:"id"`
	JobID     string            `json:"job_id"`
	Status    string            `json:"status"`
	NodeID    string            `json:"node_id"`
	Tasks     map[string]string `json:"tasks"`
}

// ConsulService represents a Consul service registration
type ConsulService struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Tags    []string          `json:"tags"`
	Port    int               `json:"port"`
	Address string            `json:"address"`
	Meta    map[string]string `json:"meta"`
	Check   *ConsulCheck      `json:"check,omitempty"`
}

// ConsulCheck represents a Consul health check
type ConsulCheck struct {
	Name         string        `json:"name"`
	Type         string        `json:"type"`
	HTTP         string        `json:"http,omitempty"`
	Interval     time.Duration `json:"interval"`
	Timeout      time.Duration `json:"timeout"`
	DeregisterTTL time.Duration `json:"deregister_ttl,omitempty"`
}

// BuildResult represents the result of a build operation
type BuildResult struct {
	Success    bool              `json:"success"`
	Artifacts  []ArtifactInfo    `json:"artifacts"`
	Logs       []LogEntry        `json:"logs"`
	Duration   time.Duration     `json:"duration"`
	Metadata   map[string]string `json:"metadata"`
	Error      string            `json:"error,omitempty"`
}

// PipelineError represents an error during pipeline execution
type PipelineError struct {
	Type       string                 `json:"type"`
	Stage      string                 `json:"stage"`
	Message    string                 `json:"message"`
	Cause      error                  `json:"cause,omitempty"`
	Retryable  bool                   `json:"retryable"`
	Metadata   map[string]interface{} `json:"metadata"`
	Timestamp  time.Time              `json:"timestamp"`
}

func (e *PipelineError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s/%s] %s: %v", e.Type, e.Stage, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s/%s] %s", e.Type, e.Stage, e.Message)
}

// DefaultPipelineConfig returns a default configuration for Helen Hugo website
func DefaultPipelineConfig(appName string) *PipelineConfig {
	return &PipelineConfig{
		AppName: appName,
		Version: time.Now().Format("20060102150405"),
		Git: GitConfig{
			Branch: "main",
		},
		Build: BuildConfig{
			Type:       "hugo",
			DockerFile: "Dockerfile",
			Context:    ".",
			Registry:   "registry.cybermonkey.net.au",
			Hugo: HugoConfig{
				Environment: "production",
				Minify:      true,
				OutputDir:   "public",
			},
		},
		Deployment: DeploymentConfig{
			Environment: "production",
			Resources: ResourceConfig{
				CPU:       500,
				Memory:    256,
				MemoryMax: 512,
			},
			Strategy: DeploymentStrategy{
				Type:              "rolling",
				MaxParallel:       1,
				MinHealthyTime:    30 * time.Second,
				HealthyDeadline:   2 * time.Minute,
				ProgressDeadline:  10 * time.Minute,
				AutoRevert:        true,
				AutoPromote:       true,
				Canary:            1,
			},
			Health: HealthCheckConfig{
				Enabled:  true,
				Path:     "/health",
				Interval: 30 * time.Second,
				Timeout:  5 * time.Second,
				Retries:  3,
			},
		},
		Infrastructure: InfrastructureConfig{
			Provider:   "hetzner",
			Region:     "nbg1",
			ServerType: "cx21",
			Image:      "ubuntu-22.04",
			Consul: ConsulConfig{
				Address:    fmt.Sprintf("localhost:%d", shared.PortConsul),
				Datacenter: "dc1",
			},
			Nomad: NomadConfig{
				Address:    "http://localhost:4646",
				Region:     "global",
				Datacenter: "dc1",
			},
			Vault: VaultConfig{
				Address: "http://localhost:8179",
			},
			Salt: SaltStackConfig{
				Master:  "salt-master.cybermonkey.net.au",
				Targets: []string{"*"},
			},
		},
		Pipeline: PipelineSettings{
			Timeout:       30 * time.Minute,
			RetryAttempts: 3,
			FailFast:      true,
			Stages: []StageConfig{
				{
					Name:    "build",
					Type:    "build",
					Enabled: true,
					Timeout: 10 * time.Minute,
				},
				{
					Name:         "infrastructure",
					Type:         "deploy",
					Enabled:      true,
					Dependencies: []string{"build"},
					Timeout:      10 * time.Minute,
				},
				{
					Name:         "deploy",
					Type:         "deploy",
					Enabled:      true,
					Dependencies: []string{"infrastructure"},
					Timeout:      10 * time.Minute,
				},
				{
					Name:         "verify",
					Type:         "verify",
					Enabled:      true,
					Dependencies: []string{"deploy"},
					Timeout:      5 * time.Minute,
				},
			},
		},
	}
}
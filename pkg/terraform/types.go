// pkg/terraform/types.go

package terraform

import (
	"time"
)

type K3sConfig struct {
	ServerName   string
	ServerType   string
	Location     string
	SSHKeyName   string
	K3sRole      string
	K3sServerURL string
	K3sToken     string
}

type DockerService struct {
	Name          string
	Image         string
	ProjectName   string
	Ports         []DockerPort
	Volumes       []DockerVolume
	EnvVars       []DockerEnvVar
	Networks      []string
	RestartPolicy string
	HealthCheck   *DockerHealthCheck
	PullTriggers  []string
}

type DockerPort struct {
	Internal int
	External int
	Protocol string
}

type DockerVolume struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

type DockerEnvVar struct {
	Key   string
	Value string
}

type DockerHealthCheck struct {
	Test        []string
	Interval    string
	Timeout     string
	Retries     int
	StartPeriod string
}

type DockerNetwork struct {
	Name   string
	Driver string
	Subnet string
}

type DockerVolumeDefinition struct {
	Name   string
	Driver string
}

type DockerComposeConfig struct {
	ProjectName string
	ComposeFile string
	Services    []DockerService
	Networks    []DockerNetwork
	Volumes     []DockerVolumeDefinition
	UseHetzner  bool
	RemoteHost  string
}

type HetznerServer struct {
	Name     string
	Image    string
	Type     string
	Location string
	Role     string
	UserData string
	Labels   map[string]string
}

type HetznerNetwork struct {
	Name        string
	IPRange     string
	Zone        string
	SubnetRange string
}

type HetznerLoadBalancer struct {
	Name     string
	Type     string
	Location string
	Services []HetznerLBService
}

type HetznerLBService struct {
	Name            string
	Protocol        string
	ListenPort      int
	DestinationPort int
	HealthCheck     *HetznerHealthCheck
}

type HetznerHealthCheck struct {
	Protocol string
	Port     int
	Interval int
	Timeout  int
	Retries  int
	HTTP     *HetznerHTTPHealthCheck
}

type HetznerHTTPHealthCheck struct {
	Path        string
	StatusCodes []int
}

type HetznerFirewall struct {
	Name  string
	Rules []HetznerFirewallRule
}

type HetznerFirewallRule struct {
	Direction string
	Port      string
	Protocol  string
	SourceIPs []string
}

type HetznerInfraConfig struct {
	ProjectName   string
	SSHKeyName    string
	Servers       []HetznerServer
	Networks      []HetznerNetwork
	LoadBalancers []HetznerLoadBalancer
	Firewalls     []HetznerFirewall
}

type WorkflowStep struct {
	Name        string
	Command     string
	Args        []string
	WorkingDir  string
	Environment map[string]string
}

type TerraformWorkflow struct {
	Name        string
	Description string
	WorkingDir  string
	PreSteps    []WorkflowStep
	PostSteps   []WorkflowStep
	Variables   map[string]interface{}
	AutoApprove bool
	BackupState bool
}

type ProviderConfig struct {
	Name    string
	Source  string
	Version string
	Config  map[string]interface{}
}

type BackendConfig struct {
	Type   string
	Config map[string]string
}

type ModuleConfig struct {
	Name    string
	Source  string
	Version string
	Inputs  map[string]interface{}
}

// ConsulVaultTemplate holds data for Consul-Vault integration templates
type ConsulVaultTemplate struct {
	ConsulAddr      string
	VaultAddr       string
	Datacenter      string
	ServicePrefix   string
	KVPrefix        string
	UseServices     bool
	UseConsulKV     bool
	UseVaultSecrets bool
}

// UpstreamService represents an upstream service configuration
type UpstreamService struct {
	Name       string
	LocalPort  int
	Datacenter string
}

// ServiceIntention represents a service intention configuration
type ServiceIntention struct {
	Source      string
	Destination string
	Action      string
}

// Workspace represents a Terraform workspace for a component
type Workspace struct {
	Component   string    `json:"component"`
	Environment string    `json:"environment"`
	Path        string    `json:"path"`
	LockID      string    `json:"lock_id,omitempty"`
	LockTime    time.Time `json:"lock_time,omitempty"`
}

// PlanResult represents the result of a Terraform plan
type PlanResult struct {
	Success         bool                   `json:"success"`
	ChangesPresent  bool                   `json:"changes_present"`
	ResourceChanges []ResourceChange       `json:"resource_changes"`
	PlanFile        string                 `json:"plan_file,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

// ResourceChange represents a single resource change in a plan
type ResourceChange struct {
	Address      string   `json:"address"`
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	Action       []string `json:"action"`
	BeforeValues any      `json:"before_values,omitempty"`
	AfterValues  any      `json:"after_values,omitempty"`
}

// ApplyResult represents the result of a Terraform apply
type ApplyResult struct {
	Success    bool              `json:"success"`
	Outputs    map[string]Output `json:"outputs"`
	SnapshotID string            `json:"snapshot_id,omitempty"`
	Error      string            `json:"error,omitempty"`
	Rollback   *RollbackResult   `json:"rollback,omitempty"`
}

// Output represents a Terraform output value
type Output struct {
	Value     any    `json:"value"`
	Type      string `json:"type"`
	Sensitive bool   `json:"sensitive"`
}

// RollbackResult represents the result of a rollback operation
type RollbackResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ResourceList represents a list of Terraform resources
type ResourceList struct {
	Resources []string `json:"resources"`
	Count     int      `json:"count"`
}

// ResourceState represents the state of a Terraform resource
type ResourceState struct {
	Resource string `json:"resource"`
	State    string `json:"state"`
}

// DeploymentStatus represents the status of a deployment
type DeploymentStatus struct {
	DeploymentID string                       `json:"deployment_id"`
	Environment  string                       `json:"environment"`
	StartedAt    time.Time                    `json:"started_at"`
	CompletedAt  *time.Time                   `json:"completed_at,omitempty"`
	Status       string                       `json:"status"`
	Components   map[string]ComponentStatus   `json:"components"`
	Error        string                       `json:"error,omitempty"`
}

// ComponentStatus represents the status of a single component deployment
type ComponentStatus struct {
	Success  bool              `json:"success"`
	Duration time.Duration     `json:"duration"`
	Outputs  map[string]Output `json:"outputs,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// ServiceDefinition defines a service that can be deployed with Hecate
type ServiceDefinition struct {
	Name           string            `json:"name"`
	DisplayName    string            `json:"display_name"`
	Description    string            `json:"description"`
	Category       string            `json:"category"`
	Icon           string            `json:"icon,omitempty"`
	NomadJobPath   string            `json:"nomad_job_path,omitempty"`
	TerraformPath  string            `json:"terraform_path,omitempty"`
	Dependencies   []string          `json:"dependencies"`
	Ports          []ServicePort     `json:"ports"`
	AuthPolicy     string            `json:"auth_policy"`
	HealthEndpoint string            `json:"health_endpoint"`
	Subdomain      string            `json:"subdomain"`
	Resources      ResourceRequirements `json:"resources"`
	Configuration  map[string]any    `json:"configuration"`
}

// ServicePort defines a port used by a service
type ServicePort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Public   bool   `json:"public"`
}

// ResourceRequirements defines resource requirements for a service
type ResourceRequirements struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
}

// Constants for common values
const (
	// Backend types
	BackendS3       = "s3"
	BackendAzure    = "azurerm"
	BackendGCS      = "gcs"
	BackendConsul   = "consul"
	BackendLocal    = "local"
	
	// Provider types
	ProviderAWS        = "aws"
	ProviderAzure      = "azurerm"
	ProviderGoogle     = "google"
	ProviderHetzner    = "hcloud"
	ProviderCloudflare = "cloudflare"
	
	// Component types
	ComponentVault    = "vault"
	ComponentConsul   = "consul"
	ComponentBoundary = "boundary"
	ComponentHecate   = "hecate"
	ComponentHera     = "hera"
	
	// Deployment statuses
	StatusInitializing = "initializing"
	StatusPlanning     = "planning"
	StatusApplying     = "applying"
	StatusCompleted    = "completed"
	StatusFailed       = "failed"
	StatusRollingBack  = "rolling_back"
	
	// Service categories
	CategoryMonitoring = "monitoring"
	CategorySecurity   = "security"
	CategoryDatabase   = "database"
	CategoryMessaging  = "messaging"
	CategoryStorage    = "storage"
)

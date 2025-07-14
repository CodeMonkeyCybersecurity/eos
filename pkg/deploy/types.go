package deploy

import (
	"context"
	"fmt"
	"time"
)

// DeploymentManager orchestrates deployments through the Salt → Terraform → Nomad hierarchy
type DeploymentManager struct {
	saltClient      *SaltClient
	terraformClient *TerraformClient
	nomadClient     *NomadClient
	vaultClient     *VaultClient
	consulClient    *ConsulClient
	config          *DeploymentConfig
}

// DeploymentConfig holds configuration for the deployment manager
type DeploymentConfig struct {
	WorkDir       string                 `yaml:"work_dir" json:"work_dir"`
	SaltConfig    SaltClientConfig       `yaml:"salt" json:"salt"`
	TerraformConfig TerraformClientConfig `yaml:"terraform" json:"terraform"`
	NomadConfig   NomadClientConfig      `yaml:"nomad" json:"nomad"`
	VaultConfig   VaultClientConfig      `yaml:"vault" json:"vault"`
	ConsulConfig  ConsulClientConfig     `yaml:"consul" json:"consul"`
}

// SaltClientConfig holds SaltStack client configuration
type SaltClientConfig struct {
	MasterURL string            `yaml:"master_url" json:"master_url"`
	Username  string            `yaml:"username" json:"username"`
	Password  string            `yaml:"password" json:"password"`
	Token     string            `yaml:"token" json:"token"`
	EAuth     string            `yaml:"eauth" json:"eauth"`
	Timeout   time.Duration     `yaml:"timeout" json:"timeout"`
	Headers   map[string]string `yaml:"headers" json:"headers"`
	TLS       TLSConfig         `yaml:"tls" json:"tls"`
}

// TerraformClientConfig holds Terraform client configuration
type TerraformClientConfig struct {
	WorkingDir    string            `yaml:"working_dir" json:"working_dir"`
	StateBackend  string            `yaml:"state_backend" json:"state_backend"`
	BackendConfig map[string]string `yaml:"backend_config" json:"backend_config"`
	Variables     map[string]string `yaml:"variables" json:"variables"`
	BinaryPath    string            `yaml:"binary_path" json:"binary_path"`
	PluginCache   string            `yaml:"plugin_cache" json:"plugin_cache"`
	Parallelism   int               `yaml:"parallelism" json:"parallelism"`
	Timeout       time.Duration     `yaml:"timeout" json:"timeout"`
}

// NomadClientConfig holds Nomad client configuration
type NomadClientConfig struct {
	Address   string        `yaml:"address" json:"address"`
	Region    string        `yaml:"region" json:"region"`
	Namespace string        `yaml:"namespace" json:"namespace"`
	Token     string        `yaml:"token" json:"token"`
	TLS       TLSConfig     `yaml:"tls" json:"tls"`
	Timeout   time.Duration `yaml:"timeout" json:"timeout"`
}

// VaultClientConfig holds Vault client configuration
type VaultClientConfig struct {
	Address   string        `yaml:"address" json:"address"`
	Token     string        `yaml:"token" json:"token"`
	Namespace string        `yaml:"namespace" json:"namespace"`
	TLS       TLSConfig     `yaml:"tls" json:"tls"`
	Timeout   time.Duration `yaml:"timeout" json:"timeout"`
}

// ConsulClientConfig holds Consul client configuration
type ConsulClientConfig struct {
	Address    string        `yaml:"address" json:"address"`
	Datacenter string        `yaml:"datacenter" json:"datacenter"`
	Token      string        `yaml:"token" json:"token"`
	TLS        TLSConfig     `yaml:"tls" json:"tls"`
	Timeout    time.Duration `yaml:"timeout" json:"timeout"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled            bool   `yaml:"enabled" json:"enabled"`
	CertFile           string `yaml:"cert_file" json:"cert_file"`
	KeyFile            string `yaml:"key_file" json:"key_file"`
	CAFile             string `yaml:"ca_file" json:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

// SaltClient implements the cicd.SaltClient interface
type SaltClient struct {
	config     SaltClientConfig
	httpClient HTTPClient
}

// TerraformClient implements the cicd.TerraformClient interface
type TerraformClient struct {
	config     TerraformClientConfig
	workingDir string
	binaryPath string
}

// NomadClient implements the cicd.NomadClient interface
type NomadClient struct {
	config     NomadClientConfig
	httpClient HTTPClient
}

// VaultClient implements the cicd.VaultClient interface
type VaultClient struct {
	config     VaultClientConfig
	httpClient HTTPClient
}

// ConsulClient implements the cicd.ConsulClient interface
type ConsulClient struct {
	config     ConsulClientConfig
	httpClient HTTPClient
}

// HTTPClient interface for making HTTP requests
type HTTPClient interface {
	Get(ctx context.Context, url string, headers map[string]string) (*HTTPResponse, error)
	Post(ctx context.Context, url string, headers map[string]string, body []byte) (*HTTPResponse, error)
	Put(ctx context.Context, url string, headers map[string]string, body []byte) (*HTTPResponse, error)
	Delete(ctx context.Context, url string, headers map[string]string) (*HTTPResponse, error)
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
}

// SaltJobRequest represents a Salt job execution request
type SaltJobRequest struct {
	Client   string                 `json:"client"`
	Target   string                 `json:"tgt"`
	Function string                 `json:"fun"`
	Args     []interface{}          `json:"arg,omitempty"`
	Kwargs   map[string]interface{} `json:"kwarg,omitempty"`
	Timeout  int                    `json:"timeout,omitempty"`
}

// SaltJobResponse represents a Salt job execution response
type SaltJobResponse struct {
	Return []map[string]interface{} `json:"return"`
	Error  string                   `json:"error,omitempty"`
}

// SaltOrchestrationRequest represents a Salt orchestration request
type SaltOrchestrationRequest struct {
	Client string                 `json:"client"`
	Fun    string                 `json:"fun"`
	Mods   string                 `json:"mods"`
	Pillar map[string]interface{} `json:"pillar,omitempty"`
}

// TerraformWorkspace represents a Terraform workspace configuration
type TerraformWorkspace struct {
	Name         string            `json:"name"`
	Directory    string            `json:"directory"`
	Variables    map[string]string `json:"variables"`
	Backend      string            `json:"backend"`
	State        string            `json:"state"`
	LastApplied  *time.Time        `json:"last_applied,omitempty"`
	LastModified *time.Time        `json:"last_modified,omitempty"`
}

// NomadJobSpec represents a Nomad job specification
type NomadJobSpec struct {
	Job      *NomadJob             `json:"Job"`
	Metadata map[string]interface{} `json:"Metadata,omitempty"`
}

// NomadJob represents a Nomad job definition
type NomadJob struct {
	ID          string                `json:"ID"`
	Name        string                `json:"Name"`
	Type        string                `json:"Type"`
	Priority    int                   `json:"Priority"`
	Datacenters []string              `json:"Datacenters"`
	Region      string                `json:"Region,omitempty"`
	Namespace   string                `json:"Namespace,omitempty"`
	TaskGroups  []*NomadTaskGroup     `json:"TaskGroups"`
	Update      *NomadUpdateStrategy  `json:"Update,omitempty"`
	Meta        map[string]string     `json:"Meta,omitempty"`
}

// NomadTaskGroup represents a Nomad task group
type NomadTaskGroup struct {
	Name     string                `json:"Name"`
	Count    int                   `json:"Count"`
	Tasks    []*NomadTask          `json:"Tasks"`
	Networks []*NomadNetwork       `json:"Networks,omitempty"`
	Services []*NomadService       `json:"Services,omitempty"`
	Restart  *NomadRestartPolicy   `json:"Restart,omitempty"`
	Update   *NomadUpdateStrategy  `json:"Update,omitempty"`
}

// NomadTask represents a Nomad task
type NomadTask struct {
	Name        string                 `json:"Name"`
	Driver      string                 `json:"Driver"`
	Config      map[string]interface{} `json:"Config"`
	Resources   *NomadResources        `json:"Resources"`
	Env         map[string]string      `json:"Env,omitempty"`
	Services    []*NomadService        `json:"Services,omitempty"`
	Vault       *NomadVault            `json:"Vault,omitempty"`
	Templates   []*NomadTemplate       `json:"Templates,omitempty"`
	Constraints []*NomadConstraint     `json:"Constraints,omitempty"`
}

// NomadResources represents Nomad resource requirements
type NomadResources struct {
	CPU      int               `json:"CPU"`
	MemoryMB int               `json:"MemoryMB"`
	DiskMB   int               `json:"DiskMB,omitempty"`
	Networks []*NomadNetwork   `json:"Networks,omitempty"`
}

// NomadNetwork represents a Nomad network configuration
type NomadNetwork struct {
	Mode         string          `json:"Mode,omitempty"`
	Device       string          `json:"Device,omitempty"`
	CIDR         string          `json:"CIDR,omitempty"`
	IP           string          `json:"IP,omitempty"`
	MBits        int             `json:"MBits,omitempty"`
	DynamicPorts []*NomadPort    `json:"DynamicPorts,omitempty"`
	StaticPorts  []*NomadPort    `json:"StaticPorts,omitempty"`
}

// NomadPort represents a Nomad port mapping
type NomadPort struct {
	Label  string `json:"Label"`
	Value  int    `json:"Value,omitempty"`
	To     int    `json:"To,omitempty"`
	HostIP string `json:"HostIP,omitempty"`
}

// NomadService represents a Nomad service definition
type NomadService struct {
	Name        string             `json:"Name"`
	Tags        []string           `json:"Tags,omitempty"`
	PortLabel   string             `json:"PortLabel,omitempty"`
	AddressMode string             `json:"AddressMode,omitempty"`
	Checks      []*NomadCheck      `json:"Checks,omitempty"`
	Connect     *NomadConnect      `json:"Connect,omitempty"`
	Meta        map[string]string  `json:"Meta,omitempty"`
}

// NomadCheck represents a Nomad health check
type NomadCheck struct {
	Name         string            `json:"Name"`
	Type         string            `json:"Type"`
	Command      string            `json:"Command,omitempty"`
	Args         []string          `json:"Args,omitempty"`
	Path         string            `json:"Path,omitempty"`
	Protocol     string            `json:"Protocol,omitempty"`
	PortLabel    string            `json:"PortLabel,omitempty"`
	Interval     time.Duration     `json:"Interval"`
	Timeout      time.Duration     `json:"Timeout"`
	InitialDelay time.Duration     `json:"InitialDelay,omitempty"`
	Headers      map[string]string `json:"Headers,omitempty"`
}

// NomadConnect represents Consul Connect configuration
type NomadConnect struct {
	SidecarService *NomadSidecarService `json:"SidecarService,omitempty"`
	SidecarTask    *NomadSidecarTask    `json:"SidecarTask,omitempty"`
}

// NomadSidecarService represents a Connect sidecar service
type NomadSidecarService struct {
	Tags  []string          `json:"Tags,omitempty"`
	Port  string            `json:"Port,omitempty"`
	Proxy *NomadProxy       `json:"Proxy,omitempty"`
}

// NomadSidecarTask represents a Connect sidecar task
type NomadSidecarTask struct {
	Name      string                 `json:"Name,omitempty"`
	Driver    string                 `json:"Driver,omitempty"`
	Config    map[string]interface{} `json:"Config,omitempty"`
	Resources *NomadResources        `json:"Resources,omitempty"`
}

// NomadProxy represents Connect proxy configuration
type NomadProxy struct {
	LocalServiceAddress string               `json:"LocalServiceAddress,omitempty"`
	LocalServicePort    int                  `json:"LocalServicePort,omitempty"`
	Upstreams           []*NomadUpstream     `json:"Upstreams,omitempty"`
	Config              map[string]interface{} `json:"Config,omitempty"`
}

// NomadUpstream represents a Connect upstream service
type NomadUpstream struct {
	DestinationName string `json:"DestinationName"`
	LocalBindPort   int    `json:"LocalBindPort"`
}

// NomadVault represents Vault integration configuration
type NomadVault struct {
	Policies    []string `json:"Policies,omitempty"`
	Env         bool     `json:"Env,omitempty"`
	ChangeMode  string   `json:"ChangeMode,omitempty"`
	Changesignal string   `json:"ChangeSignal,omitempty"`
}

// NomadTemplate represents a Nomad template
type NomadTemplate struct {
	SourcePath   string        `json:"SourcePath,omitempty"`
	DestPath     string        `json:"DestPath"`
	EmbeddedTmpl string        `json:"EmbeddedTmpl,omitempty"`
	ChangeMode   string        `json:"ChangeMode,omitempty"`
	ChangeSignal string        `json:"ChangeSignal,omitempty"`
	Splay        time.Duration `json:"Splay,omitempty"`
	Perms        string        `json:"Perms,omitempty"`
	Uid          int           `json:"Uid,omitempty"`
	Gid          int           `json:"Gid,omitempty"`
	LeftDelim    string        `json:"LeftDelim,omitempty"`
	RightDelim   string        `json:"RightDelim,omitempty"`
	Envvars      bool          `json:"Envvars,omitempty"`
	VaultGrace   time.Duration `json:"VaultGrace,omitempty"`
}

// NomadConstraint represents a Nomad constraint
type NomadConstraint struct {
	LTarget string `json:"LTarget,omitempty"`
	RTarget string `json:"RTarget,omitempty"`
	Operand string `json:"Operand"`
}

// NomadRestartPolicy represents a Nomad restart policy
type NomadRestartPolicy struct {
	Attempts int           `json:"Attempts"`
	Interval time.Duration `json:"Interval"`
	Delay    time.Duration `json:"Delay"`
	Mode     string        `json:"Mode"`
}

// NomadUpdateStrategy represents a Nomad update strategy
type NomadUpdateStrategy struct {
	Stagger          time.Duration `json:"Stagger,omitempty"`
	MaxParallel      int           `json:"MaxParallel,omitempty"`
	HealthCheck      string        `json:"HealthCheck,omitempty"`
	MinHealthyTime   time.Duration `json:"MinHealthyTime,omitempty"`
	HealthyDeadline  time.Duration `json:"HealthyDeadline,omitempty"`
	ProgressDeadline time.Duration `json:"ProgressDeadline,omitempty"`
	AutoRevert       bool          `json:"AutoRevert,omitempty"`
	AutoPromote      bool          `json:"AutoPromote,omitempty"`
	Canary           int           `json:"Canary,omitempty"`
}

// VaultSecret represents a Vault secret
type VaultSecret struct {
	Path     string                 `json:"path"`
	Data     map[string]interface{} `json:"data"`
	Metadata VaultSecretMetadata    `json:"metadata"`
}

// VaultSecretMetadata represents Vault secret metadata
type VaultSecretMetadata struct {
	CreatedTime  time.Time `json:"created_time"`
	DeletionTime string    `json:"deletion_time"`
	Destroyed    bool      `json:"destroyed"`
	Version      int       `json:"version"`
}

// ConsulKVPair represents a Consul key-value pair
type ConsulKVPair struct {
	Key         string `json:"Key"`
	Value       string `json:"Value"`
	Flags       uint64 `json:"Flags"`
	Session     string `json:"Session,omitempty"`
	LockIndex   uint64 `json:"LockIndex"`
	ModifyIndex uint64 `json:"ModifyIndex"`
	CreateIndex uint64 `json:"CreateIndex"`
}

// DeploymentError represents an error during deployment operations
type DeploymentError struct {
	Type      string                 `json:"type"`
	Component string                 `json:"component"` // salt, terraform, nomad, vault, consul
	Stage     string                 `json:"stage"`
	Message   string                 `json:"message"`
	Cause     error                  `json:"cause,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
	Retryable bool                   `json:"retryable"`
}

func (e *DeploymentError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s/%s/%s] %s: %v", e.Type, e.Component, e.Stage, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s/%s/%s] %s", e.Type, e.Component, e.Stage, e.Message)
}

// DefaultDeploymentConfig returns a default deployment configuration
func DefaultDeploymentConfig() *DeploymentConfig {
	return &DeploymentConfig{
		WorkDir: "/tmp/eos-deploy",
		SaltConfig: SaltClientConfig{
			MasterURL: "http://salt-master.cybermonkey.net.au:8000",
			EAuth:     "pam",
			Timeout:   5 * time.Minute,
		},
		TerraformConfig: TerraformClientConfig{
			WorkingDir:  "/srv/terraform",
			StateBackend: "consul",
			BackendConfig: map[string]string{
				"address": "localhost:8500",
				"path":    "terraform/state",
				"lock":    "true",
			},
			BinaryPath:  "terraform",
			Parallelism: 10,
			Timeout:     30 * time.Minute,
		},
		NomadConfig: NomadClientConfig{
			Address: "http://localhost:4646",
			Region:  "global",
			Timeout: 5 * time.Minute,
		},
		VaultConfig: VaultClientConfig{
			Address: "http://localhost:8179",
			Timeout: 30 * time.Second,
		},
		ConsulConfig: ConsulClientConfig{
			Address:    "localhost:8500",
			Datacenter: "dc1",
			Timeout:    30 * time.Second,
		},
	}
}
// pkg/terraform/types.go

package terraform

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

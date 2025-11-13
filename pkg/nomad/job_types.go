// pkg/nomad/job_types.go
package nomad

import "time"

// NomadJobConfig represents configuration for Nomad job generation
type NomadJobConfig struct {
	// Basic job configuration
	ServiceName string `json:"service_name" yaml:"service_name"`
	Region      string `json:"region" yaml:"region"`
	Datacenter  string `json:"datacenter" yaml:"datacenter"`
	JobType     string `json:"job_type" yaml:"job_type"` // service, batch, system
	Priority    int    `json:"priority" yaml:"priority"`
	Replicas    int    `json:"replicas" yaml:"replicas"`

	// Container configuration
	Driver  string   `json:"driver" yaml:"driver"` // docker, exec, raw_exec
	Image   string   `json:"image" yaml:"image"`
	Command string   `json:"command,omitempty" yaml:"command,omitempty"`
	Args    []string `json:"args,omitempty" yaml:"args,omitempty"`

	// Networking
	Networks    []NetworkConfig `json:"networks,omitempty" yaml:"networks,omitempty"`
	ServicePort string          `json:"service_port,omitempty" yaml:"service_port,omitempty"`
	ServiceTags []string        `json:"service_tags,omitempty" yaml:"service_tags,omitempty"`
	Ports       []string        `json:"ports,omitempty" yaml:"ports,omitempty"`

	// Storage
	Volumes       []VolumeConfig `json:"volumes,omitempty" yaml:"volumes,omitempty"`
	DockerVolumes []string       `json:"docker_volumes,omitempty" yaml:"docker_volumes,omitempty"`

	// Environment and configuration
	EnvVars   map[string]string `json:"env_vars,omitempty" yaml:"env_vars,omitempty"`
	Templates []TemplateConfig  `json:"templates,omitempty" yaml:"templates,omitempty"`

	// Resources
	Resources *ResourceConfig `json:"resources,omitempty" yaml:"resources,omitempty"`

	// Health checking
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty" yaml:"health_check,omitempty"`

	// Restart policy
	RestartPolicy *RestartPolicyConfig `json:"restart_policy,omitempty" yaml:"restart_policy,omitempty"`

	// Constraints
	Constraints []ConstraintConfig `json:"constraints,omitempty" yaml:"constraints,omitempty"`

	// Service mesh
	ConsulConnect bool `json:"consul_connect" yaml:"consul_connect"`

	// Migration-specific fields for K3s replacement
	Domain          string             `json:"domain,omitempty" yaml:"domain,omitempty"`
	BackendServices []string           `json:"backend_services,omitempty" yaml:"backend_services,omitempty"`
	MailBackend     string             `json:"mail_backend,omitempty" yaml:"mail_backend,omitempty"`
	EnableACL       bool               `json:"enable_acl" yaml:"enable_acl"`
	HostVolumes     []HostVolumeConfig `json:"host_volumes,omitempty" yaml:"host_volumes,omitempty"`
}

// NetworkConfig represents network configuration for Nomad jobs
type NetworkConfig struct {
	Name   string `json:"name" yaml:"name"`
	Port   int    `json:"port" yaml:"port"`
	Static bool   `json:"static" yaml:"static"`
}

// VolumeConfig represents volume configuration for Nomad jobs
type VolumeConfig struct {
	Name     string `json:"name" yaml:"name"`
	Type     string `json:"type" yaml:"type"` // host, csi
	Source   string `json:"source" yaml:"source"`
	ReadOnly bool   `json:"read_only" yaml:"read_only"`
}

// TemplateConfig represents template configuration for Nomad jobs
type TemplateConfig struct {
	Data        string `json:"data" yaml:"data"`
	Destination string `json:"destination" yaml:"destination"`
	ChangeMode  string `json:"change_mode,omitempty" yaml:"change_mode,omitempty"`
	Perms       string `json:"perms,omitempty" yaml:"perms,omitempty"`
}

// ResourceConfig represents resource requirements for Nomad jobs
type ResourceConfig struct {
	CPU    int `json:"cpu" yaml:"cpu"`                       // MHz
	Memory int `json:"memory" yaml:"memory"`                 // MB
	Disk   int `json:"disk,omitempty" yaml:"disk,omitempty"` // MB
}

// HealthCheckConfig represents health check configuration
type HealthCheckConfig struct {
	Type     string        `json:"type" yaml:"type"` // http, tcp, script
	Path     string        `json:"path,omitempty" yaml:"path,omitempty"`
	Interval time.Duration `json:"interval" yaml:"interval"`
	Timeout  time.Duration `json:"timeout" yaml:"timeout"`
}

// RestartPolicyConfig represents restart policy configuration
type RestartPolicyConfig struct {
	Attempts int           `json:"attempts" yaml:"attempts"`
	Interval time.Duration `json:"interval" yaml:"interval"`
	Delay    time.Duration `json:"delay" yaml:"delay"`
	Mode     string        `json:"mode" yaml:"mode"` // fail, delay, restart
}

// ConstraintConfig represents job constraint configuration
type ConstraintConfig struct {
	Attribute string `json:"attribute" yaml:"attribute"`
	Operator  string `json:"operator" yaml:"operator"` // =, !=, >, <, >=, <=, regexp, version
	Value     string `json:"value" yaml:"value"`
}

// HostVolumeConfig represents host volume configuration
type HostVolumeConfig struct {
	NodeID   string `json:"node_id" yaml:"node_id"`
	Name     string `json:"name" yaml:"name"`
	HostPath string `json:"host_path" yaml:"host_path"`
	ReadOnly bool   `json:"read_only" yaml:"read_only"`
}

// CaddyIngressConfig represents Caddy ingress configuration
type CaddyIngressConfig struct {
	Region             string           `json:"region" yaml:"region"`
	Datacenter         string           `json:"datacenter" yaml:"datacenter"`
	CaddyReplicas      int              `json:"caddy_replicas" yaml:"caddy_replicas"`
	CaddyVersion       string           `json:"caddy_version" yaml:"caddy_version"`
	CaddyAdminEnabled  bool             `json:"caddy_admin_enabled" yaml:"caddy_admin_enabled"`
	Domain             string           `json:"domain" yaml:"domain"`
	BackendServices    []BackendService `json:"backend_services" yaml:"backend_services"`
	CaddyCPURequest    int              `json:"caddy_cpu_request" yaml:"caddy_cpu_request"`
	CaddyMemoryRequest int              `json:"caddy_memory_request" yaml:"caddy_memory_request"`
}

// NginxMailConfig represents Nginx mail proxy configuration
type NginxMailConfig struct {
	Region             string `json:"region" yaml:"region"`
	Datacenter         string `json:"datacenter" yaml:"datacenter"`
	NginxReplicas      int    `json:"nginx_replicas" yaml:"nginx_replicas"`
	NginxVersion       string `json:"nginx_version" yaml:"nginx_version"`
	Domain             string `json:"domain" yaml:"domain"`
	MailPorts          []int  `json:"mail_ports" yaml:"mail_ports"`
	MailBackend        string `json:"mail_backend" yaml:"mail_backend"`
	NginxCPURequest    int    `json:"nginx_cpu_request" yaml:"nginx_cpu_request"`
	NginxMemoryRequest int    `json:"nginx_memory_request" yaml:"nginx_memory_request"`
}

// BackendService represents a backend service for load balancing
type BackendService struct {
	Address string `json:"address" yaml:"address"`
	Port    int    `json:"port" yaml:"port"`
}

// NomadClusterConfig represents Nomad cluster configuration
type NomadClusterConfig struct {
	Region      string             `json:"region" yaml:"region"`
	Datacenter  string             `json:"datacenter" yaml:"datacenter"`
	EnableACL   bool               `json:"enable_acl" yaml:"enable_acl"`
	HostVolumes []HostVolumeConfig `json:"host_volumes" yaml:"host_volumes"`
}

// Constants for Nomad job generation
const (
	// Default resource allocations (replacing K3s defaults)
	DefaultCaddyCPU    = 200 // MHz
	DefaultCaddyMemory = 256 // MB
	DefaultNginxCPU    = 100 // MHz
	DefaultNginxMemory = 128 // MB

	// Default replica counts
	DefaultCaddyReplicas = 2
	DefaultNginxReplicas = 1

	// Default versions
	DefaultCaddyVersion = "2.7-alpine"
	DefaultNginxVersion = "1.24-alpine"

	// Default mail ports (replacing K3s service ports)
	DefaultMailPorts = "25,587,465,110,995,143,993,4190"

	// Job types
	ServiceJobType = "service"
	BatchJobType   = "batch"
	SystemJobType  = "system"

	// Drivers
	DockerDriver  = "docker"
	ExecDriver    = "exec"
	RawExecDriver = "raw_exec"

	// Health check types
	HTTPHealthCheck   = "http"
	TCPHealthCheck    = "tcp"
	ScriptHealthCheck = "script"

	// Restart modes
	RestartModeDelay   = "delay"
	RestartModeFail    = "fail"
	RestartModeRestart = "restart"
)

// GetDefaultCaddyConfig returns default Caddy ingress configuration
func GetDefaultCaddyConfig() *CaddyIngressConfig {
	return &CaddyIngressConfig{
		Region:             "global",
		Datacenter:         "dc1",
		CaddyReplicas:      DefaultCaddyReplicas,
		CaddyVersion:       DefaultCaddyVersion,
		CaddyAdminEnabled:  true,
		Domain:             "",
		BackendServices:    []BackendService{},
		CaddyCPURequest:    DefaultCaddyCPU,
		CaddyMemoryRequest: DefaultCaddyMemory,
	}
}

// GetDefaultNginxConfig returns default Nginx mail proxy configuration
func GetDefaultNginxConfig() *NginxMailConfig {
	return &NginxMailConfig{
		Region:             "global",
		Datacenter:         "dc1",
		NginxReplicas:      DefaultNginxReplicas,
		NginxVersion:       DefaultNginxVersion,
		Domain:             "",
		MailPorts:          []int{25, 587, 465, 110, 995, 143, 993, 4190},
		MailBackend:        "stalwart-mail",
		NginxCPURequest:    DefaultNginxCPU,
		NginxMemoryRequest: DefaultNginxMemory,
	}
}

// GetDefaultServiceJobConfig returns default service job configuration
func GetDefaultServiceJobConfig(serviceName string) *NomadJobConfig {
	return &NomadJobConfig{
		ServiceName: serviceName,
		Region:      "global",
		Datacenter:  "dc1",
		JobType:     ServiceJobType,
		Priority:    50,
		Replicas:    1,
		Driver:      DockerDriver,
		Resources: &ResourceConfig{
			CPU:    100,
			Memory: 128,
		},
		HealthCheck: &HealthCheckConfig{
			Type:     HTTPHealthCheck,
			Path:     "/health",
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
		},
		RestartPolicy: &RestartPolicyConfig{
			Attempts: 3,
			Interval: 5 * time.Minute,
			Delay:    15 * time.Second,
			Mode:     RestartModeDelay,
		},
		ConsulConnect: true,
	}
}

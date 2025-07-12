// pkg/service_installation/types.go
package service_installation

import (
	"time"
)

// ServiceType represents the type of service
type ServiceType string

const (
	ServiceTypeGrafana    ServiceType = "grafana"
	ServiceTypeMattermost ServiceType = "mattermost"
	ServiceTypeLxd        ServiceType = "lxd"
	ServiceTypeLoki       ServiceType = "loki"
	ServiceTypeCaddy      ServiceType = "caddy"
	ServiceTypeTailscale  ServiceType = "tailscale"
	ServiceTypeGuacamole  ServiceType = "guacamole"
	ServiceTypeOpenStack  ServiceType = "openstack"
	ServiceTypeQemuGuest  ServiceType = "qemu-guest-agent"
)

// InstallationMethod represents how the service is installed
type InstallationMethod string

const (
	MethodDocker     InstallationMethod = "docker"
	MethodNative     InstallationMethod = "native"
	MethodSnap       InstallationMethod = "snap"
	MethodCompose    InstallationMethod = "docker-compose"
	MethodRepository InstallationMethod = "repository"
)

// ServiceInstallOptions represents options for service installation
type ServiceInstallOptions struct {
	Name             string             `json:"name"`
	Type             ServiceType        `json:"type"`
	Version          string             `json:"version"`
	Port             int                `json:"port"`
	ExposedPorts     []int              `json:"exposed_ports,omitempty"`
	Method           InstallationMethod `json:"method"`
	Config           map[string]string  `json:"config,omitempty"`
	Environment      map[string]string  `json:"environment,omitempty"`
	Dependencies     []string           `json:"dependencies,omitempty"`
	Volumes          []VolumeMount      `json:"volumes,omitempty"`
	Networks         []string           `json:"networks,omitempty"`
	Interactive      bool               `json:"interactive"`
	DryRun           bool               `json:"dry_run"`
	Force            bool               `json:"force"`
	SkipHealthCheck  bool               `json:"skip_health_check"`
	WorkingDirectory string             `json:"working_directory,omitempty"`
	Domain           string             `json:"domain,omitempty"`
	SSL              *SSLConfig         `json:"ssl,omitempty"`
}

// VolumeMount represents a volume mount configuration
type VolumeMount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only,omitempty"`
}

// SSLConfig represents SSL/TLS configuration
type SSLConfig struct {
	Enabled  bool   `json:"enabled"`
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
	AutoCert bool   `json:"auto_cert,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// ServiceStatus represents the status of an installed service
type ServiceStatus struct {
	Name        string             `json:"name"`
	Type        ServiceType        `json:"type"`
	Method      InstallationMethod `json:"method"`
	Status      string             `json:"status"`
	Version     string             `json:"version"`
	Port        int                `json:"port"`
	Uptime      time.Duration      `json:"uptime"`
	HealthCheck *HealthCheckResult `json:"health_check,omitempty"`
	Processes   []ProcessInfo      `json:"processes,omitempty"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// HealthCheckResult represents the result of a service health check
type HealthCheckResult struct {
	Healthy      bool          `json:"healthy"`
	ResponseTime time.Duration `json:"response_time"`
	Endpoint     string        `json:"endpoint,omitempty"`
	StatusCode   int           `json:"status_code,omitempty"`
	Error        string        `json:"error,omitempty"`
	Checks       []HealthCheck `json:"checks,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
}

// HealthCheck represents an individual health check
type HealthCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	PID     int     `json:"pid"`
	Name    string  `json:"name"`
	Command string  `json:"command"`
	CPU     float64 `json:"cpu_usage,omitempty"`
	Memory  int64   `json:"memory_usage,omitempty"`
}

// InstallationResult represents the result of a service installation
type InstallationResult struct {
	Success     bool               `json:"success"`
	Service     string             `json:"service"`
	Method      InstallationMethod `json:"method"`
	Version     string             `json:"version,omitempty"`
	Port        int                `json:"port,omitempty"`
	Message     string             `json:"message"`
	Error       string             `json:"error,omitempty"`
	Duration    time.Duration      `json:"duration"`
	Steps       []InstallationStep `json:"steps,omitempty"`
	Endpoints   []string           `json:"endpoints,omitempty"`
	Credentials map[string]string  `json:"credentials,omitempty"`
	ConfigFiles []string           `json:"config_files,omitempty"`
	Timestamp   time.Time          `json:"timestamp"`
}

// InstallationStep represents a step in the installation process
type InstallationStep struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Status      string        `json:"status"`
	Duration    time.Duration `json:"duration,omitempty"`
	Error       string        `json:"error,omitempty"`
}

// DependencyCheck represents a dependency check result
type DependencyCheck struct {
	Name      string `json:"name"`
	Required  bool   `json:"required"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ServiceConfiguration represents service-specific configuration
type ServiceConfiguration struct {
	Type          ServiceType        `json:"type"`
	DefaultPort   int                `json:"default_port"`
	DefaultMethod InstallationMethod `json:"default_method"`
	Dependencies  []string           `json:"dependencies"`
	HealthCheck   *HealthCheckConfig `json:"health_check,omitempty"`
	Environment   map[string]string  `json:"environment,omitempty"`
	Volumes       []VolumeMount      `json:"volumes,omitempty"`
	Networks      []string           `json:"networks,omitempty"`
	Commands      *ServiceCommands   `json:"commands,omitempty"`
}

// HealthCheckConfig represents health check configuration
type HealthCheckConfig struct {
	Enabled     bool          `json:"enabled"`
	Endpoint    string        `json:"endpoint"`
	Timeout     time.Duration `json:"timeout"`
	Interval    time.Duration `json:"interval"`
	Retries     int           `json:"retries"`
	StartPeriod time.Duration `json:"start_period"`
}

// ServiceCommands represents service-specific commands
type ServiceCommands struct {
	Install   []string `json:"install,omitempty"`
	Start     []string `json:"start,omitempty"`
	Stop      []string `json:"stop,omitempty"`
	Restart   []string `json:"restart,omitempty"`
	Status    []string `json:"status,omitempty"`
	Uninstall []string `json:"uninstall,omitempty"`
}

// GrafanaConfig represents Grafana-specific configuration
type GrafanaConfig struct {
	AdminUser     string              `json:"admin_user,omitempty"`
	AdminPassword string              `json:"admin_password,omitempty"`
	Datasources   []GrafanaDatasource `json:"datasources,omitempty"`
	Plugins       []string            `json:"plugins,omitempty"`
	Theme         string              `json:"theme,omitempty"`
}

// GrafanaDatasource represents a Grafana datasource configuration
type GrafanaDatasource struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	URL    string            `json:"url"`
	Access string            `json:"access"`
	Config map[string]string `json:"config,omitempty"`
}

// MattermostConfig represents Mattermost-specific configuration
type MattermostConfig struct {
	SiteName       string            `json:"site_name,omitempty"`
	SiteURL        string            `json:"site_url,omitempty"`
	DatabaseDriver string            `json:"database_driver,omitempty"`
	DatabaseSource string            `json:"database_source,omitempty"`
	FileSettings   map[string]string `json:"file_settings,omitempty"`
	EmailSettings  map[string]string `json:"email_settings,omitempty"`
}

// LxdConfig represents LXD-specific configuration
type LxdConfig struct {
	Channel        string   `json:"channel,omitempty"`
	StorageBackend string   `json:"storage_backend,omitempty"`
	NetworkBridge  string   `json:"network_bridge,omitempty"`
	AddressRange   string   `json:"address_range,omitempty"`
	Groups         []string `json:"groups,omitempty"`
}

// CaddyConfig represents Caddy-specific configuration
type CaddyConfig struct {
	Sites      []CaddySite `json:"sites,omitempty"`
	AutoHTTPS  bool        `json:"auto_https"`
	AdminAPI   bool        `json:"admin_api"`
	ConfigFile string      `json:"config_file,omitempty"`
}

// CaddySite represents a Caddy site configuration
type CaddySite struct {
	Address string            `json:"address"`
	Root    string            `json:"root,omitempty"`
	Proxy   string            `json:"proxy,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	TLS     *SSLConfig        `json:"tls,omitempty"`
}

// PortConflictCheck represents a port conflict check result
type PortConflictCheck struct {
	Port      int    `json:"port"`
	Available bool   `json:"available"`
	Process   string `json:"process,omitempty"`
	PID       int    `json:"pid,omitempty"`
}

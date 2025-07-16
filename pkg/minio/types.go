package minio

import "time"


// Config represents MinIO configuration
type Config struct {
	Version       string
	RootUser      string
	RootPassword  string
	Region        string
	BrowserEnable bool
	Domains       []string
}

// Dependency represents a required system dependency
type Dependency struct {
	Name        string
	Command     string
	Description string
	Required    bool
}

// Constants
const (
	DefaultMinIOVersion   = "latest"
	DefaultRegion         = "us-east-1"
	DefaultAPIPort        = 9123
	DefaultConsolePort    = 8123
	DefaultStoragePath    = "/mnt/external_disk"
	DefaultDatacenter     = "dc1"
	VaultMinIOPath        = "kv/minio/root"
	VaultMinIOPolicyPath  = "kv/minio/policies"
	DeploymentTimeout     = 10 * time.Minute
	HealthCheckTimeout    = 30 * time.Second
	HealthCheckRetries    = 10
	HealthCheckRetryDelay = 5 * time.Second
)

// GetRequiredDependencies returns the list of required system dependencies
func GetRequiredDependencies() []Dependency {
	return []Dependency{
		{
			Name:        "salt-call",
			Command:     "salt-call",
			Description: "SaltStack configuration management (masterless mode)",
			Required:    true,
		},
		{
			Name:        "terraform",
			Command:     "terraform",
			Description: "Infrastructure as Code tool for deployment",
			Required:    true,
		},
		{
			Name:        "nomad",
			Command:     "nomad",
			Description: "Container orchestration platform",
			Required:    true,
		},
		{
			Name:        "vault",
			Command:     "vault",
			Description: "Secret management system",
			Required:    true,
		},
		{
			Name:        "consul",
			Command:     "consul",
			Description: "Service discovery and configuration",
			Required:    true,
		},
		{
			Name:        "curl",
			Command:     "curl",
			Description: "HTTP client for health checks",
			Required:    true,
		},
		{
			Name:        "mc",
			Command:     "mc",
			Description: "MinIO client (optional, for testing)",
			Required:    false,
		},
	}
}
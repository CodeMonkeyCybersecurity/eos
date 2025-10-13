// pkg/openwebui/types.go
package openwebui

import "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"

// InstallConfig contains configuration for Open WebUI installation
type InstallConfig struct {
	// Installation paths
	InstallDir  string // Base installation directory (default: /opt/openwebui)
	ComposeFile string // Path to docker-compose.yml
	EnvFile     string // Path to .env file

	// Azure OpenAI Configuration
	AzureEndpoint    string // Azure OpenAI endpoint URL
	AzureDeployment  string // Azure OpenAI deployment name
	AzureAPIKey      string // Azure OpenAI API key
	AzureAPIVersion  string // Azure OpenAI API version (default: 2024-02-15-preview)

	// Open WebUI Settings
	WebUIName      string // Display name for the web UI
	WebUISecretKey string // Secret key for sessions (auto-generated if not provided)
	WebUIAuth      bool   // Enable authentication (default: true)
	LogLevel       string // Log level (default: INFO)
	Timezone       string // Timezone (default: Australia/Perth)

	// Network configuration
	Port int // External port to expose (default: shared.PortOpenWebUI = 8501)

	// Installation behavior
	ForceReinstall bool // Force reinstall even if already installed
	SkipHealthCheck bool // Skip health check after installation
}

// OpenWebUIInstaller handles Open WebUI installation
type OpenWebUIInstaller struct {
	rc     *eos_io.RuntimeContext
	config *InstallConfig
}

// InstallState tracks the state of Open WebUI installation
type InstallState struct {
	Installed         bool
	Running           bool
	ComposeFileExists bool
	EnvFileExists     bool
	VolumeExists      bool     // Docker volume exists
	ContainerID       string
	HealthStatus      string
	Version           string
	ExistingPaths     []string
}

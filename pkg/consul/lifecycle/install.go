// pkg/consul/install.go
// Core types and constructor for Consul installation

package lifecycle

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulInstaller handles Consul installation using native methods
type ConsulInstaller struct {
	rc       *eos_io.RuntimeContext
	config   *InstallConfig
	logger   otelzap.LoggerWithCtx
	runner   *CommandRunner
	systemd  *SystemdService
	dirs     *DirectoryManager
	files    *FileManager
	progress *ProgressReporter
	user     *UserHelper
	validate *ValidationHelper
	network  *HTTPClient
}

// InstallConfig contains all configuration for Consul installation
type InstallConfig struct {
	// Installation method
	Version       string // Version to install (e.g., "1.21.3" or "latest")
	UseRepository bool   // Use APT repository vs direct binary download
	BinaryPath    string // Path for binary installation

	// Consul configuration
	Datacenter      string
	ServerMode      bool
	BootstrapExpect int
	UIEnabled       bool
	ConnectEnabled  bool
	BindAddr        string
	ClientAddr      string
	LogLevel        string

	// Integration options
	VaultIntegration bool
	VaultAddr        string

	// Installation behavior
	ForceReinstall bool // Force reinstallation even if already installed
	CleanInstall   bool // Remove existing data before installation
	DryRun         bool // Dry run mode
}

// NewConsulInstaller creates a new Consul installer instance
func NewConsulInstaller(rc *eos_io.RuntimeContext, config *InstallConfig) (*ConsulInstaller, error) {
	// Set defaults
	if config.Version == "" {
		config.Version = "latest"
	}
	if config.Datacenter == "" {
		config.Datacenter = "dc1"
	}
	logger := otelzap.Ctx(rc.Ctx)

	// CRITICAL: Fail early if no network interface detected
	if config.BindAddr == "" {
		bindAddr, err := getDefaultBindAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to detect bind address: %w\nPlease specify --bind-addr explicitly", err)
		}
		config.BindAddr = bindAddr
		logger.Info("Auto-detected network bind address",
			zap.String("bind_addr", bindAddr))
	}

	if config.ClientAddr == "" {
		config.ClientAddr = "0.0.0.0"
	}

	// Set binary path based on installation method
	if config.BinaryPath == "" {
		config.BinaryPath = consul.GetConsulBinaryPath()
	}

	runner := NewCommandRunner(rc)
	
	return &ConsulInstaller{
		rc:       rc,
		config:   config,
		logger:   logger,
		runner:   runner,
		systemd:  NewSystemdService(runner, "consul"),
		dirs:     NewDirectoryManager(runner),
		files:    NewFileManager(runner),
		progress: NewProgressReporter(logger, "Consul Installation", 6),
		user:     NewUserHelper(runner),
		validate: NewValidationHelper(logger),
		network:  NewHTTPClient(10 * time.Second),
	}, nil
}

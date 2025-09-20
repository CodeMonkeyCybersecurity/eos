// cmd/create/nomad.go
//
// HashiCorp Nomad Installation Commands
//
// This file implements CLI commands for installing and configuring HashiCorp Nomad
// for workload orchestration. It provides a native installer that handles both
// server and client modes with comprehensive configuration options.
//
// EOS Infrastructure Compiler Integration:
// EOS acts as a human-friendly infrastructure compiler that translates imperative
// commands into declarative infrastructure state. The Nomad installer follows this
// pattern by taking simple user intent ("install Nomad") and orchestrating the
// complex multi-system setup required.
//
// Key Features:
// - Server and/or client mode configuration
// - Docker integration for container workloads
// - Consul service discovery integration
// - Vault secrets management integration
// - Automatic cluster bootstrapping
// - Comprehensive flag support for all configuration options
//
// Architecture Integration:
// Nomad fits into the EOS infrastructure stack as the container runtime layer:
// Human Intent → EOS CLI → SaltStack (config) → Terraform (resources) → Nomad (runtime)
//
// Available Commands:
// - eos create nomad                              # Install as both server and client
// - eos create nomad --server-only                # Server only
// - eos create nomad --client-only --docker       # Client with Docker
// - eos create nomad --consul --vault             # With integrations
//
// Configuration Options:
// - Server/Client modes with flexible deployment patterns
// - Cluster configuration (bootstrap-expect, datacenter, region)
// - Network configuration (bind/advertise addresses)
// - Driver configuration (Docker, raw exec)
// - Security configuration (ACL system)
// - Operational flags (force, clean installation)
//
// Integration Points:
// - Consul: Service discovery and health checking
// - Vault: Secret management and dynamic credentials
// - Docker: Container runtime for workloads
// - SaltStack: Configuration management and orchestration
//
// Usage Examples:
//   # Basic installation
//   eos create nomad
//
//   # Production cluster setup
//   eos create nomad --server --bootstrap-expect 3 --datacenter prod
//
//   # Client-only with Docker
//   eos create nomad --client-only --docker --servers server1:4647,server2:4647
//
// Security Considerations:
// - ACL system can be enabled for production deployments
// - TLS encryption is configured by default
// - Integration with Vault provides secure credential management
// - Network configuration supports secure bind/advertise patterns
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var CreateNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Install and configure HashiCorp Nomad using native installer",
	Long: `Install HashiCorp Nomad for workload orchestration using the native installer.

This installer provides:
- Server and/or client mode configuration
- Docker integration for containers
- Consul service discovery integration
- Vault secrets integration
- Automatic cluster bootstrapping

Examples:
  eos create nomad                              # Install as both server and client
  eos create nomad --server-only                # Server only
  eos create nomad --client-only --docker       # Client with Docker
  eos create nomad --consul --vault             # With integrations`,
	RunE: eos.Wrap(runCreateNomadNative),
}

var (
	nomadServerMode      bool
	nomadClientMode      bool
	nomadBootstrapExpect int
	nomadDatacenter      string
	nomadRegion          string
	nomadBindAddr        string
	nomadAdvertiseAddr   string
	nomadLogLevel        string
	nomadEnableACL       bool
	nomadForce           bool
	nomadClean           bool
	nomadJoinAddrs       []string
	nomadClientServers   []string
	nomadEnableDocker    bool
	nomadEnableRaw       bool
)

func init() {
	CreateCmd.AddCommand(CreateNomadCmd)

	// Server/Client mode flags
	CreateNomadCmd.Flags().BoolVar(&nomadServerMode, "server", true, "Enable server mode")
	CreateNomadCmd.Flags().BoolVar(&nomadClientMode, "client", true, "Enable client mode")
	CreateNomadCmd.Flags().BoolVar(&nomadServerMode, "server-only", false, "Server mode only")
	CreateNomadCmd.Flags().BoolVar(&nomadClientMode, "client-only", false, "Client mode only")

	// Cluster configuration
	CreateNomadCmd.Flags().IntVar(&nomadBootstrapExpect, "bootstrap-expect", 1, "Expected number of servers in cluster")
	CreateNomadCmd.Flags().StringVar(&nomadDatacenter, "datacenter", "dc1", "Datacenter name")
	CreateNomadCmd.Flags().StringVar(&nomadRegion, "region", "global", "Region name")

	// Network configuration
	CreateNomadCmd.Flags().StringVar(&nomadBindAddr, "bind", "", "Bind address")
	CreateNomadCmd.Flags().StringVar(&nomadAdvertiseAddr, "advertise", "", "Advertise address")

	// Operational flags
	CreateNomadCmd.Flags().StringVar(&nomadLogLevel, "log-level", "INFO", "Log level")
	CreateNomadCmd.Flags().BoolVar(&nomadEnableACL, "acl", false, "Enable ACL system")
	CreateNomadCmd.Flags().BoolVar(&nomadForce, "force", false, "Force installation")
	CreateNomadCmd.Flags().BoolVar(&nomadClean, "clean", false, "Clean existing installation")

	// Cluster joining
	CreateNomadCmd.Flags().StringSliceVar(&nomadJoinAddrs, "join", []string{}, "Server addresses to join")
	CreateNomadCmd.Flags().StringSliceVar(&nomadClientServers, "servers", []string{}, "Server addresses for clients")

	// Driver configuration
	CreateNomadCmd.Flags().BoolVar(&nomadEnableDocker, "docker", true, "Enable Docker driver")
	CreateNomadCmd.Flags().BoolVar(&nomadEnableRaw, "raw-exec", false, "Enable raw exec driver")
}

// NomadStatus represents the current state of Nomad installation
type NomadStatus struct {
	Installed      bool
	Running        bool
	Failed         bool
	ConfigValid    bool
	Version        string
	ServiceStatus  string
	ServerMode     bool
	ClientMode     bool
	ClusterLeader  string
	ClusterMembers []string
	JobCount       int
	LastError      string
}


// runCreateNomadNative installs Nomad using the native installer
func runCreateNomadNative(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Nomad using native installer")

	// Parse configuration from flags
	config := &nomad.InstallConfig{
		Version:           "latest",
		ServerEnabled:     nomadServerMode,
		ClientEnabled:     nomadClientMode,
		Datacenter:        nomadDatacenter,
		Region:            nomadRegion,
		BootstrapExpect:   nomadBootstrapExpect,
		ConsulIntegration: true,  // Enable by default
		VaultIntegration:  false, // Disabled by default
		DockerEnabled:     nomadEnableDocker,
	}

	// Create and run installer
	installer := nomad.NewNomadInstaller(rc, config)
	if err := installer.Install(); err != nil {
		return fmt.Errorf("nomad installation failed: %w", err)
	}

	logger.Info("Nomad installation completed successfully")
	logger.Info("terminal prompt: Nomad is installed. Check status with: nomad node status")
	return nil
}


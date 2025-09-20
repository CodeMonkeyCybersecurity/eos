// cmd/create/nomad.go

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

// TODO: Nomad status checking - removed during HashiCorp migration
// This function was replaced with native Nomad installer status checking
// Restore if detailed status monitoring is needed
func checkNomadStatus(_ *eos_io.RuntimeContext) (*NomadStatus, error) {
	// TODO: Implement Nomad status checking if needed
	return &NomadStatus{}, fmt.Errorf("nomad status checking not implemented - use native installer")
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

// TODO: Legacy Nomad creation - removed during HashiCorp migration
// This function was replaced with native Nomad installer
// Restore if direct Nomad installation is needed outside of installer
func runCreateNomadLegacy(_ *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
	// TODO: Implement legacy Nomad creation if needed
	return fmt.Errorf("legacy nomad creation not implemented - use native installer")
}

// TODO: Direct Salt execution - removed during HashiCorp migration
// This function was replaced with administrator escalation pattern
// Restore if system-level Nomad installation is needed
func runCreateNomadDirectSalt(_ *eos_io.RuntimeContext, _, _ bool,
	_ int, _, _, _, _, _ string,
	_, _, _ bool, _, _ []string,
	_, _, _, _ bool) error {
	// TODO: Implement direct Salt execution if needed
	return fmt.Errorf("direct salt execution not implemented - use administrator escalation")
}

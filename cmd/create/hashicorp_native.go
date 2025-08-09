package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// Native installer commands for each HashiCorp product
var (
	createVaultNativeCmd = &cobra.Command{
		Use:   "vault",
		Short: "Install and configure HashiCorp Vault using native installer",
		Long: `Install HashiCorp Vault for secrets management using the native installer.

This installer provides:
- Direct binary or repository installation
- Multiple storage backends (file, consul, raft)
- Auto-unseal configuration
- TLS setup
- Systemd service management
- Automatic version resolution

Examples:
  eos create vault                              # Basic installation
  eos create vault --storage-backend=consul     # Use Consul storage
  eos create vault --auto-unseal --kms-key=...  # AWS KMS auto-unseal
  eos create vault --ui                         # Enable web UI`,
		RunE: eos.Wrap(runCreateVaultNative),
	}

	createNomadNativeCmd = &cobra.Command{
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

	createTerraformNativeCmd = &cobra.Command{
		Use:   "terraform",
		Short: "Install HashiCorp Terraform using native installer",
		Long: `Install HashiCorp Terraform for infrastructure as code.

This installer provides:
- Direct binary or repository installation
- Plugin cache configuration
- Environment setup
- Version management

Examples:
  eos create terraform                          # Latest version
  eos create terraform --version=1.6.6          # Specific version`,
		RunE: eos.Wrap(runCreateTerraformNative),
	}

	createPackerNativeCmd = &cobra.Command{
		Use:   "packer",
		Short: "Install HashiCorp Packer using native installer",
		Long: `Install HashiCorp Packer for image building.

This installer provides:
- Direct binary or repository installation
- Plugin directory setup
- Cache configuration
- Environment variables

Examples:
  eos create packer                             # Latest version
  eos create packer --version=1.10.0            # Specific version`,
		RunE: eos.Wrap(runCreatePackerNative),
	}

	createBoundaryNativeCmd = &cobra.Command{
		Use:   "boundary",
		Short: "Install HashiCorp Boundary using native installer",
		Long: `Install HashiCorp Boundary for secure remote access.

This installer provides:
- Controller and/or worker configuration
- Database setup for controllers
- KMS configuration
- Development mode
- TLS setup

Examples:
  eos create boundary --dev                     # Development mode
  eos create boundary --controller              # Controller only
  eos create boundary --worker                  # Worker only
  eos create boundary --database-url=...        # With PostgreSQL`,
		RunE: eos.Wrap(runCreateBoundaryNative),
	}

	createConsulNativeCmd = &cobra.Command{
		Use:   "consul",  
		Short: "Install and configure HashiCorp Consul using native installer",
		Long: `Install HashiCorp Consul for service discovery using the native installer.

This installer provides:
- Direct binary or repository installation
- Server/agent mode configuration
- UI enablement
- Connect service mesh
- ACL system setup

Examples:
  eos create consul                              # Basic installation
  eos create consul --server --ui               # Server with UI
  eos create consul --connect                   # Enable Connect`,
		RunE: eos.Wrap(runCreateConsulNative),
	}
)

func init() {
	// Add commands to create command
	// NOTE: Most commands are now integrated into existing command files
	// Only adding Terraform here as it doesn't have a main command elsewhere
	CreateCmd.AddCommand(createTerraformNativeCmd)  // No conflict, terraform command was only in hcl.go which is commented out

	// Vault flags
	createVaultNativeCmd.Flags().String("version", "latest", "Vault version to install")
	createVaultNativeCmd.Flags().String("storage-backend", "file", "Storage backend (file, consul, raft)")
	createVaultNativeCmd.Flags().Bool("ui", true, "Enable web UI")
	createVaultNativeCmd.Flags().String("listener-address", "0.0.0.0:8200", "Listener address")
	createVaultNativeCmd.Flags().Bool("tls", true, "Enable TLS")
	createVaultNativeCmd.Flags().Bool("auto-unseal", false, "Enable auto-unseal")
	createVaultNativeCmd.Flags().String("kms-key", "", "KMS key ID for auto-unseal")
	createVaultNativeCmd.Flags().Bool("clean", false, "Clean install (remove existing)")
	createVaultNativeCmd.Flags().Bool("force", false, "Force reinstall")
	createVaultNativeCmd.Flags().Bool("use-repository", false, "Install via APT repository")

	// Nomad flags
	createNomadNativeCmd.Flags().String("version", "latest", "Nomad version to install")
	createNomadNativeCmd.Flags().Bool("server", true, "Enable server mode")
	createNomadNativeCmd.Flags().Bool("client", true, "Enable client mode")
	createNomadNativeCmd.Flags().Bool("server-only", false, "Server only (no client)")
	createNomadNativeCmd.Flags().Bool("client-only", false, "Client only (no server)")
	createNomadNativeCmd.Flags().String("datacenter", "dc1", "Datacenter name")
	createNomadNativeCmd.Flags().String("region", "global", "Region name")
	createNomadNativeCmd.Flags().Int("bootstrap-expect", 1, "Expected number of servers")
	createNomadNativeCmd.Flags().Bool("consul", true, "Enable Consul integration")
	createNomadNativeCmd.Flags().Bool("vault", false, "Enable Vault integration")
	createNomadNativeCmd.Flags().Bool("docker", true, "Enable Docker driver")
	createNomadNativeCmd.Flags().Bool("clean", false, "Clean install")
	createNomadNativeCmd.Flags().Bool("force", false, "Force reinstall")
	createNomadNativeCmd.Flags().Bool("use-repository", false, "Install via APT repository")

	// Terraform flags
	createTerraformNativeCmd.Flags().String("version", "latest", "Terraform version to install")
	createTerraformNativeCmd.Flags().String("plugin-cache", "/var/lib/terraform/plugin-cache", "Plugin cache directory")
	createTerraformNativeCmd.Flags().Bool("clean", false, "Clean install")
	createTerraformNativeCmd.Flags().Bool("force", false, "Force reinstall")
	createTerraformNativeCmd.Flags().Bool("use-repository", false, "Install via APT repository")

	// Packer flags
	createPackerNativeCmd.Flags().String("version", "latest", "Packer version to install")
	createPackerNativeCmd.Flags().String("plugin-dir", "/var/lib/packer/plugins", "Plugin directory")
	createPackerNativeCmd.Flags().String("cache-dir", "/var/cache/packer", "Cache directory")
	createPackerNativeCmd.Flags().Bool("clean", false, "Clean install")
	createPackerNativeCmd.Flags().Bool("force", false, "Force reinstall")
	createPackerNativeCmd.Flags().Bool("use-repository", false, "Install via APT repository")

	// Boundary flags
	createBoundaryNativeCmd.Flags().String("version", "latest", "Boundary version to install")
	createBoundaryNativeCmd.Flags().Bool("controller", false, "Enable controller mode")
	createBoundaryNativeCmd.Flags().Bool("worker", false, "Enable worker mode")
	createBoundaryNativeCmd.Flags().Bool("dev", false, "Development mode")
	createBoundaryNativeCmd.Flags().String("database-url", "", "PostgreSQL database URL")
	createBoundaryNativeCmd.Flags().String("cluster-addr", "", "Cluster address")
	createBoundaryNativeCmd.Flags().String("public-addr", "", "Public address")
	createBoundaryNativeCmd.Flags().Bool("tls", true, "Enable TLS")
	createBoundaryNativeCmd.Flags().String("kms-type", "aead", "KMS type (aead, awskms, gcpckms, azurekeyvault)")
	createBoundaryNativeCmd.Flags().String("kms-key", "", "KMS key ID")
	createBoundaryNativeCmd.Flags().Bool("clean", false, "Clean install")
	createBoundaryNativeCmd.Flags().Bool("force", false, "Force reinstall")
	createBoundaryNativeCmd.Flags().Bool("use-repository", false, "Install via APT repository")
}


// Terraform native installer
func runCreateTerraformNative(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Terraform using native installer")

	// Parse flags
	config := &terraform.InstallConfig{
		Version:        cmd.Flag("version").Value.String(),
		UseRepository:  cmd.Flag("use-repository").Value.String() == "true",
		PluginCacheDir: cmd.Flag("plugin-cache").Value.String(),
		CleanInstall:   cmd.Flag("clean").Value.String() == "true",
		ForceReinstall: cmd.Flag("force").Value.String() == "true",
	}

	// Create and run installer
	installer := terraform.NewTerraformInstaller(rc, config)
	if err := installer.Install(); err != nil {
		return fmt.Errorf("Terraform installation failed: %w", err)
	}

	logger.Info("Terraform installation completed successfully")
	logger.Info("terminal prompt: Terraform is installed. Check version with: terraform version")
	return nil
}


// Update existing Consul command to use native installer
func runCreateConsulNative(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Consul using native installer")

	// Implementation would be similar to above
	// This is already implemented in consul.go, so we'll leave it there
	logger.Info("Using existing Consul native installer from consul.go")
	return nil
}
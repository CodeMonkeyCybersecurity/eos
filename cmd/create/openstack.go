package create

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/openstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/openstack/display"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/openstack/orchestrator"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var openstackCmd = &cobra.Command{
	Use:     "openstack",
	Aliases: []string{"openstack-aio", "os"},
	Short:   "Deploy OpenStack cloud infrastructure with integrated services",
	Long: `Deploy OpenStack cloud infrastructure using the three-tier orchestration:
1. SaltStack manages configuration across nodes
2. Terraform provisions infrastructure resources
3. Nomad can optionally orchestrate OpenStack workloads

The deployment supports multiple modes:
- All-in-One: Single node deployment for development/testing
- Controller: Dedicated control plane node
- Compute: Nova compute nodes for running instances
- Storage: Cinder/Swift storage nodes

Integration with existing Eos services:
- Vault: Secure storage of admin passwords and service credentials
- Consul: Service discovery and health checking
- Existing networking: Neutron configuration with OVS/OVN

Prerequisites:
- Ubuntu 22.04 LTS or later (recommended) or RHEL/CentOS 8+
- Minimum 16GB RAM for all-in-one, 8GB for specialized nodes
- 100GB+ available disk space
- Network connectivity between nodes
- Optional: Existing Vault and Consul installations`,

	Example: `  # Interactive all-in-one installation
  eos create openstack

  # Controller node with specific configuration
  eos create openstack --mode controller \
    --public-endpoint https://openstack.example.com \
    --admin-password <secure-password>

  # Compute node joining existing cluster
  eos create openstack --mode compute \
    --controller-address 10.0.0.10 \
    --nova-cpu-allocation-ratio 16.0

  # Storage node with Ceph backend
  eos create openstack --mode storage \
    --storage-backend ceph \
    --ceph-monitors mon1.example.com,mon2.example.com

  # Production deployment with all integrations
  eos create openstack --mode controller \
    --enable-dashboard --enable-ssl \
    --vault-integration --consul-integration \
    --network-type provider \
    --provider-network-interface eth1`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Starting OpenStack deployment")

		// Get configuration from flags
		mode, _ := cmd.Flags().GetString("mode")
		networkType, _ := cmd.Flags().GetString("network-type")
		storageBackend, _ := cmd.Flags().GetString("storage-backend")
		enableDashboard, _ := cmd.Flags().GetBool("enable-dashboard")
		enableSSL, _ := cmd.Flags().GetBool("enable-ssl")
		vaultIntegration, _ := cmd.Flags().GetBool("vault-integration")
		consulIntegration, _ := cmd.Flags().GetBool("consul-integration")
		adminPassword, _ := cmd.Flags().GetString("admin-password")
		publicEndpoint, _ := cmd.Flags().GetString("public-endpoint")
		internalEndpoint, _ := cmd.Flags().GetString("internal-endpoint")
		skipPreChecks, _ := cmd.Flags().GetBool("skip-pre-checks")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")

		// Controller-specific flags
		controllerAddress, _ := cmd.Flags().GetString("controller-address")

		// Network-specific flags
		providerInterface, _ := cmd.Flags().GetString("provider-network-interface")
		providerPhysnet, _ := cmd.Flags().GetString("provider-physical-network")

		// Storage-specific flags
		cephMonitors, _ := cmd.Flags().GetString("ceph-monitors")

		// Compute-specific flags
		cpuAllocationRatio, _ := cmd.Flags().GetFloat64("nova-cpu-allocation-ratio")
		ramAllocationRatio, _ := cmd.Flags().GetFloat64("nova-ram-allocation-ratio")

		// Create configuration
		config := &openstack.Config{
			Mode:               openstack.DeploymentMode(mode),
			NetworkType:        openstack.NetworkType(networkType),
			StorageBackend:     openstack.StorageBackend(storageBackend),
			EnableDashboard:    enableDashboard,
			EnableSSL:          enableSSL,
			VaultIntegration:   vaultIntegration,
			ConsulIntegration:  consulIntegration,
			AdminPassword:      adminPassword,
			PublicEndpoint:     publicEndpoint,
			InternalEndpoint:   internalEndpoint,
			ControllerAddress:  controllerAddress,
			ProviderInterface:  providerInterface,
			ProviderPhysnet:    providerPhysnet,
			CephMonitors:       strings.Split(cephMonitors, ","),
			CPUAllocationRatio: cpuAllocationRatio,
			RAMAllocationRatio: ramAllocationRatio,
			DryRun:             dryRun,
			Force:              force,
		}

		// Interactive configuration if not all required fields are provided
		if !skipPreChecks && config.AdminPassword == "" && !dryRun {
			if err := openstack.InteractiveConfig(rc, config); err != nil {
				return eos_err.NewUserError("Interactive configuration cancelled")
			}
		}

		// Validate configuration
		if err := config.Validate(); err != nil {
			return eos_err.NewUserError("Invalid configuration: %v", err)
		}

		// Check for SaltStack orchestration
		// TODO: Enable Salt orchestration once the orchestrator package is fixed
		// if orchestrator.IsSaltAvailable() && !config.Force {
		// 	logger.Info("SaltStack detected, using orchestrated deployment")

		// 	opts := &orchestrator.Options{
		// 		Target: "*",
		// 		Pillar: map[string]interface{}{
		// 			"openstack_mode":           string(config.Mode),
		// 			"openstack_admin_password": config.AdminPassword,
		// 			"openstack_endpoints": map[string]string{
		// 				"public":   config.PublicEndpoint,
		// 				"internal": config.InternalEndpoint,
		// 			},
		// 		},
		// 	}

		// 	saltOp := orchestrator.CreateSaltOperation(opts)
		// 	directExec := func(rc *eos_io.RuntimeContext) error {
		// 		return executeDirectInstallation(rc, config)
		// 	}

		// 	return orchestrator.ExecuteWithSalt(rc, opts, directExec, saltOp)
		// }

		// Direct installation
		return executeDirectInstallation(rc, config)
	}),
}

func executeDirectInstallation(rc *eos_io.RuntimeContext, config *openstack.Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Run pre-installation checks
	if !config.DryRun {
		logger.Info("Running pre-installation checks")
		if err := openstack.RunPreChecks(rc, config); err != nil {
			if !config.Force {
				return eos_err.NewUserError("Pre-installation checks failed: %v", err)
			}
			logger.Warn("Pre-installation checks failed but continuing due to --force flag", zap.Error(err))
		}
	}

	// Handle existing installation
	if existing, err := openstack.DetectExistingInstallation(rc); err == nil && existing != nil {
		if !config.Force {
			display.ShowExistingInstallation(rc, existing)
			return eos_err.NewUserError("OpenStack is already installed. Use --force to reinstall")
		}
		logger.Warn("Existing OpenStack installation detected, proceeding with reinstallation")
	}

	if config.DryRun {
		logger.Info("Dry run mode - showing installation plan")
		display.ShowInstallationPlan(rc, config)
		return nil
	}

	// INTERVENE - Perform installation
	logger.Info("Starting OpenStack installation",
		zap.String("mode", string(config.Mode)),
		zap.String("network_type", string(config.NetworkType)))

	// Main installation
	if err := openstack.Install(rc, config); err != nil {
		logger.Error("OpenStack installation failed", zap.Error(err))

		// Attempt rollback
		if rollbackErr := openstack.Rollback(rc, config); rollbackErr != nil {
			logger.Error("Rollback also failed", zap.Error(rollbackErr))
		}

		return eos_err.NewUserError("Installation failed: %v", err)
	}

	// EVALUATE - Verify installation
	logger.Info("Verifying OpenStack installation")
	if err := openstack.Verify(rc, config); err != nil {
		return eos_err.NewUserError("Installation verification failed: %v", err)
	}

	// Display summary
	display.ShowInstallationSummary(rc, config)

	return nil
}

func init() {
	// Add command to parent
	CreateCmd.AddCommand(openstackCmd)

	// Mode selection
	openstackCmd.Flags().String("mode", "all-in-one", "Deployment mode: all-in-one, controller, compute, storage")

	// Network configuration
	openstackCmd.Flags().String("network-type", "provider", "Network type: provider, tenant, hybrid")
	openstackCmd.Flags().String("provider-network-interface", "", "Physical network interface for provider networks")
	openstackCmd.Flags().String("provider-physical-network", "physnet1", "Physical network name for provider networks")

	// Storage configuration
	openstackCmd.Flags().String("storage-backend", "lvm", "Storage backend: lvm, ceph, nfs")
	openstackCmd.Flags().String("ceph-monitors", "", "Comma-separated list of Ceph monitor addresses")

	// Service configuration
	openstackCmd.Flags().Bool("enable-dashboard", true, "Enable Horizon dashboard")
	openstackCmd.Flags().Bool("enable-ssl", false, "Enable SSL/TLS for all endpoints")

	// Integration flags
	openstackCmd.Flags().Bool("vault-integration", false, "Enable Vault integration for secrets")
	openstackCmd.Flags().Bool("consul-integration", false, "Enable Consul integration for service discovery")

	// Authentication
	openstackCmd.Flags().String("admin-password", "", "Admin password (will prompt if not provided)")

	// Endpoints
	openstackCmd.Flags().String("public-endpoint", "", "Public API endpoint URL")
	openstackCmd.Flags().String("internal-endpoint", "", "Internal API endpoint URL")

	// Node configuration
	openstackCmd.Flags().String("controller-address", "", "Controller node address (for compute/storage nodes)")

	// Compute configuration
	openstackCmd.Flags().Float64("nova-cpu-allocation-ratio", 16.0, "CPU allocation ratio for compute scheduling")
	openstackCmd.Flags().Float64("nova-ram-allocation-ratio", 1.5, "RAM allocation ratio for compute scheduling")

	// Operational flags
	openstackCmd.Flags().Bool("skip-pre-checks", false, "Skip pre-installation checks")
	openstackCmd.Flags().Bool("dry-run", false, "Show installation plan without executing")
	openstackCmd.Flags().Bool("force", false, "Force installation even if OpenStack is already installed")
	openstackCmd.Flags().Bool("backup", true, "Backup existing configuration before changes")
}

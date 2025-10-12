// cmd/bootstrap/bootstrap.go
// Top-level bootstrap command that provides direct access to bootstrap functionality

package bootstrap

import (
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// BootstrapCmd is the top-level bootstrap command
var BootstrapCmd *cobra.Command

func init() {
	// Create the top-level bootstrap command that defaults to "all"
	BootstrapCmd = &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap all infrastructure components with security hardening",
		Long: `Bootstrap all infrastructure components on a fresh system.
This command installs and configures:
-  (configuration management)
- Storage Operations (monitoring and management)
- Tailscale (secure networking)
- OSQuery (system monitoring)
- Ubuntu security hardening (optional FIDO2 SSH authentication)

MULTI-ENVIRONMENT SETUP:
  Bootstrap with environment awareness for multi-site deployments:

  eos bootstrap --environment dev \
    --frontend cybermonkey-dev \
    --backend vhost5 \
    --enable-vault \
    --enable-nomad

  This will:
  • Create environment configuration (dev/staging/production)
  • Setup WireGuard mesh network between frontend and backend
  • Install Consul server on backend, client on frontend
  • Install Vault on backend (with Consul service discovery)
  • Install Nomad on backend (optional)
  • Configure services to auto-discover each other via Consul

STANDARD EXAMPLES:
  eos bootstrap                     # Bootstrap everything including hardening (default)
  eos bootstrap --guided            # Beginner-friendly guided mode
  eos bootstrap --verify            # Check existing installation status
  eos bootstrap --skip-hardening    # Bootstrap without Ubuntu hardening
  eos bootstrap --single-node       # Bootstrap as single-node deployment
  eos bootstrap --join-cluster      # Join existing cluster
  eos bootstrap --stop-conflicting  # Automatically resolve port conflicts
  eos bootstrap --clean             # Clean slate installation
  eos bootstrap --force             # Force installation despite conflicts

ENVIRONMENT EXAMPLES:
  # Development environment
  eos bootstrap --environment dev --frontend cybermonkey-dev --backend vhost5 --enable-vault

  # Production environment with Nomad
  eos bootstrap --environment production --frontend cybermonkey-net --backend vhost11 --enable-vault --enable-nomad

  # Custom WireGuard config
  eos bootstrap --environment staging \
    --frontend cybermonkey-sh --backend vhost7 \
    --wireguard-subnet 10.10.0.0/24 \
    --frontend-ip 10.10.0.2 --backend-ip 10.10.0.5

Environment Options:
  --environment       Environment name (dev/staging/production)
  --datacenter        Consul datacenter (defaults to environment name)
  --frontend          Frontend/cloud host (e.g., cybermonkey-dev)
  --backend           Backend/on-prem host (e.g., vhost5)
  --wireguard-subnet  WireGuard subnet (auto-assigned by environment)
  --frontend-ip       Frontend WireGuard IP (auto-assigned)
  --backend-ip        Backend WireGuard IP (auto-assigned)
  --enable-vault      Install Vault on backend (registers with Consul)
  --enable-nomad      Install Nomad on backend

Enhanced Options:
  --guided            Step-by-step guidance for beginners
  --verify            Verify existing bootstrap without changes
  --stop-conflicting  Automatically stop conflicting services
  --continue          Continue with existing Eos installation
  --clean             Clean slate - remove existing services
  --reconfigure       Reconfigure existing services
  --force             Force bootstrap despite conflicts

Standard Options:
  --skip-hardening    Skip Ubuntu security hardening
  --single-node       Configure as single-node deployment
  --join-cluster      Join existing cluster at specified address
  --preferred-role    Set role when joining cluster (edge/core/data/compute)
  --auto-discover     Enable automatic cluster discovery`,
		RunE: eos_cli.Wrap(runBootstrapAllTop),
	}

	// Add the same flags as create bootstrap all
	BootstrapCmd.Flags().String("join-cluster", "", "Join existing cluster at specified master address")
	BootstrapCmd.Flags().Bool("single-node", false, "Explicitly configure as single-node deployment")
	BootstrapCmd.Flags().String("preferred-role", "", "Preferred role when joining cluster (edge/core/data/compute)")
	BootstrapCmd.Flags().Bool("auto-discover", false, "Enable automatic cluster discovery via multicast")
	BootstrapCmd.Flags().Bool("skip-hardening", false, "Skip Ubuntu security hardening (not recommended for production)")
	BootstrapCmd.Flags().Bool("force", false, "Force bootstrap even if system appears to be already bootstrapped")
	BootstrapCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	BootstrapCmd.Flags().Bool("validate-only", false, "Only validate system requirements without bootstrapping")

	// Enhanced bootstrap flags
	BootstrapCmd.Flags().Bool("verify", false, "Verify existing bootstrap without making changes")
	BootstrapCmd.Flags().Bool("guided", false, "Use guided mode for beginners with step-by-step instructions")
	BootstrapCmd.Flags().Bool("stop-conflicting", false, "Automatically stop conflicting services")
	BootstrapCmd.Flags().Bool("continue", false, "Continue with existing Eos installation")
	BootstrapCmd.Flags().Bool("clean", false, "Clean slate - remove existing services and start fresh")
	BootstrapCmd.Flags().Bool("reconfigure", false, "Reconfigure existing services")

	// HashiCorp service flags
	// Consul is always installed as it's required for service discovery
	BootstrapCmd.Flags().Bool("enable-vault", false, "Install and configure HashiCorp Vault (opt-in)")
	BootstrapCmd.Flags().Bool("enable-nomad", false, "Install and configure HashiCorp Nomad (opt-in)")

	// Environment setup flags (multi-environment deployment)
	BootstrapCmd.Flags().String("environment", "", "Environment name (dev/staging/production)")
	BootstrapCmd.Flags().String("datacenter", "", "Consul datacenter (defaults to environment name)")
	BootstrapCmd.Flags().String("frontend", "", "Frontend/cloud host (e.g., cybermonkey-dev)")
	BootstrapCmd.Flags().String("backend", "", "Backend/on-prem host (e.g., vhost5)")
	BootstrapCmd.Flags().String("wireguard-subnet", "", "WireGuard subnet (e.g., 10.0.0.0/24)")
	BootstrapCmd.Flags().String("frontend-ip", "", "Frontend WireGuard IP (e.g., 10.0.0.2)")
	BootstrapCmd.Flags().String("backend-ip", "", "Backend WireGuard IP (e.g., 10.0.0.5)")

}

// AddSubcommands adds all bootstrap subcommands to BootstrapCmd
func AddSubcommands() {
	BootstrapCmd.AddCommand(GetCoreCmd())
	BootstrapCmd.AddCommand(GetAllCmd())
	BootstrapCmd.AddCommand(GetQuickstartCmd())
	BootstrapCmd.AddCommand(GetVaultCmd())
	BootstrapCmd.AddCommand(GetNomadCmd())
	BootstrapCmd.AddCommand(GetOsqueryCmd())
}

// runBootstrapAllTop runs the enhanced bootstrap all command (top-level bootstrap)
func runBootstrapAllTop(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := rc.Log
	logger.Info("Bootstrap command started")

	// FIXME: [P3] Using environment variable for state management is fragile
	// Set environment variable to prevent bootstrap prompt recursion
	_ = os.Setenv("EOS_BOOTSTRAP_IN_PROGRESS", "1")
	logger.Info("Set Eos_BOOTSTRAP_IN_PROGRESS=1 to prevent recursion")

	// Directly call the enhanced bootstrap function from bootstrap package
	logger.Info("Calling enhanced bootstrap function")
	return RunBootstrapAllEnhanced(rc, cmd, args)
}

// cmd/bootstrap/bootstrap.go
// Top-level bootstrap command that provides direct access to bootstrap functionality

package bootstrap

import (
	"os"
	
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
- Salt (configuration management)
- Storage Operations (monitoring and management)
- Tailscale (secure networking)
- OSQuery (system monitoring)
- Ubuntu security hardening (optional FIDO2 SSH authentication)

Examples:
  eos bootstrap                  # Bootstrap everything including hardening (default)
  eos bootstrap --skip-hardening # Bootstrap without Ubuntu hardening
  eos bootstrap --single-node    # Bootstrap as single-node deployment
  eos bootstrap --join-cluster   # Join existing cluster

Flags:
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
	
}

// AddSubcommands adds all bootstrap subcommands to BootstrapCmd
func AddSubcommands() {
	BootstrapCmd.AddCommand(GetCoreCmd())
	BootstrapCmd.AddCommand(GetAllCmd())
	BootstrapCmd.AddCommand(GetQuickstartCmd())
	BootstrapCmd.AddCommand(GetSaltCmd())
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
	os.Setenv("EOS_BOOTSTRAP_IN_PROGRESS", "1")
	logger.Info("Set EOS_BOOTSTRAP_IN_PROGRESS=1 to prevent recursion")
	
	// Directly call the enhanced bootstrap function from bootstrap package
	logger.Info("Calling enhanced bootstrap function")
	return RunBootstrapAllEnhanced(rc, cmd, args)
}
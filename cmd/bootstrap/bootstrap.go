// cmd/bootstrap/bootstrap.go
// Top-level bootstrap command that provides direct access to bootstrap functionality

package bootstrap

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
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
		RunE: eos_cli.Wrap(runBootstrapAll),
	}
	
	// Add the same flags as create bootstrap all
	BootstrapCmd.Flags().String("join-cluster", "", "Join existing cluster at specified master address")
	BootstrapCmd.Flags().Bool("single-node", false, "Explicitly configure as single-node deployment")
	BootstrapCmd.Flags().String("preferred-role", "", "Preferred role when joining cluster (edge/core/data/compute)")
	BootstrapCmd.Flags().Bool("auto-discover", false, "Enable automatic cluster discovery via multicast")
	BootstrapCmd.Flags().Bool("skip-hardening", false, "Skip Ubuntu security hardening (not recommended for production)")
}

// runBootstrapAll runs the enhanced bootstrap all command
func runBootstrapAll(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Directly call the enhanced bootstrap function from create package
	return create.RunBootstrapAllEnhanced(rc, cmd, args)
}
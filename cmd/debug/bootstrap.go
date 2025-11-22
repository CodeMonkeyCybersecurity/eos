// cmd/debug/bootstrap.go
package debug

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	bootstrapdebug "github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap/debug"
	"github.com/spf13/cobra"
)

var debugBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Debug bootstrap process and infrastructure setup",
	Long: `Comprehensive diagnostics for the Eos bootstrap process.

This command examines the entire bootstrap state, checks for conflicts,
validates prerequisites, and identifies exactly where and why the bootstrap
process is failing.

Checks performed:
1. System information (OS, kernel, architecture)
2. Bootstrap prerequisites (systemd, wget, curl, unzip)
3. Bootstrap state markers and flags
4. Bootstrap locks (detect stale locks from crashed processes)
5. Infrastructure services (Consul, Vault, Nomad)
6. Port conflicts on infrastructure ports
7. Network configuration and connectivity
8. System resources (memory, CPU, disk)
9. Bootstrap phase status
10. Previous bootstrap attempts analysis

Example:
  eos debug bootstrap`,
	RunE: eos.WrapDebug("bootstrap", runDebugBootstrap),
}

func init() {
	debugCmd.AddCommand(debugBootstrapCmd)
}

func runDebugBootstrap(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Parse flags (currently no flags defined, but structure ready)
	config := &bootstrapdebug.DiagnosticConfig{
		Verbose:    false,
		JSONOutput: false,
	}

	// Delegate to pkg/
	return bootstrapdebug.RunDiagnostics(rc, config)
}

// cmd/debug/iris.go
package debug

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	irisdebug "github.com/CodeMonkeyCybersecurity/eos/pkg/iris/debug"
	"github.com/spf13/cobra"
)

var debugIrisCmd = &cobra.Command{
	Use:   "iris",
	Short: "Debug Iris installation and configuration",
	Long: `Comprehensive diagnostic tool for Iris security alert processing system.

Enhanced Phase 1 checks performed:

Infrastructure (6 checks):
  • Project structure and files
  • Temporal CLI availability
  • Binary accessibility (non-root user access)
  • Port status (7233, 8233, 8080)
  • Temporal server health (deep check with gRPC verification)

Configuration (3 checks):
  • Configuration file validity
  • Azure OpenAI configuration
  • SMTP configuration

Services (3 checks):
  • Worker process health (with uptime check)
  • Webhook server health (with HTTP health endpoint)
  • Recent workflows in Temporal

System (1 check):
  • Go module dependencies

Flags:
  --test      Send a test alert through the system
  --verbose   Show detailed diagnostic output`,
	RunE: eos.WrapDebug("iris", runDebugIris),
}

var (
	testAlert bool
	verbose   bool
)

func init() {
	debugIrisCmd.Flags().BoolVar(&testAlert, "test", false, "Send a test alert")
	debugIrisCmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")
	debugCmd.AddCommand(debugIrisCmd)
}

func runDebugIris(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Parse flags into config
	config := &irisdebug.DiagnosticConfig{
		ProjectDir: "/opt/iris",
		TestAlert:  testAlert,
		Verbose:    verbose,
	}

	// Delegate to pkg/
	return irisdebug.RunDiagnostics(rc, config)
}

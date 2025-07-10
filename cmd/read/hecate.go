// cmd/read/read.go

package read

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// readHecateCmd is the top-level `inspect` command
var readHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Inspect the current state of Hecate-managed services",
	Long: `Use this command to inspect the status, configuration, and health of 
reverse proxy applications deployed via Hecate.

Examples:
	hecate inspect config
	hecate inspect`,
	Aliases: []string{"read", "get"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		fmt.Println(" Please use a subcommand (e.g. 'inspect config') to inspect a resource.")
		return nil
	}),
}

// Register subcommands when the package is loaded
func init() {
	readHecateCmd.AddCommand(inspectConfigCmd)
}

// inspectConfigCmd represents the "inspect config" subcommand
var inspectConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect configurations",
	Long: `This command lets you inspect various configuration resources for Hecate.
You can choose from:
  1) Inspect Certificates
  2) Inspect docker compose file
  3) Inspect Eos backend web apps configuration
  4) Inspect Nginx defaults
  5) Inspect all configurations`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runInspectConfig(rc)
	}),
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// runInspectConfig presents an interactive menu for inspection
func runInspectConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Inspect Configurations Menu")
	logger.Info("Select the resource you want to inspect:")
	logger.Info("1) Inspect Certificates")
	logger.Info("2) Inspect docker compose file")
	logger.Info("3) Inspect Eos backend web apps configuration")
	logger.Info("4) Inspect Nginx defaults")
	logger.Info("5) Inspect all configurations")
	logger.Info("Enter choice (1-5): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.ToLower(strings.TrimSpace(choice))

	switch choice {
	case "1", "certificates", "certs":
		logger.Info("Inspecting certificates...")
		// TODO: Implement certificate inspection
	case "2", "compose", "docker-compose":
		logger.Info("Inspecting docker compose file...")
		// TODO: Implement docker compose inspection
	case "3", "github.com/CodeMonkeyCybersecurity/eos":
		logger.Info("Inspecting Eos configuration...")
		// TODO: Implement Eos config inspection
	case "4", "nginx":
		logger.Info("Inspecting Nginx defaults...")
		// TODO: Implement Nginx defaults inspection
	case "5", "all":
		logger.Info("Inspecting all configurations...")
		// TODO: Implement all inspections
	default:
		logger.Error(" Invalid choice provided", zap.String("choice", choice))
		return fmt.Errorf("invalid choice: %s", choice)
	}

	return nil
}

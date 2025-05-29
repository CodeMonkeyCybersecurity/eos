/* cmd/hecate/update/update.go */

package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateCmd represents the "update" command.
var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update configurations and services",
	Long: `Update Hecate configurations, renew certificates, or update specific services.

Examples:
  hecate update certs
  hecate update eos
  hecate update http
  hecate update docker-compose`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for update command.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Initialize the shared global logger.

	// Attach subcommands to UpdateCmd.
	UpdateCmd.AddCommand(runCertsCmd)
	UpdateCmd.AddCommand(runEosCmd)
	UpdateCmd.AddCommand(runHttpCmd)
	// The docker-compose subcommand is defined in docker_compose.go.
}

// runCertsCmd renews SSL certificates.
var runCertsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Renew SSL certificates",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for certs command.", zap.String("command", cmd.Use))
		_ = cmd.Help()
		return nil
	}),
}

// runEosCmd updates the Eos eos_unix.
var runEosCmd = &cobra.Command{
	Use:   "eos",
	Short: "Update Eos system",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for eos command.", zap.String("command", cmd.Use))
		_ = cmd.Help()
		return nil
	}),
}

// runHttpCmd updates the HTTP server configuration.
var runHttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Update HTTP configurations",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for http command.", zap.String("command", cmd.Use))
		_ = cmd.Help()
		return nil
	}),
}

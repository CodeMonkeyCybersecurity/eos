/* cmd/update/hecate.go */

package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// updateHecateCmd represents the "update hecate" command.
var updateHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Update Hecate configurations and services",
	Long: `Update Hecate configurations, renew certificates, or update specific services.

Examples:
  eos update hecate certs
  eos update hecate eos
  eos update hecate http
  eos update hecate k3s`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for update hecate command.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Add updateHecateCmd to the main UpdateCmd
	UpdateCmd.AddCommand(updateHecateCmd)

	// Attach subcommands to updateHecateCmd.
	updateHecateCmd.AddCommand(runCertsCmd)
	updateHecateCmd.AddCommand(runEosCmd)
	updateHecateCmd.AddCommand(runHttpCmd)
	updateHecateCmd.AddCommand(runK3sCmd)
}

// runK3sCmd updates the k3s deployment configuration.
var runK3sCmd = &cobra.Command{
	Use:   "k3s",
	Short: "Update k3s deployment configuration",
	Long: `Update the k3s deployment by applying updated manifests and restarting services.
This is the preferred method for managing Hecate containers.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		config := &hecate.UpdateConfig{}
		updater := hecate.NewHecateUpdater(rc, config)
		return updater.UpdateK3sDeployment()
	}),
}

// runCertsCmd renews SSL certificates.
var runCertsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Renew SSL certificates",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		config := &hecate.UpdateConfig{}
		updater := hecate.NewHecateUpdater(rc, config)
		return updater.RenewCertificates()
	}),
}

// runEosCmd updates the Eos system.
var runEosCmd = &cobra.Command{
	Use:   "eos",
	Short: "Update Eos system",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		config := &hecate.UpdateConfig{}
		updater := hecate.NewHecateUpdater(rc, config)
		return updater.UpdateEosSystem()
	}),
}

// runHttpCmd updates the HTTP server configuration.
var runHttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Update HTTP configurations",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		config := &hecate.UpdateConfig{}
		updater := hecate.NewHecateUpdater(rc, config)
		return updater.UpdateHTTPConfig()
	}),
}

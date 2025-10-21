/* cmd/update/hecate.go */

package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// updateHecateCmd represents the "update hecate" command.
var updateHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Update Hecate deployment (regenerate files from Consul KV)",
	Long: `Regenerate Hecate docker-compose.yml and .env files from configuration stored in Consul KV.

This command:
  1. Backs up existing files with timestamp
  2. Loads configuration from Consul KV (service/hecate/config/apps/)
  3. Regenerates docker-compose.yml and .env with latest templates
  4. Restarts containers to apply changes

Use this when:
  - Eos code has been updated with bug fixes
  - You need to apply configuration changes
  - Files were manually deleted or corrupted

Examples:
  eos update hecate              # Regenerate from Consul KV
  eos update hecate certs        # Only renew certificates
  eos update hecate k3s          # Update k3s deployment`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Regenerating Hecate deployment from Consul KV configuration")

		// Regenerate from Consul KV with backup
		return hecate.RegenerateFromConsulKV(rc)
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

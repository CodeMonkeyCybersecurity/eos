// cmd/update/authentik.go

package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/authentik"
	"github.com/spf13/cobra"
)

// updateAuthentikCmd represents the "update authentik" command
var updateAuthentikCmd = &cobra.Command{
	Use:   "authentik",
	Args:  cobra.NoArgs,
	Short: "Update or export Authentik configuration",
	Long: `Update Authentik configuration or export the current setup as a Blueprint archive.

With --export flag:
  1. Retrieves Authentik credentials from /opt/hecate/.env
  2. Queries Caddy to determine the correct Authentik base URL
  3. Runs "ak export_blueprint" inside the Authentik container
  4. Copies the generated Blueprint YAML to /opt/hecate/exports/authentik_blueprint_TIMESTAMP/

Use this when:
  - You want a vendor-supported export that respects Authentik dependencies
  - You need to promote changes between environments using Blueprints
  - You prefer a single YAML artifact instead of the legacy multi-file dump

Example:
  eos update authentik --export`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Check if --export flag is set
		exportFlag, _ := cmd.Flags().GetBool("export")

		if exportFlag {
			return authentik.ExportAuthentikConfig(rc)
		}

		// Default behavior (no flags) - could add update logic here in the future
		return cmd.Help()
	}),
}

func init() {
	UpdateCmd.AddCommand(updateAuthentikCmd)

	// Add --export flag
	updateAuthentikCmd.Flags().Bool("export", false, "Export Authentik configuration as a Blueprint")
}

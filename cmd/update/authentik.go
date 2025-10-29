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
	Long: `Update Authentik configuration or export the current configuration to a backup.

With --export flag:
  1. Retrieves Authentik API token from /opt/hecate/.env
  2. Queries Caddy API to determine Authentik base URL
  3. Exports all Authentik configurations via API:
     - Applications (BionicGPT)
     - Proxy providers
     - Outposts and health status
     - Authentication and authorization flows
     - Property mappings
     - OAuth2 sources
     - Policies
     - System configuration
     - Tenants and brands
  4. Copies Caddyfile and docker-compose.yml
  5. Creates timestamped backup in /opt/hecate/exports/
  6. Generates README with restore instructions
  7. Creates compressed tar.gz archive

Use this when:
  - You want to backup Authentik configuration before changes
  - You need to replicate configuration to another environment
  - You're troubleshooting Authentik integration issues
  - You want to document current SSO setup

Examples:
  # Export current Authentik configuration
  eos update authentik --export

  # The export will be saved to:
  # /opt/hecate/exports/authentik_config_backup_YYYYMMDD_HHMMSS/

Output includes:
  - JSON files with all Authentik configurations
  - Caddyfile with reverse proxy rules
  - docker-compose.yml with service definitions
  - README.md with restore instructions
  - Compressed tar.gz archive for easy transfer`,
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
	updateAuthentikCmd.Flags().Bool("export", false, "Export Authentik configuration to backup")
}

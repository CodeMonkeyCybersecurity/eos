// cmd/update/hecate_add.go

package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/add"
	"github.com/spf13/cobra"
)

// addServiceCmd adds a new service to Hecate
var addServiceCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new reverse proxy route to Hecate",
	Long: `Add a new service to an existing Hecate installation by modifying the Caddyfile.

This command:
  1. Validates input (DNS, backend, SSO configuration)
  2. Checks DNS resolution and backend connectivity
  3. Backs up the existing Caddyfile
  4. Adds the new route configuration
  5. Validates and reloads Caddy (no restart)
  6. Verifies the new route is working

Examples:
  # Basic service without SSO
  eos update hecate add \
    --service bionicgpt \
    --dns chat.codemonkey.ai \
    --backend 100.64.0.50:8080

  # Service with SSO enabled
  eos update hecate add \
    --service nextcloud \
    --dns cloud.codemonkey.ai \
    --backend 100.64.0.51:80 \
    --sso

  # Dry run to see what would be changed
  eos update hecate add \
    --service wazuh \
    --dns wazuh.codemonkey.ai \
    --backend 100.64.0.52:443 \
    --dry-run

  # With custom Caddy directives
  eos update hecate add \
    --service api \
    --dns api.codemonkey.ai \
    --backend 100.64.0.53:3000 \
    --custom-directive "rate_limit 100/m" \
    --custom-directive "header X-Custom-Header value"`,
	RunE: eos.Wrap(runAddService),
}

func init() {
	// Add as subcommand of updateHecateCmd
	updateHecateCmd.AddCommand(addServiceCmd)

	// Required flags with short aliases for better UX
	addServiceCmd.Flags().StringP("service", "s", "", "Service name (alphanumeric, hyphens, underscores)")
	addServiceCmd.Flags().StringP("dns", "d", "", "Domain/subdomain for this service (aliases: --domain, --route, --host)")
	addServiceCmd.Flags().StringP("backend", "b", "", "Backend address (ip:port or hostname:port) (aliases: --upstream, --target)")

	// Optional flags
	addServiceCmd.Flags().Bool("sso", false, "Enable SSO for this route")
	addServiceCmd.Flags().String("sso-provider", "authentik", "SSO provider to use (default: authentik)")
	addServiceCmd.Flags().StringSlice("custom-directive", []string{}, "Custom Caddy directives (can specify multiple times)")
	addServiceCmd.Flags().Bool("dry-run", false, "Show what would be changed without applying")
	addServiceCmd.Flags().Bool("skip-dns-check", false, "Skip DNS resolution validation")
	addServiceCmd.Flags().Bool("skip-backend-check", false, "Skip backend connectivity check")
	addServiceCmd.Flags().Int("backup-retention-days", 30, "Days to keep old backups (0 = keep forever)")
}

func runAddService(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Parse flags
	service, _ := cmd.Flags().GetString("service")
	dns, _ := cmd.Flags().GetString("dns")
	backend, _ := cmd.Flags().GetString("backend")
	sso, _ := cmd.Flags().GetBool("sso")
	ssoProvider, _ := cmd.Flags().GetString("sso-provider")
	customDirectives, _ := cmd.Flags().GetStringSlice("custom-directive")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipDNSCheck, _ := cmd.Flags().GetBool("skip-dns-check")
	skipBackendCheck, _ := cmd.Flags().GetBool("skip-backend-check")
	backupRetentionDays, _ := cmd.Flags().GetInt("backup-retention-days")

	// Build options
	opts := &add.ServiceOptions{
		Service:             service,
		DNS:                 dns,
		Backend:             backend,
		SSO:                 sso,
		SSOProvider:         ssoProvider,
		CustomDirectives:    customDirectives,
		DryRun:              dryRun,
		SkipDNSCheck:        skipDNSCheck,
		SkipBackendCheck:    skipBackendCheck,
		BackupRetentionDays: backupRetentionDays,
	}

	// Execute the add operation
	return add.AddService(rc, opts)
}

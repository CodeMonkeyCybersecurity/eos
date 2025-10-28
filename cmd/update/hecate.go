/* cmd/update/hecate.go */

package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/add"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// updateHecateCmd represents the "update hecate" command.
var updateHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Update Hecate deployment (regenerate files from Consul KV or add service)",
	Long: `Regenerate Hecate docker-compose.yml and .env files from configuration stored in Consul KV,
or add a new reverse proxy route to an existing Hecate installation.

Default behavior (no flags):
  1. Backs up existing files with timestamp
  2. Loads configuration from Consul KV (service/hecate/config/apps/)
  3. Regenerates docker-compose.yml and .env with latest templates
  4. Restarts containers to apply changes

With --add flag:
  1. Validates input (DNS, backend, SSO configuration)
  2. Checks DNS resolution and backend connectivity
  3. Backs up the existing Caddyfile
  4. Adds the new route configuration
  5. Validates and reloads Caddy (no restart)
  6. Verifies the new route is working

Use this when:
  - Eos code has been updated with bug fixes
  - You need to apply configuration changes
  - Files were manually deleted or corrupted
  - You want to add a new service to Hecate

Examples:
  eos update hecate                              # Regenerate from Consul KV
  eos update hecate certs                        # Only renew certificates
  eos update hecate k3s                          # Update k3s deployment

  # Add new service (basic)
  eos update hecate --add bionicgpt \
    --route chat.codemonkey.ai \
    --upstream 100.64.0.50:8080

  # Add new service with SSO
  eos update hecate --add nextcloud \
    --route cloud.codemonkey.ai \
    --upstream 100.64.0.51:80 \
    --sso

  # Dry run to see changes
  eos update hecate --add wazuh \
    --route wazuh.codemonkey.ai \
    --upstream 100.64.0.52:443 \
    --dry-run`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Check if --add flag is set
		addService, _ := cmd.Flags().GetString("add")
		if addService != "" {
			// Delegate to add service flow
			return runAddServiceFromFlag(rc, cmd, addService)
		}

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

	// Add service management flags
	updateHecateCmd.Flags().String("add", "", "Add a new service to Hecate (service name)")
	updateHecateCmd.Flags().String("route", "", "Domain/subdomain for the service (aliases: --dns, --domain, --host)")
	updateHecateCmd.Flags().String("upstream", "", "Backend address (ip:port or hostname:port) (aliases: --backend, --target)")

	// Optional flags for --add
	updateHecateCmd.Flags().Bool("sso", false, "Enable SSO for this route")
	updateHecateCmd.Flags().String("sso-provider", "authentik", "SSO provider to use (default: authentik)")
	updateHecateCmd.Flags().StringSlice("custom-directive", []string{}, "Custom Caddy directives (can specify multiple times)")
	updateHecateCmd.Flags().Bool("dry-run", false, "Show what would be changed without applying")
	updateHecateCmd.Flags().Bool("skip-dns-check", false, "Skip DNS resolution validation")
	updateHecateCmd.Flags().Bool("skip-backend-check", false, "Skip backend connectivity check")
	updateHecateCmd.Flags().Int("backup-retention-days", 30, "Days to keep old backups (0 = keep forever)")

	// Mark route and upstream as required when --add is used (validated in RunE)
}

// runAddServiceFromFlag handles adding a new service when --add flag is used
func runAddServiceFromFlag(rc *eos_io.RuntimeContext, cmd *cobra.Command, service string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags (using "route" instead of "dns" as per new flag name)
	route, _ := cmd.Flags().GetString("route")
	upstream, _ := cmd.Flags().GetString("upstream")
	sso, _ := cmd.Flags().GetBool("sso")
	ssoProvider, _ := cmd.Flags().GetString("sso-provider")
	customDirectives, _ := cmd.Flags().GetStringSlice("custom-directive")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipDNSCheck, _ := cmd.Flags().GetBool("skip-dns-check")
	skipBackendCheck, _ := cmd.Flags().GetBool("skip-backend-check")
	backupRetentionDays, _ := cmd.Flags().GetInt("backup-retention-days")

	// Validate required flags
	if route == "" {
		return fmt.Errorf("--route flag is required when using --add\nExample: eos update hecate --add %s --route chat.example.com --upstream 100.64.0.1:8080", service)
	}
	if upstream == "" {
		return fmt.Errorf("--upstream flag is required when using --add\nExample: eos update hecate --add %s --route chat.example.com --upstream 100.64.0.1:8080", service)
	}

	logger.Info("Adding new service to Hecate",
		zap.String("service", service),
		zap.String("route", route),
		zap.String("upstream", upstream),
		zap.Bool("sso", sso))

	// Build options
	opts := &add.ServiceOptions{
		Service:             service,
		DNS:                 route, // Map route to DNS field
		Backend:             upstream,
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

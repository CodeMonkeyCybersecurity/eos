/* cmd/update/hecate.go */

package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/add"
	hecateexport "github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/export"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// updateHecateCmd represents the "update hecate" command.
var updateHecateCmd = &cobra.Command{
	Use:   "hecate",
	Args:  cobra.NoArgs, // Parent command takes no positional args
	Short: "Update Hecate deployment (regenerate files from Consul KV or add service)",
	Long: `Regenerate Hecate docker-compose.yml and .env files from configuration stored in Consul KV,
or add a new reverse proxy route to an existing Hecate installation.

Default behavior (no flags):
  1. Backs up existing files with timestamp
  2. Loads configuration from Consul KV (service/hecate/config/apps/)
  3. Regenerates docker-compose.yml and .env with latest templates
  4. Restarts containers to apply changes

With --export flag:
  1. Exports complete Hecate infrastructure configuration
  2. Includes Authentik SSO configuration via API
  3. Includes docker-compose.yml, Caddyfile, .env
  4. Creates timestamped backup in /opt/hecate/exports/
  5. Generates compressed tar.gz archive

With --refresh flag:
  1. Gracefully reloads Caddy configuration (zero downtime)
  2. Preserves TLS certificates in memory (no renewal)
  3. Uses Admin API (preferred) → docker exec → restart (fallback)
  4. Safe for repeated use during debugging (no rate limits)

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
  - You manually edited Caddyfile and need to reload

Examples:
  eos update hecate                              # Regenerate from Consul KV
  eos update hecate --export                     # Export complete configuration (Authentik + files)
  eos update hecate --refresh                    # Gracefully reload Caddy (preserves TLS certs)
  eos update hecate certs                        # Only renew certificates
  eos update hecate k3s                          # Update k3s deployment

  # Enable features (OAuth2 signout, self-enrollment)
  eos update hecate --enable oauth2-signout      # Add logout handlers to protected routes
  eos update hecate --enable self-enrollment --app bionicgpt --dns chat.example.com
  eos update hecate --enable self-enrollment --app bionicgpt --dns chat.example.com --dry-run

  # Fix Caddy configuration drift (Admin API binding + network name)
  eos update hecate --fix caddy                  # Apply both fixes and restart Caddy
  eos update hecate --fix caddy --dry-run        # Preview fixes without applying

  # Add BionicGPT (auto-detects port :8513 and enables SSO automatically)
  eos update hecate --add bionicgpt \
    --dns chat.codemonkey.ai \
    --upstream 100.64.0.50

  # Add service with custom port
  eos update hecate --add bionicgpt \
    --dns chat.codemonkey.ai \
    --upstream 100.64.0.50:7703

  # Add service with SSO
  eos update hecate --add nextcloud \
    --dns cloud.codemonkey.ai \
    --upstream 100.64.0.51:80 \
    --sso

  # Dry run to see changes
  eos update hecate --add wazuh \
    --dns wazuh.codemonkey.ai \
    --upstream 100.64.0.52:443 \
    --dry-run`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Check if --export flag is explicitly set
		exportWasSet := cmd.Flags().Changed("export")

		// Check if --refresh flag is explicitly set
		refreshWasSet := cmd.Flags().Changed("refresh")

		// Check if --add flag is explicitly set
		addService, _ := cmd.Flags().GetString("add")
		addWasSet := cmd.Flags().Changed("add")

		// Check if --remove flag is explicitly set
		removeService, _ := cmd.Flags().GetString("remove")
		removeWasSet := cmd.Flags().Changed("remove")

		// Check if --fix flag is explicitly set
		fixService, _ := cmd.Flags().GetString("fix")
		fixWasSet := cmd.Flags().Changed("fix")

		// Check if --enable flag is explicitly set
		enableFeature, _ := cmd.Flags().GetString("enable")
		enableWasSet := cmd.Flags().Changed("enable")

		// Validate mutually exclusive flags
		exclusiveFlagsCount := 0
		if exportWasSet {
			exclusiveFlagsCount++
		}
		if refreshWasSet {
			exclusiveFlagsCount++
		}
		if addWasSet {
			exclusiveFlagsCount++
		}
		if removeWasSet {
			exclusiveFlagsCount++
		}
		if fixWasSet {
			exclusiveFlagsCount++
		}
		if enableWasSet {
			exclusiveFlagsCount++
		}

		if exclusiveFlagsCount > 1 {
			return fmt.Errorf("cannot use --export, --refresh, --add, --remove, --fix, and --enable together\nUse one at a time")
		}

		if exportWasSet {
			// Delegate to export flow (backup all Hecate infrastructure)
			return hecateexport.ExportHecateConfig(rc)
		}

		if refreshWasSet {
			// Delegate to refresh flow (graceful Caddy reload)
			return runRefreshCaddy(rc, cmd)
		}

		if addWasSet {
			if addService == "" {
				return fmt.Errorf("--add requires a service name\nExample: eos update hecate --add bionicgpt --dns chat.example.com --upstream 100.64.0.1:8080")
			}
			// Delegate to add service flow
			return runAddServiceFromFlag(rc, cmd, addService)
		}

		if removeWasSet {
			if removeService == "" {
				return fmt.Errorf("--remove requires a service name\nExample: eos update hecate --remove bionicgpt")
			}
			// Delegate to remove service flow
			return runRemoveServiceFromFlag(rc, cmd, removeService)
		}

		if fixWasSet {
			if fixService == "" {
				return fmt.Errorf("--fix requires a service name\nExample: eos update hecate --fix bionicgpt")
			}
			// Delegate to fix service flow
			return runFixServiceFromFlag(rc, cmd, fixService)
		}

		if enableWasSet {
			if enableFeature == "" {
				return fmt.Errorf("--enable requires a feature name\nExample: eos update hecate --enable self-enrollment --app bionicgpt")
			}
			// Delegate to enable feature flow
			return runEnableFeature(rc, cmd, enableFeature)
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

	// Add export flag
	updateHecateCmd.Flags().Bool("export", false, "Export complete Hecate infrastructure configuration (Authentik + docker-compose + Caddyfile + .env)")

	// Add service management flags
	updateHecateCmd.Flags().Bool("refresh", false, "Gracefully reload Caddy configuration (zero-downtime, preserves TLS certificates)")
	updateHecateCmd.Flags().String("add", "", "Add a new service to Hecate (service name)")
	updateHecateCmd.Flags().String("remove", "", "Remove a service from Hecate (service name)")
	updateHecateCmd.Flags().String("fix", "", "Fix drift/misconfigurations for a service (service name)")
	updateHecateCmd.Flags().String("enable", "", "Enable a feature for Hecate (feature name: self-enrollment, oauth2-signout, default-flows)")
	updateHecateCmd.Flags().StringP("dns", "d", "", "Domain/subdomain for the service (required with --add)")
	updateHecateCmd.Flags().StringP("upstream", "u", "", "Backend address (ip:port or hostname:port, required with --add)")

	// Feature flags (used with --enable)
	updateHecateCmd.Flags().String("app", "", "Application name (used with --enable self-enrollment)")
	updateHecateCmd.Flags().String("authentik-host", "hecate-server-1", "Authentik hostname (used with --enable)")
	updateHecateCmd.Flags().Int("authentik-port", hecate.AuthentikPort, "Authentik port (used with --enable)")
	updateHecateCmd.Flags().Bool("skip-caddyfile", false, "Skip Caddyfile updates (used with --enable, advanced usage)")
	updateHecateCmd.Flags().Bool("enable-captcha", true, "Enable captcha for self-enrollment (default: true, uses test keys initially)")
	updateHecateCmd.Flags().Bool("disable-captcha", false, "Disable captcha protection (NOT RECOMMENDED for production)")
	updateHecateCmd.Flags().Bool("require-approval", false, "New users inactive until admin approves (default: active immediately)")
	updateHecateCmd.Flags().Bool("update-existing", true, "Replace existing Authentik resources when enabling default flows")

	// Optional flags for --add
	updateHecateCmd.Flags().Bool("sso", false, "Enable SSO for this route (NOTE: BionicGPT always uses Authentik forward auth regardless of this flag)")
	updateHecateCmd.Flags().String("sso-provider", "authentik", "SSO provider to use (default: authentik)")
	updateHecateCmd.Flags().StringSlice("custom-directive", []string{}, "Custom Caddy directives (can specify multiple times)")
	updateHecateCmd.Flags().Bool("dry-run", false, "Show what would be changed without applying")
	updateHecateCmd.Flags().Bool("skip-dns-check", false, "Skip DNS resolution validation")
	updateHecateCmd.Flags().Bool("skip-backend-check", false, "Skip backend connectivity check")
	updateHecateCmd.Flags().Int("backup-retention-days", 30, "Days to keep old backups (0 = keep forever)")

	// Email configuration flags (used with --add authentik-email)
	updateHecateCmd.Flags().String("test-email", "", "Send test email to this address after configuration")

	// Mark route and upstream as required when --add is used (validated in RunE)
}

// runAddServiceFromFlag handles adding a new service when --add flag is used
func runAddServiceFromFlag(rc *eos_io.RuntimeContext, cmd *cobra.Command, service string) error {
	if service == "authentik-email" {
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		testEmail, _ := cmd.Flags().GetString("test-email")
		return runAddAuthentikEmail(rc, dryRun, testEmail)
	}

	// Parse flags
	dns, _ := cmd.Flags().GetString("dns")
	upstream, _ := cmd.Flags().GetString("upstream")
	sso, _ := cmd.Flags().GetBool("sso")
	ssoProvider, _ := cmd.Flags().GetString("sso-provider")
	customDirectives, _ := cmd.Flags().GetStringSlice("custom-directive")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipDNSCheck, _ := cmd.Flags().GetBool("skip-dns-check")
	skipBackendCheck, _ := cmd.Flags().GetBool("skip-backend-check")
	backupRetentionDays, _ := cmd.Flags().GetInt("backup-retention-days")

	// Validate required flags early (fail fast)
	if dns == "" {
		return fmt.Errorf("--dns flag is required when using --add\nExample: eos update hecate --add %s --dns chat.example.com --upstream 100.64.0.1:8080", service)
	}
	if upstream == "" {
		return fmt.Errorf("--upstream flag is required when using --add\nExample: eos update hecate --add %s --dns chat.example.com --upstream 100.64.0.1:8080", service)
	}

	// Auto-append default port for known services if port is missing
	// This improves UX by allowing: --upstream 100.71.196.79 instead of --upstream 100.71.196.79:8513
	backendWithPort := add.EnsureBackendHasPort(service, upstream)

	// Auto-enable SSO for services that require it (e.g., BionicGPT)
	// This matches wizard behavior and reduces operator cognitive load
	// If user explicitly provided --sso flag, respect their choice
	// If service requires SSO by default, enable it automatically
	ssoEnabled := sso || add.ServiceRequiresSSO(service)

	// NOTE: No logging here - business layer (pkg/hecate/add/add.go:32) provides detailed log
	//       to avoid duplicate output. Orchestration layer stays thin per CLAUDE.md architecture.

	// Build options (with telemetry for UX measurement)
	opts := &add.ServiceOptions{
		Service:             service,
		DNS:                 dns,
		Backend:             backendWithPort,
		SSO:                 ssoEnabled, // Auto-enabled for services that require it
		SSOProvider:         ssoProvider,
		CustomDirectives:    customDirectives,
		DryRun:              dryRun,
		SkipDNSCheck:        skipDNSCheck,
		SkipBackendCheck:    skipBackendCheck,
		BackupRetentionDays: backupRetentionDays,
		InvocationMethod:    "flag", // Track --add flag vs subcommand usage
	}

	// Execute the add operation
	return add.AddService(rc, opts)
}

// runAddAuthentikEmail configures Authentik email settings using admin API.
func runAddAuthentikEmail(rc *eos_io.RuntimeContext, dryRun bool, testEmail string) error {
	if err := hecate.ConfigureAuthentikEmail(rc, &hecate.AuthentikEmailConfig{
		DryRun:    dryRun,
		TestEmail: testEmail,
	}); err != nil {
		return fmt.Errorf("failed to configure Authentik email settings: %w", err)
	}
	return nil
}

// runRemoveServiceFromFlag handles removing a service when --remove flag is used
func runRemoveServiceFromFlag(rc *eos_io.RuntimeContext, cmd *cobra.Command, service string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Removing service from Hecate",
		zap.String("service", service))

	// Get dry-run flag (for future implementation)
	_, _ = cmd.Flags().GetBool("dry-run")

	// TODO: Create remove package and implement RemoveService function
	// For now, return not implemented error with clear workaround
	return fmt.Errorf("--remove functionality not yet implemented\n\n"+
		"Workaround: Manually remove service block from /opt/hecate/Caddyfile\n"+
		"Then reload Caddy: docker exec hecate-caddy caddy reload --config /etc/caddy/Caddyfile\n\n"+
		"Service to remove: %s\n"+
		"Look for: # Service: %s", service, service)
}

// runFixServiceFromFlag handles fixing drift/misconfigurations when --fix flag is used
func runFixServiceFromFlag(rc *eos_io.RuntimeContext, cmd *cobra.Command, service string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get dry-run flag
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	logger.Info("Fixing service configuration drift",
		zap.String("service", service),
		zap.Bool("dry_run", dryRun))

	// Build fix options
	opts := &add.FixOptions{
		Service: service,
		DryRun:  dryRun,
	}

	// Execute the fix operation
	return add.FixService(rc, opts)
}

// runRefreshCaddy gracefully reloads Caddy configuration without restarting
// P1 - CRITICAL: Uses graceful reload strategies that preserve TLS certificates
// RATIONALE: Prevents Let's Encrypt rate limiting during debugging/development
// STRATEGY: Admin API (preferred) → Docker exec → Container restart (fallback only)
func runRefreshCaddy(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Refreshing Caddy configuration (zero-downtime graceful reload)")
	logger.Info("Strategy: Admin API (preserves TLS certs) → Docker exec → Container restart (last resort)")

	// Use the shared ReloadCaddy function which implements strategy fallback
	// This will try Admin API first (zero-downtime, preserves certs), then docker exec, then restart
	if err := add.ReloadCaddy(rc, hecate.CaddyfilePath); err != nil {
		return fmt.Errorf("failed to refresh Caddy: %w\n\n"+
			"Troubleshooting:\n"+
			"  1. Check Caddy is running: docker ps | grep caddy\n"+
			"  2. Check Caddy logs: docker logs hecate-caddy\n"+
			"  3. Validate Caddyfile: docker exec hecate-caddy caddy validate --config /etc/caddy/Caddyfile", err)
	}

	logger.Info("✓ Caddy configuration reloaded successfully")
	logger.Info("TLS certificates preserved (no renewal triggered)")

	return nil
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

// runEnableFeature handles enabling features when --enable flag is used
// Delegates to functions defined in hecate_enable.go
func runEnableFeature(rc *eos_io.RuntimeContext, cmd *cobra.Command, feature string) error {
	switch feature {
	case "oauth2-signout":
		return runEnableOAuth2Signout(rc, cmd)
	case "self-enrollment":
		return runEnableSelfEnrollment(rc, cmd)
	case "default-flows":
		return runEnableDefaultFlows(rc, cmd)
	default:
		return fmt.Errorf("unknown feature: %s\n\nAvailable features:\n  - oauth2-signout\n  - self-enrollment\n  - default-flows", feature)
	}
}

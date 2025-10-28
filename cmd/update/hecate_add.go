// cmd/update/hecate_add.go

package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/add"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// addServiceCmd adds a new service to Hecate
var addServiceCmd = &cobra.Command{
	Use:        "add [service]",
	Short:      "Add a new reverse proxy route to Hecate",
	Args:       cobra.ExactArgs(1),
	Deprecated: "Use 'eos update hecate --add [service]' instead. Subcommand syntax will be removed in v2.0 (approximately 6 months).",
	Long: `Add a new service to an existing Hecate installation by modifying the Caddyfile.

This command:
  1. Validates input (DNS, backend, SSO configuration)
  2. Checks DNS resolution and backend connectivity
  3. Backs up the existing Caddyfile
  4. Adds the new route configuration
  5. Validates and reloads Caddy (no restart)
  6. Verifies the new route is working

DEPRECATED: This subcommand syntax is deprecated. Use 'eos update hecate --add [service]' instead.

Examples (DEPRECATED - use flag syntax instead):
  # Basic service without SSO
  eos update hecate add bionicgpt \
    --dns chat.codemonkey.ai \
    --upstream 100.64.0.50:8080

  # PREFERRED FLAG-BASED SYNTAX:
  eos update hecate --add bionicgpt \
    --dns chat.codemonkey.ai \
    --upstream 100.64.0.50:8080`,
	RunE: eos.Wrap(runAddService),
}

func init() {
	// Add as subcommand of updateHecateCmd
	updateHecateCmd.AddCommand(addServiceCmd)

	// Required flags with short aliases for better UX
	addServiceCmd.Flags().StringP("dns", "d", "", "Domain/subdomain for this service (aliases: --domain, --route, --host)")
	addServiceCmd.Flags().StringP("upstream", "u", "", "Backend address (ip:port or hostname:port) (aliases: --backend, --target)")

	// Optional flags
	addServiceCmd.Flags().Bool("sso", false, "Enable SSO for this route")
	addServiceCmd.Flags().String("sso-provider", "authentik", "SSO provider to use (default: authentik)")
	addServiceCmd.Flags().StringSlice("custom-directive", []string{}, "Custom Caddy directives (can specify multiple times)")
	addServiceCmd.Flags().Bool("dry-run", false, "Show what would be changed without applying")
	addServiceCmd.Flags().Bool("skip-dns-check", false, "Skip DNS resolution validation")
	addServiceCmd.Flags().Bool("skip-backend-check", false, "Skip backend connectivity check")
	addServiceCmd.Flags().Bool("allow-insecure-tls", false, "Allow InsecureSkipVerify for TLS connections (INSECURE - use only with self-signed certs)")
	addServiceCmd.Flags().Int("backup-retention-days", 30, "Days to keep old backups (0 = keep forever)")
}

func runAddService(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// DEPRECATION WARNING: Soft deprecation phase (v1.X)
	logger.Warn("DEPRECATED: Subcommand syntax is deprecated and will be removed in v2.0",
		zap.String("current_syntax", "eos update hecate add "+args[0]),
		zap.String("preferred_syntax", "eos update hecate --add "+args[0]),
		zap.String("removal_version", "v2.0.0"),
		zap.String("timeline", "approximately 6 months"))

	// CRITICAL: Detect flag-like args (--force, -f, etc.) to prevent '--' separator bypass
	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}

	// Get service from positional argument
	service := args[0]

	// Parse flags
	dns, _ := cmd.Flags().GetString("dns")
	upstream, _ := cmd.Flags().GetString("upstream")
	sso, _ := cmd.Flags().GetBool("sso")
	ssoProvider, _ := cmd.Flags().GetString("sso-provider")
	customDirectives, _ := cmd.Flags().GetStringSlice("custom-directive")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipDNSCheck, _ := cmd.Flags().GetBool("skip-dns-check")
	skipBackendCheck, _ := cmd.Flags().GetBool("skip-backend-check")
	allowInsecureTLS, _ := cmd.Flags().GetBool("allow-insecure-tls")
	backupRetentionDays, _ := cmd.Flags().GetInt("backup-retention-days")

	// Auto-append default port for known services if port is missing
	// This improves UX by allowing: --upstream 100.71.196.79 instead of --upstream 100.71.196.79:8513
	backendWithPort := add.EnsureBackendHasPort(service, upstream)

	// Build options (with telemetry for UX measurement)
	opts := &add.ServiceOptions{
		Service:             service,
		DNS:                 dns,
		Backend:             backendWithPort,
		SSO:                 sso,
		SSOProvider:         ssoProvider,
		AllowInsecureTLS:    allowInsecureTLS,
		CustomDirectives:    customDirectives,
		DryRun:              dryRun,
		SkipDNSCheck:        skipDNSCheck,
		SkipBackendCheck:    skipBackendCheck,
		BackupRetentionDays: backupRetentionDays,
		InvocationMethod:    "subcommand", // Track --add flag vs subcommand usage
	}

	// Execute the add operation
	return add.AddService(rc, opts)
}

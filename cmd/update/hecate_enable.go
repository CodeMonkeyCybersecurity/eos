// cmd/update/hecate_enable.go - Enable features for Hecate deployment

package update

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// updateHecateEnableCmd represents the "update hecate enable" command
// DEPRECATED: Use flag syntax instead: eos update hecate --enable <feature>
// This subcommand will be removed in Eos v2.0 (approximately Q3 2026)
var updateHecateEnableCmd = &cobra.Command{
	Use:        "enable [feature]",
	Args:       cobra.ExactArgs(1),
	Short:      "Enable features for Hecate deployment",
	Deprecated: "Use 'eos update hecate --enable <feature>' instead. Subcommand will be removed in v2.0.",
	Long: `Enable additional features for an existing Hecate deployment.

⚠️  DEPRECATION NOTICE:
This subcommand syntax is deprecated and will be removed in Eos v2.0 (Q3 2026).

NEW SYNTAX (recommended):
  eos update hecate --enable <feature>

OLD SYNTAX (deprecated, still works):
  eos update hecate enable <feature>

Available features:
  oauth2-signout     - Add /oauth2/sign_out logout handlers to Authentik-protected routes
  self-enrollment    - Enable user self-registration via Authentik enrollment flow
  default-flows      - Deploy opinionated Authentik 2025.10 default flows for an app

The enable command modifies live configuration via APIs (zero-downtime):
  - Uses Caddy Admin API to inject route handlers
  - Uses Authentik API to fetch application metadata
  - No container restarts required
  - Idempotent (safe to run multiple times)

Examples (NEW SYNTAX - RECOMMENDED):
  # Enable logout handlers
  eos update hecate --enable oauth2-signout

  # Enable self-enrollment
  eos update hecate --enable self-enrollment --app bionicgpt --dns chat.example.com

  # Dry run
  eos update hecate --enable oauth2-signout --dry-run`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Show deprecation warning
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Warn("⚠️  DEPRECATION WARNING")
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Warn("")
		logger.Warn("Subcommand syntax 'eos update hecate enable' is deprecated")
		logger.Warn("Will be removed in Eos v2.0 (Q3 2026)")
		logger.Warn("")
		logger.Warn("Use: eos update hecate --enable <feature>")
		logger.Warn("")
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Warn("")

		feature := args[0]

		switch feature {
		case "oauth2-signout":
			return runEnableOAuth2Signout(rc, cmd)
		case "self-enrollment":
			return runEnableSelfEnrollment(rc, cmd)
		default:
			return fmt.Errorf("unknown feature: %s\n\nAvailable features:\n  - oauth2-signout\n  - self-enrollment\n  - default-flows", feature)
		}
	}),
}

func init() {
	// DEPRECATED: Subcommand pattern (eos update hecate enable self-enrollment)
	// NEW: Flag pattern (eos update hecate --enable self-enrollment)
	// Keep subcommand for backwards compatibility, will be removed in v2.0
	updateHecateCmd.AddCommand(updateHecateEnableCmd)

	// Add flags for oauth2-signout
	updateHecateEnableCmd.Flags().String("authentik-host", "hecate-server-1", "Authentik hostname (default: hecate-server-1)")
	updateHecateEnableCmd.Flags().Int("authentik-port", hecate.AuthentikPort, "Authentik port")
	updateHecateEnableCmd.Flags().Bool("dry-run", false, "Show what would be changed without applying")

	// Add flags for self-enrollment
	updateHecateEnableCmd.Flags().String("app", "", "Application name (e.g., bionicgpt) - creates app-specific brand for isolated enrollment")
	updateHecateEnableCmd.Flags().Bool("skip-caddyfile", false, "Skip Caddyfile updates (advanced usage)")
	updateHecateEnableCmd.Flags().Bool("enable-captcha", true, "Enable captcha stage for bot protection (default: true, uses test keys initially)")
	updateHecateEnableCmd.Flags().Bool("disable-captcha", false, "Disable captcha protection (NOT RECOMMENDED for production)")
	updateHecateEnableCmd.Flags().Bool("require-approval", false, "New users inactive until admin approves (default: active immediately)")
}

// runEnableOAuth2Signout enables /oauth2/sign_out logout handlers
func runEnableOAuth2Signout(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	authentikHost, _ := cmd.Flags().GetString("authentik-host")
	authentikPort, _ := cmd.Flags().GetInt("authentik-port")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	logger.Info("Enabling OAuth2 logout handlers",
		zap.String("authentik_host", authentikHost),
		zap.Int("authentik_port", authentikPort),
		zap.Bool("dry_run", dryRun))

	// Build config
	config := &hecate.OAuth2SignoutConfig{
		AuthentikHost: authentikHost,
		AuthentikPort: authentikPort,
		DryRun:        dryRun,
	}

	// Execute enable operation
	if err := hecate.EnableOAuth2Signout(rc, config); err != nil {
		return fmt.Errorf("failed to enable oauth2-signout: %w", err)
	}

	return nil
}

// runEnableSelfEnrollment enables self-enrollment for Hecate applications
func runEnableSelfEnrollment(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	appName, _ := cmd.Flags().GetString("app")
	domain, _ := cmd.Flags().GetString("dns") // Read --dns flag from parent command
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipCaddyfile, _ := cmd.Flags().GetBool("skip-caddyfile")
	enableCaptcha, _ := cmd.Flags().GetBool("enable-captcha")
	disableCaptcha, _ := cmd.Flags().GetBool("disable-captcha")
	requireApproval, _ := cmd.Flags().GetBool("require-approval")

	// Handle CAPTCHA flag logic: default enabled, explicit disable overrides
	if disableCaptcha {
		enableCaptcha = false
		logger.Warn("CAPTCHA protection disabled via --disable-captcha flag")
		logger.Warn("This is NOT RECOMMENDED for production environments")
		logger.Warn("Self-enrollment endpoints without CAPTCHA are vulnerable to bot attacks")
	}

	// Validate app flag
	if appName == "" {
		logger.Warn("--app flag not specified, using 'hecate' as default")
		appName = "hecate"
	}

	logger.Info("Enabling self-enrollment for Hecate",
		zap.String("app", appName),
		zap.Bool("dry_run", dryRun),
		zap.Bool("skip_caddyfile", skipCaddyfile),
		zap.Bool("require_approval", requireApproval))

	// ARCHITECTURE UPDATE (2025-10-31): Self-enrollment is now app-specific via one-brand-per-application
	if appName != "hecate" {
		logger.Info("ARCHITECTURE: App-specific brand isolation enabled")
		logger.Info("Self-enrollment is isolated to THIS application only")
		logger.Info("Each application gets its own Authentik brand for enrollment security")
	}

	// Build config
	config := &hecate.SelfEnrollmentConfig{
		AppName:         appName,
		Domain:          domain, // Pass explicit domain if provided via --dns flag
		DryRun:          dryRun,
		SkipCaddyfile:   skipCaddyfile,
		EnableCaptcha:   enableCaptcha,
		RequireApproval: requireApproval,
	}

	if enableCaptcha {
		logger.Info("Captcha protection will be enabled (using test keys)")
		logger.Info("IMPORTANT: Configure production captcha keys in Authentik UI after enrollment is enabled")
		logger.Info("  Path: Admin → Flows & Stages → Stages → eos-enrollment-captcha → Edit")
	}

	// Execute enable operation
	if err := hecate.EnableSelfEnrollment(rc, config); err != nil {
		return fmt.Errorf("failed to enable self-enrollment: %w", err)
	}

	return nil
}

// runEnableDefaultFlows deploys the opinionated Authentik default flows.
func runEnableDefaultFlows(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	appName, _ := cmd.Flags().GetString("app")
	domain, _ := cmd.Flags().GetString("dns")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	updateExisting, _ := cmd.Flags().GetBool("update-existing")

	if appName == "" {
		appName = hecate.BionicGPTApplicationSlug
		logger.Info("No --app provided, defaulting to", zap.String("app", appName))
	}

	logger.Info("Enabling Authentik default flows",
		zap.String("app", appName),
		zap.String("domain", domain),
		zap.Bool("dry_run", dryRun),
		zap.Bool("replace_existing", updateExisting))

	config := &hecate.DefaultFlowsConfig{
		App:            appName,
		Domain:         domain,
		DryRun:         dryRun,
		UpdateExisting: updateExisting,
	}

	return hecate.EnableDefaultFlows(rc, config)
}

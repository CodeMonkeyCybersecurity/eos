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
var updateHecateEnableCmd = &cobra.Command{
	Use:   "enable [feature]",
	Args:  cobra.ExactArgs(1),
	Short: "Enable features for Hecate deployment",
	Long: `Enable additional features for an existing Hecate deployment.

Available features:
  oauth2-signout     - Add /oauth2/sign_out logout handlers to Authentik-protected routes
  self-enrollment    - Enable user self-registration via Authentik enrollment flow

The enable command modifies live configuration via APIs (zero-downtime):
  - Uses Caddy Admin API to inject route handlers
  - Uses Authentik API to fetch application metadata
  - No container restarts required
  - Idempotent (safe to run multiple times)

Examples:
  # Enable logout handlers (auto-discovers protected routes)
  eos update hecate enable oauth2-signout

  # Enable self-enrollment for users to register
  eos update hecate enable self-enrollment --app bionicgpt

  # Dry run to see what would be changed
  eos update hecate enable oauth2-signout --dry-run
  eos update hecate enable self-enrollment --app bionicgpt --dry-run

  # Specify custom Authentik host
  eos update hecate enable oauth2-signout --authentik-host auth.example.com`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		feature := args[0]

		switch feature {
		case "oauth2-signout":
			return runEnableOAuth2Signout(rc, cmd)
		case "self-enrollment":
			return runEnableSelfEnrollment(rc, cmd)
		default:
			return fmt.Errorf("unknown feature: %s\n\nAvailable features:\n  - oauth2-signout\n  - self-enrollment", feature)
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
	updateHecateEnableCmd.Flags().Bool("enable-captcha", false, "Enable captcha stage for bot protection (uses test keys initially)")
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
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipCaddyfile, _ := cmd.Flags().GetBool("skip-caddyfile")
	enableCaptcha, _ := cmd.Flags().GetBool("enable-captcha")
	requireApproval, _ := cmd.Flags().GetBool("require-approval")

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

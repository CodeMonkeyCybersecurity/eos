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
  oauth2-signout  - Add /oauth2/sign_out logout handlers to Authentik-protected routes

The enable command modifies live configuration via APIs (zero-downtime):
  - Uses Caddy Admin API to inject route handlers
  - Uses Authentik API to fetch application metadata
  - No container restarts required
  - Idempotent (safe to run multiple times)

Examples:
  # Enable logout handlers (auto-discovers protected routes)
  eos update hecate enable oauth2-signout

  # Dry run to see what would be changed
  eos update hecate enable oauth2-signout --dry-run

  # Specify custom Authentik host
  eos update hecate enable oauth2-signout --authentik-host auth.example.com`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		feature := args[0]

		switch feature {
		case "oauth2-signout":
			return runEnableOAuth2Signout(rc, cmd)
		default:
			return fmt.Errorf("unknown feature: %s\n\nAvailable features:\n  - oauth2-signout", feature)
		}
	}),
}

func init() {
	// Add as subcommand to updateHecateCmd
	updateHecateCmd.AddCommand(updateHecateEnableCmd)

	// Add flags for oauth2-signout
	updateHecateEnableCmd.Flags().String("authentik-host", "hecate-server-1", "Authentik hostname (default: hecate-server-1)")
	updateHecateEnableCmd.Flags().Int("authentik-port", hecate.AuthentikPort, "Authentik port")
	updateHecateEnableCmd.Flags().Bool("dry-run", false, "Show what would be changed without applying")
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

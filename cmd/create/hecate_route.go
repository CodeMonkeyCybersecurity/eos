package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var createHecateRouteCmd = &cobra.Command{
	Use:   "route",
	Short: "DEPRECATED: Use 'eos update hecate route --add' instead",
	Long: `DEPRECATED: This command is deprecated and will be removed in Eos v2.0.0.

Please use the unified command instead:
  eos update hecate route --add

This provides a consistent interface for both adding and updating routes.

Examples (NEW way):
  eos update hecate route --add --domain app.example.com --upstream localhost:3000
  eos update hecate route --add --domain api.example.com --upstream localhost:8080 --auth-policy api-users
  eos update hecate route --add  # Interactive mode`,
	Deprecated: "Use 'eos update hecate route --add' instead",
	RunE:       eos_cli.Wrap(runCreateHecateRoute),
}

func init() {
	// Add route subcommand to the existing Hecate command
	CreateHecateCmd.AddCommand(createHecateRouteCmd)

	// Define flags (kept for backwards compatibility)
	createHecateRouteCmd.Flags().String("domain", "", "Domain name for the route (prompted if not provided)")
	createHecateRouteCmd.Flags().String("upstream", "", "Upstream backend address (prompted if not provided)")
	createHecateRouteCmd.Flags().Bool("require-auth", false, "Require Authentik SSO authentication")
	createHecateRouteCmd.Flags().StringSlice("headers", []string{}, "Custom headers in key=value format")
}

func runCreateHecateRoute(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Show deprecation warning
	logger.Warn("DEPRECATED: 'eos create hecate route' is deprecated")
	logger.Info("terminal prompt: Please use 'eos update hecate route --add' instead")
	logger.Info("terminal prompt: This command will be removed in Eos v2.0.0 (approximately 6 months)")
	logger.Info("terminal prompt: ")

	// Parse flags (only the ones we still support)
	domain, _ := cmd.Flags().GetString("domain")
	upstream, _ := cmd.Flags().GetString("upstream")
	requireAuth, _ := cmd.Flags().GetBool("require-auth")
	headers, _ := cmd.Flags().GetStringSlice("headers")

	// Use the shared helper from pkg/hecate (same implementation as update --add)
	opts := &hecate.RouteCreationOptions{
		Domain:      domain,
		Upstream:    upstream,
		RequireAuth: requireAuth,
		Headers:     headers,
		Force:       false, // Always prompt for confirmation
	}

	return hecate.CreateRouteInteractive(rc, opts)
}

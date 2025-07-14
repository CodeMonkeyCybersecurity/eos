package delete

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var deleteHecateRouteCmd = &cobra.Command{
	Use:   "hecate-route",
	Short: "Delete a Hecate reverse proxy route",
	Long: `Delete a reverse proxy route from Hecate.

This command removes a route configuration from the reverse proxy. The associated
DNS records may also be removed if they were managed by Hecate.

Examples:
  eos delete hecate-route --domain app.example.com
  eos delete hecate-route --domain api.example.com --force
  eos delete hecate-route --domain old.example.com --keep-dns`,
	RunE: eos_cli.Wrap(runDeleteHecateRoute),
}

func init() {
	DeleteCmd.AddCommand(deleteHecateRouteCmd)

	// Define flags
	deleteHecateRouteCmd.Flags().String("domain", "", "Domain name of the route to delete (prompted if not provided)")
	deleteHecateRouteCmd.Flags().Bool("force", false, "Force deletion without confirmation")
	deleteHecateRouteCmd.Flags().Bool("keep-dns", false, "Keep DNS records (do not delete)")
	deleteHecateRouteCmd.Flags().Bool("backup", true, "Create backup before deletion")
}

func runDeleteHecateRoute(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	domain, _ := cmd.Flags().GetString("domain")
	force, _ := cmd.Flags().GetBool("force")
	keepDNS, _ := cmd.Flags().GetBool("keep-dns")
	createBackup, _ := cmd.Flags().GetBool("backup")

	// Prompt for domain if not provided
	if domain == "" {
		logger.Info("Domain not provided via flag, prompting user")
		logger.Info("terminal prompt: Please enter the domain name of the route to delete")

		input, err := eos_io.PromptInput(rc, "Domain", "Enter domain name")
		if err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		domain = input
	}

	logger.Info("Preparing to delete Hecate route",
		zap.String("domain", domain))

	// Get route details before deletion
	// TODO: Get config from context or parameter
	config := &hecate.HecateConfig{} // Placeholder
	route, err := hecate.GetRoute(rc, config, domain)
	if err != nil {
		return fmt.Errorf("failed to get route: %w", err)
	}

	// Display route information
	logger.Info("terminal prompt: Route to be deleted:")
	logger.Info("terminal prompt: " + strings.Repeat("-", 60))
	logger.Info(fmt.Sprintf("terminal prompt: Domain: %s", route.Domain))
	logger.Info(fmt.Sprintf("terminal prompt: Upstream: %s", route.Upstream.URL))
	if route.AuthPolicy != nil {
		logger.Info(fmt.Sprintf("terminal prompt: Auth Policy: %s", route.AuthPolicy.Name))
	}
	logger.Info(fmt.Sprintf("terminal prompt: Created: %s", route.CreatedAt.Format("2006-01-02 15:04:05")))
	logger.Info("terminal prompt: " + strings.Repeat("-", 60))

	// Confirm deletion unless force flag is set
	if !force {
		logger.Info("terminal prompt: ⚠️  WARNING: This action cannot be undone!")
		logger.Info("terminal prompt: Are you sure you want to delete this route? (y/N)")
		
		confirm, err := eos_io.PromptInput(rc, "Confirm", "Delete route? (y/N)")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if !strings.HasPrefix(strings.ToLower(confirm), "y") {
			logger.Info("terminal prompt: Deletion cancelled")
			return nil
		}
	}

	// Create backup if requested
	var backupPath string
	if createBackup {
		logger.Info("Creating backup of route configuration",
			zap.String("domain", domain))

		err = hecate.BackupRoute(rc, config, route)
		if err != nil {
			logger.Warn("Failed to create backup",
				zap.Error(err))
			// Non-fatal - continue with deletion
		} else {
			backupPath = "backup_created" // TODO: Get actual path from BackupRoute
			logger.Info("terminal prompt: Backup created",
				zap.String("path", backupPath))
		}
	}

	// Delete the route
	deleteOptions := &hecate.DeleteOptions{
		RemoveDNS: !keepDNS,
	}

	if err := hecate.DeleteRouteWithOptions(rc, config, domain, deleteOptions); err != nil {
		return fmt.Errorf("failed to delete route: %w", err)
	}

	logger.Info("Route deleted successfully",
		zap.String("domain", domain))

	// Display success message
	logger.Info("terminal prompt: ✓ Route deleted successfully!")
	logger.Info("terminal prompt: Domain", zap.String("value", domain))
	
	if keepDNS {
		logger.Info("terminal prompt: DNS records were preserved as requested")
		logger.Info("terminal prompt: You may need to update DNS records manually")
	} else {
		logger.Info("terminal prompt: Associated DNS records have been removed")
	}

	if createBackup && backupPath != "" {
		logger.Info("terminal prompt: Route configuration backed up to:", zap.String("path", backupPath))
		logger.Info("terminal prompt: You can restore this route using: eos create hecate-route --from-backup " + backupPath)
	}

	// Check if there are any other routes using the same upstream
	routes, err := hecate.ListRoutes(rc, config)
	if err == nil {
		var sameUpstreamCount int
		for _, r := range routes {
			if r.Upstream.URL == route.Upstream.URL {
				sameUpstreamCount++
			}
		}
		if sameUpstreamCount == 0 {
			logger.Info("terminal prompt: Note: No other routes are using upstream " + route.Upstream.URL)
			logger.Info("terminal prompt: You may want to check if the upstream service is still needed")
		}
	}

	return nil
}
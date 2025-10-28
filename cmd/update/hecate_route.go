package update

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

var updateHecateRouteCmd = &cobra.Command{
	Use:   "route",
	Short: "Add or update Hecate route configuration",
	Long: `Add a new route or update an existing reverse proxy route configuration in Hecate.

Use the --add flag to create a new route. Without --add, this command updates an existing route.

This command allows you to:
  - Create new routes with --add flag
  - Modify upstream backend addresses
  - Update authentication policies
  - Add or remove custom headers
  - Configure health check settings

Examples:
  # Add a new route
  eos update hecate route --add --domain app.example.com --upstream localhost:3000
  eos update hecate route --add --domain api.example.com --upstream localhost:8080 --auth-policy api-users
  eos update hecate route --add  # Interactive mode (prompts for inputs)

  # Update an existing route
  eos update hecate route --domain app.example.com --upstream localhost:3001
  eos update hecate route --domain api.example.com --auth-policy new-api-policy
  eos update hecate route --domain secure.example.com --add-header "X-Custom-Header=value"
  eos update hecate route --domain app.example.com --health-check-path /health`,
	RunE: eos_cli.Wrap(runUpdateHecateRoute),
}

func init() {
	UpdateCmd.AddCommand(updateHecateRouteCmd)

	// Define flags
	updateHecateRouteCmd.Flags().Bool("add", false, "Create a new route instead of updating an existing one")
	updateHecateRouteCmd.Flags().String("domain", "", "Domain name of the route (prompted if not provided)")
	updateHecateRouteCmd.Flags().String("upstream", "", "Upstream backend address (prompted if not provided with --add)")
	updateHecateRouteCmd.Flags().Bool("require-auth", false, "Require Authentik SSO authentication")
	updateHecateRouteCmd.Flags().StringSlice("add-header", []string{}, "Add custom headers in key=value format")
	updateHecateRouteCmd.Flags().StringSlice("remove-header", []string{}, "Remove custom headers by key")
	updateHecateRouteCmd.Flags().String("auth-policy", "", "Authentication policy name (for update only)")
	updateHecateRouteCmd.Flags().Bool("disable-auth", false, "Remove authentication requirement (for update only)")
	updateHecateRouteCmd.Flags().Bool("force", false, "Skip confirmation prompt")
}

func runUpdateHecateRoute(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	addMode, _ := cmd.Flags().GetBool("add")
	domain, _ := cmd.Flags().GetString("domain")
	upstream, _ := cmd.Flags().GetString("upstream")
	requireAuth, _ := cmd.Flags().GetBool("require-auth")
	addHeaders, _ := cmd.Flags().GetStringSlice("add-header")
	force, _ := cmd.Flags().GetBool("force")

	// Branch on --add flag: create new route vs update existing
	if addMode {
		return runCreateNewRoute(rc, domain, upstream, requireAuth, addHeaders, force)
	}

	// UPDATE EXISTING ROUTE - parse additional update-specific flags
	authPolicy, _ := cmd.Flags().GetString("auth-policy")
	removeHeaders, _ := cmd.Flags().GetStringSlice("remove-header")
	disableAuth, _ := cmd.Flags().GetBool("disable-auth")

	// UPDATE EXISTING ROUTE LOGIC
	// Prompt for domain if not provided
	if domain == "" {
		logger.Info("Domain not provided via flag, prompting user")
		logger.Info("terminal prompt: Please enter the domain name of the route to update")

		input, err := eos_io.PromptInput(rc, "Domain", "Enter domain name")
		if err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		domain = input
	}

	logger.Info("Updating Hecate route",
		zap.String("domain", domain))

	// Build updates map
	updates := make(map[string]interface{})

	if upstream != "" {
		updates["upstream"] = upstream
	}

	if authPolicy != "" {
		updates["auth_policy"] = authPolicy
	}

	if disableAuth {
		updates["auth_policy"] = ""
	}

	// Handle headers
	if len(addHeaders) > 0 || len(removeHeaders) > 0 {
		// Get current route to modify headers
		config, err := hecate.LoadRouteConfig(rc)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		currentRoute, err := hecate.GetRoute(rc, config, domain)
		if err != nil {
			return fmt.Errorf("failed to get current route: %w", err)
		}

		headers := make(map[string]string)
		// Copy existing headers
		for k, v := range currentRoute.Headers {
			headers[k] = v
		}

		// Add new headers
		for _, header := range addHeaders {
			parts := strings.SplitN(header, "=", 2)
			if len(parts) != 2 {
				logger.Warn("Invalid header format, skipping",
					zap.String("header", header))
				continue
			}
			headers[parts[0]] = parts[1]
		}

		// Remove headers
		for _, key := range removeHeaders {
			delete(headers, key)
		}

		updates["headers"] = headers
	}

	// Check if any updates were specified
	if len(updates) == 0 {
		return fmt.Errorf("no updates specified")
	}

	// Show what will be updated
	logger.Info("terminal prompt: The following updates will be applied:")
	for key, value := range updates {
		logger.Info(fmt.Sprintf("terminal prompt:   %s: %v", key, value))
	}

	// Confirm unless force flag is set
	if !force {
		logger.Info("terminal prompt: Do you want to proceed with these updates? (y/N)")

		confirm, err := eos_io.PromptInput(rc, "Confirm", "Proceed with updates? (y/N)")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if !strings.HasPrefix(strings.ToLower(confirm), "y") {
			logger.Info("terminal prompt: Update cancelled")
			return nil
		}
	}

	// Apply updates
	config, err := hecate.LoadRouteConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Convert updates map to Route object
	updatedRoute := &hecate.Route{
		Domain: domain,
	}

	if upstream, ok := updates["upstream"]; ok {
		updatedRoute.Upstream = &hecate.Upstream{URL: upstream.(string)}
	}

	if authPolicy, ok := updates["auth_policy"]; ok {
		if authPolicy.(string) != "" {
			updatedRoute.AuthPolicy = &hecate.AuthPolicy{Name: authPolicy.(string)}
		}
	}

	if headers, ok := updates["headers"]; ok {
		updatedRoute.Headers = headers.(map[string]string)
	}

	if err := hecate.UpdateRoute(rc, config, domain, updatedRoute); err != nil {
		return fmt.Errorf("failed to update route: %w", err)
	}

	logger.Info("Route updated successfully",
		zap.String("domain", domain))

	// Display success message
	logger.Info("terminal prompt: Route updated successfully!")
	logger.Info("terminal prompt: Domain", zap.String("value", domain))

	if upstream != "" {
		logger.Info("terminal prompt: New Upstream", zap.String("value", upstream))
	}
	if authPolicy != "" {
		logger.Info("terminal prompt: New Auth Policy", zap.String("value", authPolicy))
	}
	if disableAuth {
		logger.Info("terminal prompt: Authentication disabled - route is now publicly accessible")
	}

	// Verify the route is still working
	logger.Info("terminal prompt: Verifying route functionality...")

	// Get the route for health check
	route, err := hecate.GetRoute(rc, config, domain)
	if err != nil {
		logger.Warn("Failed to get route for health check", zap.Error(err))
	} else {
		status, err := hecate.GetRouteHealth(rc, route)
		if err != nil {
			logger.Warn("Failed to verify route health",
				zap.Error(err))
		} else if status != nil {
			if status.Health == hecate.RouteHealthHealthy {
				logger.Info("terminal prompt: ✓ Route is healthy and responding normally")
			} else {
				logger.Warn("terminal prompt: ⚠ Route may be experiencing issues",
					zap.String("error", status.Message))
			}
		}
	}

	return nil
}

// runCreateNewRoute handles the --add flag to create a new route
// This is now a thin wrapper around the shared pkg/hecate/CreateRouteInteractive
func runCreateNewRoute(rc *eos_io.RuntimeContext, domain, upstream string, requireAuth bool, headers []string, force bool) error {
	opts := &hecate.RouteCreationOptions{
		Domain:      domain,
		Upstream:    upstream,
		RequireAuth: requireAuth,
		Headers:     headers,
		Force:       force,
	}

	return hecate.CreateRouteInteractive(rc, opts)
}

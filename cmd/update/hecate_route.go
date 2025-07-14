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
	Use:   "hecate-route",
	Short: "Update an existing Hecate route configuration",
	Long: `Update an existing reverse proxy route configuration in Hecate.

This command allows you to modify various aspects of a route including its
upstream backend, authentication policy, headers, and health check settings.

Examples:
  eos update hecate-route --domain app.example.com --upstream localhost:3001
  eos update hecate-route --domain api.example.com --auth-policy new-api-policy
  eos update hecate-route --domain secure.example.com --add-header "X-Custom-Header=value"
  eos update hecate-route --domain app.example.com --health-check-path /health`,
	RunE: eos_cli.Wrap(runUpdateHecateRoute),
}

func init() {
	UpdateCmd.AddCommand(updateHecateRouteCmd)

	// Define flags
	updateHecateRouteCmd.Flags().String("domain", "", "Domain name of the route to update (prompted if not provided)")
	updateHecateRouteCmd.Flags().String("upstream", "", "New upstream backend address")
	updateHecateRouteCmd.Flags().String("auth-policy", "", "New authentication policy name")
	updateHecateRouteCmd.Flags().StringSlice("add-header", []string{}, "Add custom headers in key=value format")
	updateHecateRouteCmd.Flags().StringSlice("remove-header", []string{}, "Remove custom headers by key")
	updateHecateRouteCmd.Flags().String("health-check-path", "", "New health check endpoint path")
	updateHecateRouteCmd.Flags().String("health-check-interval", "", "New health check interval")
	updateHecateRouteCmd.Flags().Bool("disable-auth", false, "Remove authentication requirement")
	updateHecateRouteCmd.Flags().Bool("enable-mfa", false, "Enable MFA requirement for authentication")
	updateHecateRouteCmd.Flags().Bool("force", false, "Force update without confirmation")
}

func runUpdateHecateRoute(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	domain, _ := cmd.Flags().GetString("domain")
	upstream, _ := cmd.Flags().GetString("upstream")
	authPolicy, _ := cmd.Flags().GetString("auth-policy")
	addHeaders, _ := cmd.Flags().GetStringSlice("add-header")
	removeHeaders, _ := cmd.Flags().GetStringSlice("remove-header")
	healthCheckPath, _ := cmd.Flags().GetString("health-check-path")
	healthCheckInterval, _ := cmd.Flags().GetString("health-check-interval")
	disableAuth, _ := cmd.Flags().GetBool("disable-auth")
	force, _ := cmd.Flags().GetBool("force")

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

	// Handle health check updates
	if healthCheckPath != "" || healthCheckInterval != "" {
		healthCheckUpdates := make(map[string]interface{})
		if healthCheckPath != "" {
			healthCheckUpdates["path"] = healthCheckPath
		}
		if healthCheckInterval != "" {
			healthCheckUpdates["interval"] = healthCheckInterval
		}
		updates["health_check"] = healthCheckUpdates
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
package list

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var listHecateRoutesCmd = &cobra.Command{
	Use:   "hecate-routes",
	Short: "List all configured Hecate reverse proxy routes",
	Long: `List all configured reverse proxy routes in Hecate.

This command displays all routes configured in the Hecate reverse proxy,
including their domains, upstream backends, authentication policies, and health status.

Examples:
  eos list hecate-routes                    # List all routes
  eos list hecate-routes --format json      # Output in JSON format
  eos list hecate-routes --domain-filter example.com  # Filter by domain
  eos list hecate-routes --health-only      # Show only health status`,
	RunE: eos_cli.Wrap(runListHecateRoutes),
}

func init() {
	ListCmd.AddCommand(listHecateRoutesCmd)

	// Define flags
	listHecateRoutesCmd.Flags().String("format", "table", "Output format (table, json, yaml)")
	listHecateRoutesCmd.Flags().String("domain-filter", "", "Filter routes by domain (supports wildcards)")
	listHecateRoutesCmd.Flags().Bool("health-only", false, "Show only health status information")
	listHecateRoutesCmd.Flags().Bool("verbose", false, "Show detailed route information")
}

func runListHecateRoutes(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	format, _ := cmd.Flags().GetString("format")
	domainFilter, _ := cmd.Flags().GetString("domain-filter")
	healthOnly, _ := cmd.Flags().GetBool("health-only")
	verbose, _ := cmd.Flags().GetBool("verbose")

	logger.Info("Listing Hecate routes",
		zap.String("format", format),
		zap.String("domain_filter", domainFilter),
		zap.Bool("health_only", healthOnly))

	// Get routes from Hecate
	// Load Hecate configuration
	config, err := hecate.LoadRouteConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load Hecate config: %w", err)
	}

	routes, err := hecate.ListRoutes(rc, config)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	// Apply domain filter if specified
	if domainFilter != "" {
		filtered := []*hecate.Route{}
		for _, route := range routes {
			if matchesDomainFilter(route.Domain, domainFilter) {
				filtered = append(filtered, route)
			}
		}
		routes = filtered
	}

	// Get health status if requested
	var routeStatuses map[string]*hecate.RouteStatus
	if healthOnly || verbose {
		routeStatuses, err = hecate.GetRoutesHealth(rc, config)
		if err != nil {
			logger.Warn("Failed to get routes health status",
				zap.Error(err))
			// Non-fatal - continue without health info
		}
	}

	// Display results based on format
	switch format {
	case "json":
		return displayRoutesJSON(rc, routes, routeStatuses)
	case "yaml":
		return displayRoutesYAML(rc, routes, routeStatuses)
	default:
		return displayRoutesTable(rc, routes, routeStatuses, healthOnly, verbose)
	}
}

func displayRoutesTable(rc *eos_io.RuntimeContext, routes []*hecate.Route, statuses map[string]*hecate.RouteStatus, healthOnly, verbose bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	if len(routes) == 0 {
		logger.Info("terminal prompt: No routes configured")
		return nil
	}

	logger.Info("terminal prompt: Hecate Routes")
	logger.Info("terminal prompt: " + strings.Repeat("=", 80))

	if healthOnly {
		// Health-focused display
		logger.Info("terminal prompt: Domain                          Status    Response Time    Last Check")
		logger.Info("terminal prompt: " + strings.Repeat("-", 80))

		for _, route := range routes {
			status := statuses[route.Domain]
			if status == nil {
				logger.Info(fmt.Sprintf("terminal prompt: %-30s  %-8s  %-15s  %s",
					route.Domain, "Unknown", "-", "-"))
				continue
			}

			statusText := "Healthy"
			if status.Health != hecate.RouteHealthHealthy {
				statusText = "Unhealthy"
			}

			logger.Info(fmt.Sprintf("terminal prompt: %-30s  %-8s  %-15s  %s",
				route.Domain, statusText, "N/A", status.LastChecked.Format("15:04:05")))

			if status.Health != hecate.RouteHealthHealthy && status.Message != "" {
				logger.Info(fmt.Sprintf("terminal prompt:   Error: %s", status.Message))
			}
		}
	} else if verbose {
		// Detailed display
		for i, route := range routes {
			if i > 0 {
				logger.Info("terminal prompt: " + strings.Repeat("-", 80))
			}

			logger.Info(fmt.Sprintf("terminal prompt: Domain: %s", route.Domain))
			logger.Info(fmt.Sprintf("terminal prompt: Upstream: %s", route.Upstream.URL))

			if route.AuthPolicy != nil {
				logger.Info(fmt.Sprintf("terminal prompt: Auth Policy: %s", route.AuthPolicy.Name))
			}

			// TODO: Add middleware field to Route type if needed
			// if len(route.Middleware) > 0 {
			//	logger.Info(fmt.Sprintf("terminal prompt: Middleware: %s", strings.Join(route.Middleware, ", ")))
			// }

			if len(route.Headers) > 0 {
				logger.Info("terminal prompt: Custom Headers:")
				for k, v := range route.Headers {
					logger.Info(fmt.Sprintf("terminal prompt:   %s: %s", k, v))
				}
			}

			if route.TLS != nil {
				logger.Info("terminal prompt: TLS Configuration:")
				logger.Info(fmt.Sprintf("terminal prompt:   Enabled: %v", route.TLS.Enabled))
				logger.Info(fmt.Sprintf("terminal prompt:   Min Version: %s", route.TLS.MinVersion))
			}

			if route.HealthCheck != nil {
				logger.Info("terminal prompt: Health Check:")
				logger.Info(fmt.Sprintf("terminal prompt:   Path: %s", route.HealthCheck.Path))
				logger.Info(fmt.Sprintf("terminal prompt:   Interval: %s", route.HealthCheck.Interval))
			}

			// Add health status if available
			if status := statuses[route.Domain]; status != nil {
				logger.Info("terminal prompt: Current Status:")
				if status.Health == hecate.RouteHealthHealthy {
					logger.Info("terminal prompt:   ✓ Healthy")
				} else {
					logger.Info(fmt.Sprintf("terminal prompt:   ✗ Unhealthy: %s", status.Message))
				}
			}

			logger.Info(fmt.Sprintf("terminal prompt: Created: %s", route.CreatedAt.Format("2006-01-02 15:04:05")))
			logger.Info(fmt.Sprintf("terminal prompt: Updated: %s", route.UpdatedAt.Format("2006-01-02 15:04:05")))
		}
	} else {
		// Simple table display
		logger.Info("terminal prompt: Domain                          Upstream                     Auth Policy")
		logger.Info("terminal prompt: " + strings.Repeat("-", 80))

		for _, route := range routes {
			authPolicyName := "-"
			if route.AuthPolicy != nil {
				authPolicyName = route.AuthPolicy.Name
			}

			logger.Info(fmt.Sprintf("terminal prompt: %-30s  %-25s  %s",
				route.Domain, route.Upstream.URL, authPolicyName))
		}
	}

	logger.Info("terminal prompt: " + strings.Repeat("=", 80))
	logger.Info(fmt.Sprintf("terminal prompt: Total routes: %d", len(routes)))

	return nil
}

func displayRoutesJSON(rc *eos_io.RuntimeContext, routes []*hecate.Route, statuses map[string]*hecate.RouteStatus) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build output structure
	output := struct {
		Routes   []*hecate.Route                    `json:"routes"`
		Statuses map[string]*hecate.RouteStatus     `json:"statuses,omitempty"`
		Count    int                                `json:"count"`
	}{
		Routes:   routes,
		Statuses: statuses,
		Count:    len(routes),
	}

	// Marshal to JSON
	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal routes to JSON: %w", err)
	}

	logger.Info("terminal prompt: " + string(jsonBytes))
	return nil
}

func displayRoutesYAML(rc *eos_io.RuntimeContext, routes []*hecate.Route, statuses map[string]*hecate.RouteStatus) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build output structure
	output := struct {
		Routes   []*hecate.Route                    `yaml:"routes"`
		Statuses map[string]*hecate.RouteStatus     `yaml:"statuses,omitempty"`
		Count    int                                `yaml:"count"`
	}{
		Routes:   routes,
		Statuses: statuses,
		Count:    len(routes),
	}

	// Marshal to YAML
	yamlBytes, err := yaml.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal routes to YAML: %w", err)
	}

	logger.Info("terminal prompt: " + string(yamlBytes))
	return nil
}

func matchesDomainFilter(domain, filter string) bool {
	// Simple wildcard matching
	if strings.Contains(filter, "*") {
		// Convert wildcard to regex pattern
		pattern := strings.ReplaceAll(filter, ".", "\\.")
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		matched, _ := regexp.MatchString("^"+pattern+"$", domain)
		return matched
	}
	// Substring match
	return strings.Contains(domain, filter)
}
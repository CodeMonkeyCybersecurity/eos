package read

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var readHecateRouteCmd = &cobra.Command{
	Use:   "hecate-route",
	Short: "Read details of a specific Hecate route",
	Long: `Read detailed information about a specific reverse proxy route in Hecate.

This command retrieves comprehensive information about a route including its
configuration, authentication settings, health status, and current metrics.

Examples:
  eos read hecate-route --domain app.example.com
  eos read hecate-route --domain api.example.com --format json
  eos read hecate-route --domain secure.example.com --show-metrics`,
	RunE: eos_cli.Wrap(runReadHecateRoute),
}

func init() {
	ReadCmd.AddCommand(readHecateRouteCmd)

	// Define flags
	readHecateRouteCmd.Flags().String("domain", "", "Domain name of the route to read (prompted if not provided)")
	readHecateRouteCmd.Flags().String("format", "table", "Output format (table, json, yaml)")
	readHecateRouteCmd.Flags().Bool("show-metrics", false, "Include performance metrics")
	readHecateRouteCmd.Flags().Bool("show-config", true, "Show route configuration")
	readHecateRouteCmd.Flags().Bool("test-connection", false, "Test connection to the route")
}

func runReadHecateRoute(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	domain, _ := cmd.Flags().GetString("domain")
	format, _ := cmd.Flags().GetString("format")
	showMetrics, _ := cmd.Flags().GetBool("show-metrics")
	showConfig, _ := cmd.Flags().GetBool("show-config")
	testConnection, _ := cmd.Flags().GetBool("test-connection")

	// Prompt for domain if not provided
	if domain == "" {
		logger.Info("Domain not provided via flag, prompting user")
		logger.Info("terminal prompt: Please enter the domain name of the route to read")

		input, err := eos_io.PromptInput(rc, "Domain", "Enter domain name")
		if err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		domain = input
	}

	logger.Info("Reading Hecate route details",
		zap.String("domain", domain),
		zap.String("format", format))

	// Get route details
	// TODO: Get config from context or parameter
	config := &hecate.HecateConfig{} // Placeholder
	route, err := hecate.GetRoute(rc, config, domain)
	if err != nil {
		return fmt.Errorf("failed to get route: %w", err)
	}

	// Get health status
	status, err := hecate.GetRouteHealth(rc, route)
	if err != nil {
		logger.Warn("Failed to get route health status",
			zap.Error(err))
		// Non-fatal - continue without health info
	}

	// Get metrics if requested
	var metrics *hecate.RouteMetrics
	if showMetrics {
		metrics, err = hecate.GetRouteMetrics(rc, config, domain)
		if err != nil {
			logger.Warn("Failed to get route metrics",
				zap.Error(err))
			// Non-fatal - continue without metrics
		}
	}

	// Test connection if requested
	var connectionTest *hecate.ConnectionTestResult
	if testConnection {
		logger.Info("Testing connection to route",
			zap.String("domain", domain))
		connectionTest, err = hecate.TestRouteConnection(rc, route)
		if err != nil {
			logger.Warn("Failed to test route connection",
				zap.Error(err))
			// Non-fatal - continue without test results
		}
	}

	// Display results based on format
	switch format {
	case "json":
		return displayRouteJSON(rc, route, status, metrics, connectionTest)
	case "yaml":
		return displayRouteYAML(rc, route, status, metrics, connectionTest)
	default:
		return displayRouteTable(rc, route, status, metrics, connectionTest, showConfig)
	}
}

func displayRouteTable(rc *eos_io.RuntimeContext, route *hecate.Route, status *hecate.RouteStatus,
	metrics *hecate.RouteMetrics, connectionTest *hecate.ConnectionTestResult, showConfig bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: Hecate Route Details")
	logger.Info("terminal prompt: " + strings.Repeat("=", 80))

	// Basic information
	logger.Info(fmt.Sprintf("terminal prompt: Domain: %s", route.Domain))
	logger.Info(fmt.Sprintf("terminal prompt: Upstream: %s", route.Upstream.URL))
	logger.Info(fmt.Sprintf("terminal prompt: Created: %s", route.CreatedAt.Format("2006-01-02 15:04:05")))
	logger.Info(fmt.Sprintf("terminal prompt: Updated: %s", route.UpdatedAt.Format("2006-01-02 15:04:05")))

	// Configuration details
	if showConfig {
		logger.Info("terminal prompt: " + strings.Repeat("-", 80))
		logger.Info("terminal prompt: Configuration:")

		if route.AuthPolicy != nil {
			logger.Info(fmt.Sprintf("terminal prompt:   Auth Policy: %s", route.AuthPolicy.Name))
		} else {
			logger.Info("terminal prompt:   Auth Policy: None (public access)")
		}

		// TODO: Add middleware field to Route type if needed
		// if len(route.Middleware) > 0 {
		//	logger.Info(fmt.Sprintf("terminal prompt:   Middleware: %s", strings.Join(route.Middleware, ", ")))
		// }

		if len(route.Headers) > 0 {
			logger.Info("terminal prompt:   Custom Headers:")
			for k, v := range route.Headers {
				logger.Info(fmt.Sprintf("terminal prompt:     %s: %s", k, v))
			}
		}

		if route.TLS != nil {
			logger.Info("terminal prompt:   TLS Configuration:")
			logger.Info(fmt.Sprintf("terminal prompt:     Enabled: %v", route.TLS.Enabled))
			logger.Info(fmt.Sprintf("terminal prompt:     Min Version: %s", route.TLS.MinVersion))
			if route.TLS.CertFile != "" {
				logger.Info(fmt.Sprintf("terminal prompt:     Certificate: %s", route.TLS.CertFile))
			}
			if route.TLS.MinVersion != "" {
				logger.Info(fmt.Sprintf("terminal prompt:     Min TLS Version: %s", route.TLS.MinVersion))
			}
		}

		if route.HealthCheck != nil {
			logger.Info("terminal prompt:   Health Check:")
			logger.Info(fmt.Sprintf("terminal prompt:     Path: %s", route.HealthCheck.Path))
			logger.Info(fmt.Sprintf("terminal prompt:     Interval: %s", route.HealthCheck.Interval))
			logger.Info(fmt.Sprintf("terminal prompt:     Timeout: %s", route.HealthCheck.Timeout))
			logger.Info(fmt.Sprintf("terminal prompt:     Failure Threshold: %d", route.HealthCheck.FailureThreshold))
			logger.Info(fmt.Sprintf("terminal prompt:     Success Threshold: %d", route.HealthCheck.SuccessThreshold))
		}
	}

	// Health status
	if status != nil {
		logger.Info("terminal prompt: " + strings.Repeat("-", 80))
		logger.Info("terminal prompt: Health Status:")
		if status.Health == hecate.RouteHealthHealthy {
			logger.Info("terminal prompt:   ✓ Status: Healthy")
			logger.Info("terminal prompt:   Response Time: N/A")
		} else {
			logger.Info("terminal prompt:   ✗ Status: Unhealthy")
			if status.Message != "" {
				logger.Info("terminal prompt:   Error: " + status.Message)
			}
		}
		logger.Info("terminal prompt:   Last Check: " + status.LastChecked.Format("2006-01-02 15:04:05"))
	}

	// Metrics
	if metrics != nil {
		logger.Info("terminal prompt: " + strings.Repeat("-", 80))
		logger.Info("terminal prompt: Performance Metrics (last 24h):")
		logger.Info(fmt.Sprintf("terminal prompt:   Total Requests: %d", metrics.RequestCount))
		logger.Info(fmt.Sprintf("terminal prompt:   Error Count: %d", metrics.ErrorCount))
		logger.Info(fmt.Sprintf("terminal prompt:   Average Response Time: %s", metrics.AverageLatency))
		logger.Info(fmt.Sprintf("terminal prompt:   P95 Response Time: %s", metrics.P95Latency))
		logger.Info(fmt.Sprintf("terminal prompt:   P99 Response Time: %s", metrics.P99Latency))
		logger.Info(fmt.Sprintf("terminal prompt:   Bytes Transferred: %d", metrics.BytesTransferred))
	}

	// Connection test results
	if connectionTest != nil {
		logger.Info("terminal prompt: " + strings.Repeat("-", 80))
		logger.Info("terminal prompt: Connection Test Results:")
		if connectionTest.Success {
			logger.Info("terminal prompt:   ✓ Connection Successful")
			logger.Info(fmt.Sprintf("terminal prompt:   Response Code: %d", connectionTest.StatusCode))
			logger.Info(fmt.Sprintf("terminal prompt:   Response Time: %s", connectionTest.ResponseTime))
			if connectionTest.SSL != nil {
				logger.Info(fmt.Sprintf("terminal prompt:   SSL Valid: %v", connectionTest.SSL.Valid))
				logger.Info(fmt.Sprintf("terminal prompt:   Certificate Valid Until: %s",
					connectionTest.SSL.NotAfter.Format("2006-01-02")))
			}
		} else {
			logger.Info("terminal prompt:   ✗ Connection Failed")
			logger.Info("terminal prompt:   Error: " + connectionTest.Error)
		}
	}

	logger.Info("terminal prompt: " + strings.Repeat("=", 80))

	return nil
}

func displayRouteJSON(rc *eos_io.RuntimeContext, route *hecate.Route, status *hecate.RouteStatus,
	metrics *hecate.RouteMetrics, connectionTest *hecate.ConnectionTestResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build output structure
	output := struct {
		Route          *hecate.Route                `json:"route"`
		Status         *hecate.RouteStatus          `json:"status,omitempty"`
		Metrics        *hecate.RouteMetrics         `json:"metrics,omitempty"`
		ConnectionTest *hecate.ConnectionTestResult `json:"connection_test,omitempty"`
	}{
		Route:          route,
		Status:         status,
		Metrics:        metrics,
		ConnectionTest: connectionTest,
	}

	// Marshal to JSON
	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal route to JSON: %w", err)
	}

	logger.Info("terminal prompt: " + string(jsonBytes))
	return nil
}

func displayRouteYAML(rc *eos_io.RuntimeContext, route *hecate.Route, status *hecate.RouteStatus,
	metrics *hecate.RouteMetrics, connectionTest *hecate.ConnectionTestResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build output structure
	output := struct {
		Route          *hecate.Route                `yaml:"route"`
		Status         *hecate.RouteStatus          `yaml:"status,omitempty"`
		Metrics        *hecate.RouteMetrics         `yaml:"metrics,omitempty"`
		ConnectionTest *hecate.ConnectionTestResult `yaml:"connection_test,omitempty"`
	}{
		Route:          route,
		Status:         status,
		Metrics:        metrics,
		ConnectionTest: connectionTest,
	}

	// Marshal to YAML
	yamlBytes, err := yaml.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal route to YAML: %w", err)
	}

	logger.Info("terminal prompt: " + string(yamlBytes))
	return nil
}

package read

import (
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/monitoring"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var readHecateMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Read Hecate metrics",
	Long: `Read and display Hecate metrics including route performance, 
system health, and service status.

The metrics command provides comprehensive monitoring data for all
Hecate components including routes, upstreams, authentication policies,
and system resources.

Examples:
  eos read hecate metrics
  eos read hecate metrics --format json
  eos read hecate metrics --format prometheus
  eos read hecate metrics --route api.example.com`,
	RunE: eos_cli.Wrap(runReadHecateMetrics),
}

func init() {
	readHecateCmd.AddCommand(readHecateMetricsCmd)

	// Define flags
	readHecateMetricsCmd.Flags().String("format", "table", "Output format: table, json, prometheus")
	readHecateMetricsCmd.Flags().String("route", "", "Show metrics for specific route")
	readHecateMetricsCmd.Flags().Bool("system", false, "Show only system metrics")
	readHecateMetricsCmd.Flags().Bool("services", false, "Show only service health")
	readHecateMetricsCmd.Flags().String("caddy-url", "http://localhost:2019", "Caddy admin URL")
	readHecateMetricsCmd.Flags().String("authentik-url", "", "Authentik base URL")
}

func runReadHecateMetrics(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	format, _ := cmd.Flags().GetString("format")
	routeFilter, _ := cmd.Flags().GetString("route")
	systemOnly, _ := cmd.Flags().GetBool("system")
	servicesOnly, _ := cmd.Flags().GetBool("services")
	caddyURL, _ := cmd.Flags().GetString("caddy-url")
	authentikURL, _ := cmd.Flags().GetString("authentik-url")

	logger.Info("Reading Hecate metrics",
		zap.String("format", format),
		zap.String("route_filter", routeFilter))

	// Create metrics collector
	collector := monitoring.NewMetricsCollector(rc, caddyURL, authentikURL)

	// Collect metrics
	snapshot, err := collector.CollectMetrics()
	if err != nil {
		return fmt.Errorf("failed to collect metrics: %w", err)
	}

	// Output based on format
	switch format {
	case "json":
		return outputMetricsJSON(snapshot, routeFilter, systemOnly, servicesOnly)
	case "prometheus":
		return outputMetricsPrometheus(rc, routeFilter)
	case "table":
		return outputMetricsTable(snapshot, routeFilter, systemOnly, servicesOnly)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func outputMetricsJSON(snapshot *monitoring.MetricsSnapshot, routeFilter string, systemOnly, servicesOnly bool) error {
	output := make(map[string]interface{})

	if !systemOnly && !servicesOnly {
		if routeFilter != "" {
			if metrics, exists := snapshot.Routes[routeFilter]; exists {
				output["route"] = metrics
			} else {
				return fmt.Errorf("route %s not found", routeFilter)
			}
		} else {
			output["routes"] = snapshot.Routes
		}
	}

	if !servicesOnly {
		output["system"] = snapshot.System
	}

	if !systemOnly {
		output["services"] = snapshot.Services
	}

	output["timestamp"] = snapshot.Timestamp

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", string(jsonData))))
	return nil
}

func outputMetricsPrometheus(rc *eos_io.RuntimeContext, routeFilter string) error {
	prometheusData, err := monitoring.CollectPrometheusMetrics(rc)
	if err != nil {
		return fmt.Errorf("failed to collect Prometheus metrics: %w", err)
	}

	fmt.Print(prometheusData)
	return nil
}

func outputMetricsTable(snapshot *monitoring.MetricsSnapshot, routeFilter string, systemOnly, servicesOnly bool) error {
	if !systemOnly && !servicesOnly {
		// Route metrics table
		if routeFilter != "" {
			if metrics, exists := snapshot.Routes[routeFilter]; exists {
				printRouteMetricsTable(map[string]monitoring.RouteMetrics{routeFilter: metrics})
			} else {
				return fmt.Errorf("route %s not found", routeFilter)
			}
		} else {
			printRouteMetricsTable(snapshot.Routes)
		}
	}

	if !servicesOnly {
		// System metrics table
		printSystemMetricsTable(snapshot.System)
	}

	if !systemOnly {
		// Service health table
		printServiceHealthTable(snapshot.Services)
	}

	return nil
}

func printRouteMetricsTable(routes map[string]monitoring.RouteMetrics) {
	if len(routes) == 0 {
		logger.Info("terminal prompt: No routes found")
		return
	}

	logger.Info("terminal prompt: \n📊 Route Metrics")
	logger.Info("terminal prompt: ================")
	fmt.Printf("%-25s %-12s %-12s %-15s %-12s %-10s\n",
		"Domain", "Requests", "Errors", "Response Time", "Health", "Error Rate")
	logger.Info("terminal prompt: -----------------------------------------------------------------------------------------")

	for domain, metrics := range routes {
		healthIcon := "🟢"
		if metrics.HealthStatus != "healthy" {
			healthIcon = "🔴"
		}

		fmt.Printf("%-25s %-12d %-12d %-15s %-12s %.2f%%\n",
			domain,
			metrics.RequestCount,
			metrics.ErrorCount,
			metrics.ResponseTime,
			healthIcon+" "+metrics.HealthStatus,
			metrics.ErrorRate*100)
	}
}

func printSystemMetricsTable(system monitoring.SystemMetrics) {
	logger.Info("terminal prompt: \n🖥️  System Metrics")
	logger.Info("terminal prompt: =================")
	logger.Info("terminal prompt: Total Routes:        %d", system.TotalRoutes)
	logger.Info("terminal prompt: Healthy Routes:      %d", system.HealthyRoutes)
	logger.Info("terminal prompt: Unhealthy Routes:    %d", system.UnhealthyRoutes)
	logger.Info("terminal prompt: Total Requests:      %d", system.TotalRequests)
	logger.Info("terminal prompt: Total Errors:        %d", system.TotalErrors)
	logger.Info("terminal prompt: Avg Response Time:   %s", system.AverageResponseTime)
	logger.Info("terminal prompt: System Load:         %.2f", system.SystemLoad)
	logger.Info("terminal prompt: Memory Usage:        %.1f%%", system.MemoryUsage*100)
	logger.Info("terminal prompt: CPU Usage:           %.1f%%", system.CPUUsage*100)
	logger.Info("terminal prompt: Disk Usage:          %.1f%%", system.DiskUsage*100)
	logger.Info("terminal prompt: Network In:          %d bytes", system.NetworkIn)
	logger.Info("terminal prompt: Network Out:         %d bytes", system.NetworkOut)
	logger.Info("terminal prompt: Uptime:              %s", system.Uptime)
}

func printServiceHealthTable(services map[string]monitoring.ServiceHealth) {
	if len(services) == 0 {
		logger.Info("terminal prompt: No services found")
		return
	}

	logger.Info("terminal prompt: \n🔧 Service Health")
	logger.Info("terminal prompt: =================")
	logger.Info("terminal prompt: %-15s %-10s %-15s %-25s", "Service", "Status", "Response Time", "Last Check")
	logger.Info("terminal prompt: -----------------------------------------------------------------------")

	for name, health := range services {
		statusIcon := "🟢"
		if health.Status != "healthy" {
			statusIcon = "🔴"
		}

		fmt.Printf("%-15s %-10s %-15s %-25s\n",
			name,
			statusIcon+" "+health.Status,
			health.ResponseTime,
			health.LastCheck.Format("2006-01-02 15:04:05"))

		if health.ErrorMessage != "" {
			logger.Info("terminal prompt:                 Error: %s", health.ErrorMessage)
		}
	}
}

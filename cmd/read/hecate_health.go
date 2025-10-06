package read

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/monitoring"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var readHecateHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check health of Hecate routes and services",
	Long: `Check the health status of Hecate routes and services.

This command performs health checks on all configured routes and services,
providing detailed status information and response times.

Examples:
  eos read hecate health
  eos read hecate health --route api.example.com
  eos read hecate health --continuous --interval 30s`,
	RunE: eos_cli.Wrap(runReadHecateHealth),
}

func init() {
	readHecateCmd.AddCommand(readHecateHealthCmd)

	// Define flags
	readHecateHealthCmd.Flags().String("route", "", "Check health for specific route")
	readHecateHealthCmd.Flags().Bool("continuous", false, "Continuous health monitoring")
	readHecateHealthCmd.Flags().Duration("interval", 30*time.Second, "Check interval for continuous monitoring")
	readHecateHealthCmd.Flags().Bool("services-only", false, "Check only service health")
	readHecateHealthCmd.Flags().Bool("routes-only", false, "Check only route health")
}

func runReadHecateHealth(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	routeFilter, _ := cmd.Flags().GetString("route")
	continuous, _ := cmd.Flags().GetBool("continuous")
	interval, _ := cmd.Flags().GetDuration("interval")
	servicesOnly, _ := cmd.Flags().GetBool("services-only")
	routesOnly, _ := cmd.Flags().GetBool("routes-only")

	logger.Info("Checking Hecate health",
		zap.String("route_filter", routeFilter),
		zap.Bool("continuous", continuous),
		zap.Duration("interval", interval))

	if continuous {
		return runContinuousHealthCheck(rc, routeFilter, interval, servicesOnly, routesOnly)
	}

	return runSingleHealthCheck(rc, routeFilter, servicesOnly, routesOnly)
}

func runSingleHealthCheck(rc *eos_io.RuntimeContext, routeFilter string, servicesOnly, routesOnly bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !servicesOnly {
		// Check route health
		if routeFilter != "" {
			route := &hecate.Route{
				Domain:   routeFilter,
				Upstream: &hecate.Upstream{URL: "http://localhost:8080"}, // Placeholder
			}

			status, err := monitoring.CheckRouteHealth(rc, route)
			if err != nil {
				return fmt.Errorf("failed to check route health: %w", err)
			}

			printSingleRouteHealth(logger, routeFilter, status)
		} else {
			// TODO: Get all routes from state store
			mockRoutes := []*hecate.Route{
				{Domain: "api.example.com", Upstream: &hecate.Upstream{URL: "http://localhost:8080"}},
				{Domain: "app.example.com", Upstream: &hecate.Upstream{URL: "http://localhost:3000"}},
				{Domain: "admin.example.com", Upstream: &hecate.Upstream{URL: "http://localhost:9000"}},
			}

			logger.Info("terminal prompt:  Route Health Check")
			logger.Info("terminal prompt: =====================")
			allHealthy := true

			for _, route := range mockRoutes {
				status, err := monitoring.CheckRouteHealth(rc, route)
				if err != nil {
					logger.Error("Failed to check route health",
						zap.String("domain", route.Domain),
						zap.Error(err))
					continue
				}

				printRouteHealthStatus(logger, route.Domain, status)
				if status.Health != hecate.RouteHealthHealthy {
					allHealthy = false
				}
			}

			if allHealthy {
				logger.Info("terminal prompt: \n All routes are healthy")
			} else {
				logger.Info("terminal prompt: \n❌ Some routes are unhealthy")
			}
		}
	}

	if !routesOnly {
		// Check service health
		collector := monitoring.NewMetricsCollector(rc, "http://localhost:2019", "")
		snapshot, err := collector.CollectMetrics()
		if err != nil {
			return fmt.Errorf("failed to collect service health: %w", err)
		}

		logger.Info("terminal prompt: \n Service Health Check")
		logger.Info("terminal prompt: =======================")
		allHealthy := true

		for name, health := range snapshot.Services {
			printServiceHealthStatus(logger, name, health)
			if health.Status != "healthy" {
				allHealthy = false
			}
		}

		if allHealthy {
			logger.Info("terminal prompt: \n All services are healthy")
		} else {
			logger.Info("terminal prompt: \n❌ Some services are unhealthy")
		}
	}

	return nil
}

func runContinuousHealthCheck(rc *eos_io.RuntimeContext, routeFilter string, interval time.Duration, servicesOnly, routesOnly bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting continuous health monitoring",
		zap.Duration("interval", interval))

	logger.Info("terminal prompt:  Continuous Health Monitoring", zap.Duration("interval", interval))
	logger.Info("terminal prompt: Press Ctrl+C to stop")
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("=", 50))))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial check
	if err := runSingleHealthCheck(rc, routeFilter, servicesOnly, routesOnly); err != nil {
		logger.Error("Health check failed", zap.Error(err))
	}

	// Continuous monitoring
	for {
		select {
		case <-rc.Ctx.Done():
			logger.Info("Health monitoring stopped")
			return nil
		case <-ticker.C:
			logger.Info("terminal prompt: 🕒 Health Check", zap.String("time", time.Now().Format("15:04:05")))
			logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("-", 30))))

			if err := runSingleHealthCheck(rc, routeFilter, servicesOnly, routesOnly); err != nil {
				logger.Error("Health check failed", zap.Error(err))
			}
		}
	}
}

func printSingleRouteHealth(logger otelzap.LoggerWithCtx, domain string, status *hecate.RouteStatus) {
	logger.Info("terminal prompt:  Route Health", zap.String("domain", domain))
	logger.Info("terminal prompt: ==================")

	healthIcon := "🟢"
	if status.Health != hecate.RouteHealthHealthy {
		healthIcon = "🔴"
	}

	logger.Info("terminal prompt: Status", zap.String("icon", healthIcon), zap.String("status", getHealthText(status.Health == hecate.RouteHealthHealthy)))
	logger.Info("terminal prompt: Response Time", zap.String("time", "N/A"))
	logger.Info("terminal prompt: Last Check", zap.String("time", status.LastChecked.Format("2006-01-02 15:04:05")))

	if status.Message != "" {
		logger.Info("terminal prompt: Error", zap.String("message", status.Message))
	}
}

func printRouteHealthStatus(logger otelzap.LoggerWithCtx, domain string, status *hecate.RouteStatus) {
	healthIcon := "🟢"
	healthText := "Healthy"
	if status.Health != hecate.RouteHealthHealthy {
		healthIcon = "🔴"
		healthText = "Unhealthy"
	}

	logger.Info("terminal prompt: Route health",
		zap.String("domain", domain),
		zap.String("icon", healthIcon),
		zap.String("status", healthText),
		zap.String("response_time", "N/A"))

	if status.Message != "" {
		logger.Info("terminal prompt: Error", zap.String("error", status.Message))
	}

	// Empty line for formatting
}

func printServiceHealthStatus(logger otelzap.LoggerWithCtx, name string, health monitoring.ServiceHealth) {
	healthIcon := "🟢"
	if health.Status != "healthy" {
		healthIcon = "🔴"
	}

	logger.Info("terminal prompt: Service health",
		zap.String("name", name),
		zap.String("icon", healthIcon),
		zap.String("status", health.Status),
		zap.Duration("response_time", health.ResponseTime))

	if health.ErrorMessage != "" {
		logger.Info("terminal prompt: Error", zap.String("error", health.ErrorMessage))
	}

	// Empty line for formatting
}

func getHealthText(healthy bool) string {
	if healthy {
		return "Healthy"
	}
	return "Unhealthy"
}

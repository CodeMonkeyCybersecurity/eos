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
				Upstream: "localhost:8080", // Placeholder
			}

			status, err := monitoring.CheckRouteHealth(rc, route)
			if err != nil {
				return fmt.Errorf("failed to check route health: %w", err)
			}

			printSingleRouteHealth(routeFilter, status)
		} else {
			// TODO: Get all routes from state store
			mockRoutes := []*hecate.Route{
				{Domain: "api.example.com", Upstream: "localhost:8080"},
				{Domain: "app.example.com", Upstream: "localhost:3000"},
				{Domain: "admin.example.com", Upstream: "localhost:9000"},
			}

			fmt.Println("🔍 Route Health Check")
			fmt.Println("=====================")
			allHealthy := true

			for _, route := range mockRoutes {
				status, err := monitoring.CheckRouteHealth(rc, route)
				if err != nil {
					logger.Error("Failed to check route health",
						zap.String("domain", route.Domain),
						zap.Error(err))
					continue
				}

				printRouteHealthStatus(route.Domain, status)
				if !status.Healthy {
					allHealthy = false
				}
			}

			if allHealthy {
				fmt.Println("\n All routes are healthy")
			} else {
				fmt.Println("\n❌ Some routes are unhealthy")
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

		fmt.Println("\n🔧 Service Health Check")
		fmt.Println("=======================")
		allHealthy := true

		for name, health := range snapshot.Services {
			printServiceHealthStatus(name, health)
			if health.Status != "healthy" {
				allHealthy = false
			}
		}

		if allHealthy {
			fmt.Println("\n All services are healthy")
		} else {
			fmt.Println("\n❌ Some services are unhealthy")
		}
	}

	return nil
}

func runContinuousHealthCheck(rc *eos_io.RuntimeContext, routeFilter string, interval time.Duration, servicesOnly, routesOnly bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting continuous health monitoring",
		zap.Duration("interval", interval))

	fmt.Printf("🔄 Continuous Health Monitoring (every %s)\n", interval)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println(strings.Repeat("=", 50))

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
			fmt.Printf("\n🕒 Health Check - %s\n", time.Now().Format("15:04:05"))
			fmt.Println(strings.Repeat("-", 30))

			if err := runSingleHealthCheck(rc, routeFilter, servicesOnly, routesOnly); err != nil {
				logger.Error("Health check failed", zap.Error(err))
			}
		}
	}
}

func printSingleRouteHealth(domain string, status *hecate.RouteStatus) {
	fmt.Printf("🔍 Route Health: %s\n", domain)
	fmt.Println("==================")

	healthIcon := "🟢"
	if !status.Healthy {
		healthIcon = "🔴"
	}

	fmt.Printf("Status:        %s %s\n", healthIcon, getHealthText(status.Healthy))
	fmt.Printf("Response Time: %s\n", status.ResponseTime)
	fmt.Printf("Last Check:    %s\n", status.LastCheck.Format("2006-01-02 15:04:05"))

	if status.ErrorMessage != "" {
		fmt.Printf("Error:         %s\n", status.ErrorMessage)
	}
}

func printRouteHealthStatus(domain string, status *hecate.RouteStatus) {
	healthIcon := "🟢"
	healthText := "Healthy"
	if !status.Healthy {
		healthIcon = "🔴"
		healthText = "Unhealthy"
	}

	fmt.Printf("%-25s %s %-10s %8s", domain, healthIcon, healthText, status.ResponseTime)

	if status.ErrorMessage != "" {
		fmt.Printf(" (%s)", status.ErrorMessage)
	}

	fmt.Println()
}

func printServiceHealthStatus(name string, health monitoring.ServiceHealth) {
	healthIcon := "🟢"
	if health.Status != "healthy" {
		healthIcon = "🔴"
	}

	fmt.Printf("%-15s %s %-10s %8s", name, healthIcon, health.Status, health.ResponseTime)

	if health.ErrorMessage != "" {
		fmt.Printf(" (%s)", health.ErrorMessage)
	}

	fmt.Println()
}

func getHealthText(healthy bool) string {
	if healthy {
		return "Healthy"
	}
	return "Unhealthy"
}

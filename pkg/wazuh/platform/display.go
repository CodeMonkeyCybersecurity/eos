package platform

import (
	"encoding/json"
	"fmt"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// OutputFormat represents supported output formats.
type OutputFormat string

const (
	FormatTable OutputFormat = "table"
	FormatJSON  OutputFormat = "json"
	FormatYAML  OutputFormat = "yaml"
)

// OutputPlatformStatus outputs platform status in the specified format.
func OutputPlatformStatus(logger otelzap.LoggerWithCtx, status *PlatformStatus, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return outputJSON(status)
	case FormatYAML:
		return outputYAML(status)
	case FormatTable:
		return outputStatusTable(logger, *status)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// OutputCustomerStatus outputs customer deployment status in the specified format.
func OutputCustomerStatus(logger otelzap.LoggerWithCtx, status *CustomerDeploymentStatus, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return outputJSON(status)
	case FormatYAML:
		return outputYAML(status)
	case FormatTable:
		return outputCustomerStatusTable(logger, *status)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// OutputCustomerDetails outputs customer details in the specified format.
func OutputCustomerDetails(logger otelzap.LoggerWithCtx, details *CustomerDetails, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return outputJSON(details)
	case FormatYAML:
		return outputYAML(details)
	case FormatTable:
		return outputCustomerDetailsTable(logger, *details)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// OutputPlatformHealth outputs platform health in the specified format.
func OutputPlatformHealth(logger otelzap.LoggerWithCtx, health *PlatformHealth, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return outputJSON(health)
	case FormatYAML:
		return outputYAML(health)
	case FormatTable:
		return outputHealthTable(logger, *health)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// OutputPlatformResources outputs platform resources in the specified format.
func OutputPlatformResources(logger otelzap.LoggerWithCtx, resources *PlatformResources, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return outputJSON(resources)
	case FormatYAML:
		return outputYAML(resources)
	case FormatTable:
		return outputResourcesTable(logger, *resources)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// OutputCustomerResources outputs customer resources in the specified format.
func OutputCustomerResources(logger otelzap.LoggerWithCtx, resources *CustomerResources, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return outputJSON(resources)
	case FormatYAML:
		return outputYAML(resources)
	case FormatTable:
		return outputCustomerResourcesTable(logger, *resources)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// OutputEventStatistics outputs event statistics in the specified format.
func OutputEventStatistics(logger otelzap.LoggerWithCtx, stats *EventStatistics, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return outputJSON(stats)
	case FormatYAML:
		return outputYAML(stats)
	case FormatTable:
		return outputEventStatsTable(logger, *stats)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// Helper functions for output formatting
func outputJSON(data interface{}) error {
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

func outputYAML(data interface{}) error {
	output, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

// Table output functions
func outputStatusTable(logger otelzap.LoggerWithCtx, status PlatformStatus) error {
	logger.Info("terminal prompt: === Platform Status ===")
	logger.Info("terminal prompt: Platform", zap.String("name", status.Platform.Name), zap.String("status", status.Platform.Status), zap.String("health", status.Platform.Health))

	logger.Info("terminal prompt:")
	logger.Info("terminal prompt: === Components ===")
	for _, comp := range status.Components {
		logger.Info("terminal prompt: Component",
			zap.String("name", comp.Name),
			zap.String("status", comp.Status),
			zap.String("health", comp.Health),
			zap.String("details", comp.Details))
	}

	logger.Info("terminal prompt:")
	logger.Info("terminal prompt: === Customers Summary ===")
	logger.Info("terminal prompt: Customers",
		zap.Int("total", status.Customers.Total),
		zap.Int("active", status.Customers.Active),
		zap.Int("suspended", status.Customers.Suspended))

	return nil
}

func outputCustomerStatusTable(logger otelzap.LoggerWithCtx, status CustomerDeploymentStatus) error {
	logger.Info("terminal prompt: === Customer Deployment Status ===")
	logger.Info("terminal prompt: Customer",
		zap.String("id", status.CustomerID),
		zap.String("company", status.CompanyName),
		zap.String("tier", status.Tier),
		zap.String("status", status.Status))

	logger.Info("terminal prompt:")
	logger.Info("terminal prompt: === Components ===")
	for _, comp := range status.Components {
		logger.Info("terminal prompt: Component",
			zap.String("name", comp.Name),
			zap.String("status", comp.Status),
			zap.String("details", comp.Details))
	}

	logger.Info("terminal prompt:")
	logger.Info("terminal prompt: === Resources ===")
	logger.Info("terminal prompt: CPU", zap.String("used", status.Resources.CPU.Used), zap.String("total", status.Resources.CPU.Total))
	logger.Info("terminal prompt: Memory", zap.String("used", status.Resources.Memory.Used), zap.String("total", status.Resources.Memory.Total))
	logger.Info("terminal prompt: Disk", zap.String("used", status.Resources.Disk.Used), zap.String("total", status.Resources.Disk.Total))

	return nil
}

func outputCustomerDetailsTable(logger otelzap.LoggerWithCtx, details CustomerDetails) error {
	logger.Info("terminal prompt: === Customer Details ===")
	logger.Info("terminal prompt: Basic Info",
		zap.String("id", details.CustomerID),
		zap.String("company", details.CompanyName),
		zap.String("tier", details.Tier),
		zap.String("status", details.Status))

	logger.Info("terminal prompt:")
	logger.Info("terminal prompt: Admin Contact",
		zap.String("name", details.AdminName),
		zap.String("email", details.AdminEmail))

	logger.Info("terminal prompt:")
	logger.Info("terminal prompt: URLs",
		zap.String("dashboard", details.URLs.Dashboard),
		zap.String("api", details.URLs.API))

	if details.Credentials != nil {
		logger.Info("terminal prompt:")
		logger.Info("terminal prompt: Credentials",
			zap.String("username", details.Credentials.Username),
			zap.String("password", details.Credentials.Password))
	}

	return nil
}

func outputHealthTable(logger otelzap.LoggerWithCtx, health PlatformHealth) error {
	logger.Info("terminal prompt: === Platform Health ===")
	logger.Info("terminal prompt: Overall Status", zap.String("health", health.Overall), zap.Int("issues", health.Issues))

	logger.Info("terminal prompt:")
	logger.Info("terminal prompt: === Health Checks ===")
	for _, check := range health.Checks {
		logger.Info("terminal prompt: Check",
			zap.String("name", check.Name),
			zap.String("status", check.Status),
			zap.String("message", check.Message))
	}

	return nil
}

func outputResourcesTable(logger otelzap.LoggerWithCtx, resources PlatformResources) error {
	logger.Info("terminal prompt: === Platform Resources ===")
	logger.Info("terminal prompt: Total CPU", zap.String("used", resources.Total.CPU.Used), zap.String("total", resources.Total.CPU.Total))
	logger.Info("terminal prompt: Total Memory", zap.String("used", resources.Total.Memory.Used), zap.String("total", resources.Total.Memory.Total))
	logger.Info("terminal prompt: Total Disk", zap.String("used", resources.Total.Disk.Used), zap.String("total", resources.Total.Disk.Total))

	if len(resources.Customers) > 0 {
		logger.Info("terminal prompt:")
		logger.Info("terminal prompt: === By Customer ===")
		for _, cust := range resources.Customers {
			logger.Info("terminal prompt: Customer",
				zap.String("id", cust.CustomerID),
				zap.String("company", cust.CompanyName),
				zap.String("cpu", cust.Resources.CPU.Used),
				zap.String("memory", cust.Resources.Memory.Used),
				zap.String("disk", cust.Resources.Disk.Used))
		}
	}

	return nil
}

func outputCustomerResourcesTable(logger otelzap.LoggerWithCtx, resources CustomerResources) error {
	logger.Info("terminal prompt: === Customer Resources ===")
	for _, cust := range resources.Customers {
		logger.Info("terminal prompt: Customer",
			zap.String("id", cust.CustomerID),
			zap.String("company", cust.CompanyName),
			zap.String("cpu_used", cust.Resources.CPU.Used),
			zap.String("memory_used", cust.Resources.Memory.Used),
			zap.String("disk_used", cust.Resources.Disk.Used))
	}
	return nil
}

func outputEventStatsTable(logger otelzap.LoggerWithCtx, stats EventStatistics) error {
	logger.Info("terminal prompt: === Event Statistics ===")
	logger.Info("terminal prompt: Time Range", zap.String("range", stats.TimeRange))
	logger.Info("terminal prompt: Total Events", zap.Int64("total", stats.Total))
	logger.Info("terminal prompt: Events/sec", zap.Float64("per_second", stats.PerSecond))
	logger.Info("terminal prompt: Events/min", zap.Float64("per_minute", stats.PerMinute))
	logger.Info("terminal prompt: Events/hour", zap.Float64("per_hour", stats.PerHour))

	if len(stats.ByCustomer) > 0 {
		logger.Info("terminal prompt:")
		logger.Info("terminal prompt: === By Customer ===")
		for _, cust := range stats.ByCustomer {
			logger.Info("terminal prompt: Customer",
				zap.String("id", cust.CustomerID),
				zap.String("company", cust.CompanyName),
				zap.Int64("events", cust.EventCount),
				zap.Float64("per_second", cust.PerSecond))
		}
	}

	return nil
}

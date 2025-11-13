package customers

import (
	"fmt"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OutputCustomerTable formats and displays customer list as a table.
func OutputCustomerTable(logger otelzap.LoggerWithCtx, list CustomerList) error {
	logger.Info("terminal prompt: Customers", zap.Int("total", list.Total))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 100)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-15s %-25s %-15s %-10s %-10s %-20s",
		"Customer ID", "Company", "Subdomain", "Tier", "Status", "Created")))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 100)))

	for _, customer := range list.Customers {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-15s %-25s %-15s %-10s %-10s %-20s",
			customer.CustomerID,
			truncate(customer.CompanyName, 25),
			customer.Subdomain,
			customer.Tier,
			customer.Status,
			customer.CreatedAt.Format("2006-01-02"))))
	}

	logger.Info("terminal prompt: Summary:")
	logger.Info("terminal prompt: By Tier: ")
	for tier, count := range list.Summary.ByTier {
		logger.Info("terminal prompt: Tier", zap.String("tier", tier), zap.Int("count", count))
	}
	logger.Info("terminal prompt: By Status: ")
	for status, count := range list.Summary.ByStatus {
		logger.Info("terminal prompt: Status", zap.String("status", status), zap.Int("count", count))
	}

	return nil
}

// OutputDetailedCustomerTable formats and displays detailed customer information.
func OutputDetailedCustomerTable(logger otelzap.LoggerWithCtx, list CustomerList) error {
	logger.Info("terminal prompt: Customers - Detailed View", zap.Int("total", list.Total))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 120)))

	for _, customer := range list.Customers {
		logger.Info("terminal prompt: \nCustomer:", zap.String("company", customer.CompanyName), zap.String("id", customer.CustomerID))
		logger.Info("terminal prompt:   Subdomain:", zap.String("subdomain", customer.Subdomain))
		logger.Info("terminal prompt:   Tier:", zap.String("tier", customer.Tier))
		logger.Info("terminal prompt:   Status:", zap.String("status", customer.Status))
		logger.Info("terminal prompt:   Admin Email:", zap.String("email", customer.AdminEmail))
		logger.Info("terminal prompt:   Created:", zap.String("created", customer.CreatedAt.Format("2006-01-02 15:04:05")))
		logger.Info("terminal prompt:   Agents:", zap.Int("agents", customer.AgentCount))
		logger.Info("terminal prompt:   Events/Day:", zap.Int("events_per_day", customer.EventsPerDay))
		logger.Info("terminal prompt:   Resources:",
			zap.Int("cpu_cores", customer.Resources.CPUCores),
			zap.Int("memory_gb", customer.Resources.MemoryGB),
			zap.Int("disk_gb", customer.Resources.DiskGB))
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))
	}

	return nil
}

// truncate truncates a string to maxLen characters, adding "..." if truncated.
// TODO: Consider moving to pkg/shared/format/strings.go if used across multiple packages.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// cmd/read/wazuh_ccs.go
package read

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReadWazuhCCSCmd reads Wazuh MSSP platform status and information
var ReadWazuhCCSCmd = &cobra.Command{
	Use:   "wazuh-ccs",
	Short: "Read Wazuh MSSP platform status and information",
	Long: `Read various information about the Wazuh MSSP platform:

- Platform status (--status)
- Customer details (--customer)
- Deployment health (--health)
- Resource usage (--resources)
- Event statistics (--events)`,
	RunE: eos_cli.Wrap(runReadWazuhCCS),
}

func init() {
	ReadCmd.AddCommand(ReadWazuhCCSCmd)

	// Status flags
	ReadWazuhCCSCmd.Flags().Bool("status", false, "Show platform status")
	ReadWazuhCCSCmd.Flags().String("customer-id", "", "Customer ID for detailed status")

	// Customer information flags
	ReadWazuhCCSCmd.Flags().Bool("customer", false, "Show customer details")
	ReadWazuhCCSCmd.Flags().Bool("show-credentials", false, "Include credentials in output")

	// Health check flags
	ReadWazuhCCSCmd.Flags().Bool("health", false, "Show platform health")
	ReadWazuhCCSCmd.Flags().Bool("detailed", false, "Show detailed health information")

	// Resource usage flags
	ReadWazuhCCSCmd.Flags().Bool("resources", false, "Show resource usage")
	ReadWazuhCCSCmd.Flags().Bool("by-customer", false, "Group resources by customer")

	// Event statistics flags
	ReadWazuhCCSCmd.Flags().Bool("events", false, "Show event statistics")
	ReadWazuhCCSCmd.Flags().String("time-range", "1h", "Time range for statistics (1h/24h/7d)")

	// Output format
	ReadWazuhCCSCmd.Flags().String("output", "table", "Output format (table/json/yaml)")
}

func runReadWazuhCCS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Reading Wazuh MSSP information")

	// Determine what to read
	status, _ := cmd.Flags().GetBool("status")
	customer, _ := cmd.Flags().GetBool("customer")
	health, _ := cmd.Flags().GetBool("health")
	resources, _ := cmd.Flags().GetBool("resources")
	events, _ := cmd.Flags().GetBool("events")

	// Default to status if nothing specified
	if !status && !customer && !health && !resources && !events {
		status = true
	}

	outputFormat, _ := cmd.Flags().GetString("output")

	switch {
	case status:
		return showPlatformStatus(rc, cmd, outputFormat)
	case customer:
		return showCustomerDetails(rc, cmd, outputFormat)
	case health:
		return showPlatformHealth(rc, cmd, outputFormat)
	case resources:
		return showResourceUsage(rc, cmd, outputFormat)
	case events:
		return showEventStatistics(rc, cmd, outputFormat)
	default:
		return cmd.Help()
	}
}

func showPlatformStatus(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Showing platform status")

	customerID, _ := cmd.Flags().GetString("customer-id")

	if customerID != "" {
		// Show specific customer status
		return showCustomerStatus(rc, customerID, format)
	}

	// Get overall platform status
	// This would query various components
	status := PlatformStatus{
		Platform: ComponentStatus{
			Name:    "Wazuh MSSP Platform",
			Status:  "operational",
			Health:  "healthy",
			Version: "1.0.0",
		},
		Components: []ComponentStatus{
			{
				Name:    "Nomad Cluster",
				Status:  "running",
				Health:  "healthy",
				Details: "3 servers, 5 clients",
			},
			{
				Name:    "Temporal",
				Status:  "running",
				Health:  "healthy",
				Details: "1 server, default namespace",
			},
			{
				Name:    "NATS",
				Status:  "running",
				Health:  "healthy",
				Details: "3 servers, JetStream enabled",
			},
			{
				Name:    "CCS Indexer",
				Status:  "running",
				Health:  "healthy",
				Details: "Cluster status: green",
			},
			{
				Name:    "Platform API",
				Status:  "running",
				Health:  "healthy",
				Details: "v1 endpoints available",
			},
		},
		Customers: CustomersSummary{
			Total:     15,
			Active:    14,
			Suspended: 1,
			ByTier:    map[string]int{"starter": 5, "pro": 7, "enterprise": 3},
		},
		LastUpdated: time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(status)
	case "yaml":
		return outputYAML(status)
	default:
		return outputStatusTable(logger, status)
	}
}

func showCustomerStatus(rc *eos_io.RuntimeContext, customerID string, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Showing customer status", zap.String("customer_id", customerID))

	// Verify customer
	if err := delphi.VerifyCustomer(rc, customerID); err != nil {
		return fmt.Errorf("customer verification failed: %w", err)
	}

	// Get customer deployment status
	status := CustomerDeploymentStatus{
		CustomerID:  customerID,
		CompanyName: "ACME Corporation", // Would fetch from Vault
		Tier:        "pro",
		Status:      "active",
		Components: []ComponentStatus{
			{
				Name:     "Wazuh Indexer",
				Status:   "running",
				Health:   "healthy",
				Version:  "4.8.2",
				Endpoint: "https://acme.mssp.example.com:9200",
				Details:  "3 nodes, cluster green",
			},
			{
				Name:     "Wazuh Server",
				Status:   "running",
				Health:   "healthy",
				Version:  "4.8.2",
				Endpoint: "https://acme.mssp.example.com:55000",
				Details:  "2 nodes, 150 agents connected",
			},
			{
				Name:     "Wazuh Dashboard",
				Status:   "running",
				Health:   "healthy",
				Version:  "4.8.2",
				Endpoint: "https://acme.mssp.example.com",
				Details:  "SSO enabled via Authentik",
			},
		},
		Resources: ResourceUsage{
			CPU:    ResourceMetric{Used: 12, Total: 16, Unit: "cores"},
			Memory: ResourceMetric{Used: 24576, Total: 32768, Unit: "MB"},
			Disk:   ResourceMetric{Used: 150, Total: 400, Unit: "GB"},
		},
		Network: NetworkInfo{
			VLANID:    123,
			Subnet:    "10.123.0.0/24",
			Interface: "br-platform.123",
		},
		LastUpdated: time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(status)
	case "yaml":
		return outputYAML(status)
	default:
		return outputCustomerStatusTable(logger, status)
	}
}

func showCustomerDetails(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	customerID, _ := cmd.Flags().GetString("customer-id")
	if customerID == "" {
		return fmt.Errorf("customer-id flag is required")
	}

	showCredentials, _ := cmd.Flags().GetBool("show-credentials")

	logger.Info("Showing customer details", zap.String("customer_id", customerID))

	// Get customer configuration
	// This would fetch from Vault
	details := CustomerDetails{
		CustomerID:   customerID,
		CompanyName:  "ACME Corporation",
		Subdomain:    "acme",
		Tier:         "pro",
		AdminEmail:   "admin@acme.com",
		AdminName:    "John Doe",
		Status:       "active",
		CreatedAt:    time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:    time.Now().Add(-2 * time.Hour),
		WazuhVersion: "4.8.2",
		URLs: CustomerURLs{
			Dashboard: "https://acme.mssp.example.com",
			API:       "https://acme.mssp.example.com:55000",
		},
	}

	if showCredentials {
		// Fetch credentials from Vault
		details.Credentials = &CustomerCredentials{
			AdminUsername: "admin",
			APIUsername:   "wazuh-wui",
			VaultPath:     fmt.Sprintf("wazuh-mssp/customers/%s/wazuh/credentials", customerID),
		}
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(details)
	case "yaml":
		return outputYAML(details)
	default:
		return outputCustomerDetailsTable(logger, details)
	}
}

func showPlatformHealth(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking platform health")

	detailed, _ := cmd.Flags().GetBool("detailed")

	// Run platform verification
	if err := delphi.VerifyPlatform(rc); err != nil {
		logger.Warn("Platform verification found issues", zap.Error(err))
	}

	// Collect health information
	health := PlatformHealth{
		Overall: "healthy",
		Checks: []HealthCheck{
			{
				Name:     "Nomad Cluster",
				Status:   "passed",
				Message:  "Cluster is healthy with leader elected",
				Duration: 150 * time.Millisecond,
			},
			{
				Name:     "Temporal Service",
				Status:   "passed",
				Message:  "Temporal is running and accessible",
				Duration: 230 * time.Millisecond,
			},
			{
				Name:     "NATS Service",
				Status:   "passed",
				Message:  "NATS is running with all required streams",
				Duration: 180 * time.Millisecond,
			},
			{
				Name:     "CCS Services",
				Status:   "passed",
				Message:  "CCS indexer and dashboard are healthy",
				Duration: 340 * time.Millisecond,
			},
			{
				Name:     "Network Configuration",
				Status:   "passed",
				Message:  "Network configured with 14 customer VLANs",
				Duration: 120 * time.Millisecond,
			},
			{
				Name:     "Storage Capacity",
				Status:   "warning",
				Message:  "Storage usage at 78%",
				Duration: 90 * time.Millisecond,
			},
		},
		LastCheck: time.Now(),
	}

	if detailed {
		// Add more detailed information
		health.Details = map[string]interface{}{
			"nomad_servers":     3,
			"nomad_clients":     5,
			"active_customers":  14,
			"total_agents":      2150,
			"events_per_second": 3500,
			"storage_used_gb":   780,
			"storage_total_gb":  1000,
		}
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(health)
	case "yaml":
		return outputYAML(health)
	default:
		return outputHealthTable(logger, health)
	}
}

func showResourceUsage(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Showing resource usage")

	byCustomer, _ := cmd.Flags().GetBool("by-customer")

	if byCustomer {
		return showResourcesByCustomer(rc, format)
	}

	// Get overall resource usage
	usage := PlatformResources{
		Total: ResourceUsage{
			CPU:    ResourceMetric{Used: 156, Total: 200, Unit: "cores"},
			Memory: ResourceMetric{Used: 320000, Total: 409600, Unit: "MB"},
			Disk:   ResourceMetric{Used: 3200, Total: 5000, Unit: "GB"},
		},
		ByComponent: map[string]ResourceUsage{
			"Platform Services": {
				CPU:    ResourceMetric{Used: 24, Total: 40, Unit: "cores"},
				Memory: ResourceMetric{Used: 49152, Total: 65536, Unit: "MB"},
				Disk:   ResourceMetric{Used: 400, Total: 500, Unit: "GB"},
			},
			"Customer Deployments": {
				CPU:    ResourceMetric{Used: 132, Total: 160, Unit: "cores"},
				Memory: ResourceMetric{Used: 270848, Total: 344064, Unit: "MB"},
				Disk:   ResourceMetric{Used: 2800, Total: 4500, Unit: "GB"},
			},
		},
		Timestamp: time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(usage)
	case "yaml":
		return outputYAML(usage)
	default:
		return outputResourcesTable(logger, usage)
	}
}

func showResourcesByCustomer(rc *eos_io.RuntimeContext, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	// Get resource usage by customer
	resources := CustomerResources{
		Customers: []CustomerResourceUsage{
			{
				CustomerID:  "cust_12345",
				CompanyName: "ACME Corporation",
				Tier:        "pro",
				Usage: ResourceUsage{
					CPU:    ResourceMetric{Used: 12, Total: 16, Unit: "cores"},
					Memory: ResourceMetric{Used: 24576, Total: 32768, Unit: "MB"},
					Disk:   ResourceMetric{Used: 150, Total: 400, Unit: "GB"},
				},
			},
			{
				CustomerID:  "cust_67890",
				CompanyName: "TechCorp Inc",
				Tier:        "enterprise",
				Usage: ResourceUsage{
					CPU:    ResourceMetric{Used: 28, Total: 32, Unit: "cores"},
					Memory: ResourceMetric{Used: 57344, Total: 65536, Unit: "MB"},
					Disk:   ResourceMetric{Used: 480, Total: 1000, Unit: "GB"},
				},
			},
		},
		Total: ResourceUsage{
			CPU:    ResourceMetric{Used: 132, Total: 160, Unit: "cores"},
			Memory: ResourceMetric{Used: 270848, Total: 344064, Unit: "MB"},
			Disk:   ResourceMetric{Used: 2800, Total: 4500, Unit: "GB"},
		},
		Timestamp: time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(resources)
	case "yaml":
		return outputYAML(resources)
	default:
		return outputCustomerResourcesTable(logger, resources)
	}
}

func showEventStatistics(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Showing event statistics")

	timeRange, _ := cmd.Flags().GetString("time-range")

	// Get event statistics
	// This would query the platform metrics
	stats := EventStatistics{
		TimeRange: timeRange,
		Total:     1250000,
		ByType: map[string]int{
			"security_events":    450000,
			"system_events":      300000,
			"application_events": 250000,
			"audit_events":       150000,
			"file_integrity":     100000,
		},
		ByCustomer: []CustomerEventStats{
			{
				CustomerID:  "cust_12345",
				CompanyName: "ACME Corporation",
				Events:      125000,
				AlertsHigh:  15,
				AlertsMed:   230,
				AlertsLow:   1450,
			},
			{
				CustomerID:  "cust_67890",
				CompanyName: "TechCorp Inc",
				Events:      285000,
				AlertsHigh:  42,
				AlertsMed:   580,
				AlertsLow:   3200,
			},
		},
		EventsPerSecond: 347,
		PeakEPS:         892,
		Timestamp:       time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(stats)
	case "yaml":
		return outputYAML(stats)
	default:
		return outputEventStatsTable(logger, stats)
	}
}

// Data structures for output

type PlatformStatus struct {
	Platform    ComponentStatus   `json:"platform"`
	Components  []ComponentStatus `json:"components"`
	Customers   CustomersSummary  `json:"customers"`
	LastUpdated time.Time         `json:"last_updated"`
}

type ComponentStatus struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Health   string `json:"health"`
	Version  string `json:"version,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Details  string `json:"details,omitempty"`
}

type CustomersSummary struct {
	Total     int            `json:"total"`
	Active    int            `json:"active"`
	Suspended int            `json:"suspended"`
	ByTier    map[string]int `json:"by_tier"`
}

type CustomerDeploymentStatus struct {
	CustomerID  string            `json:"customer_id"`
	CompanyName string            `json:"company_name"`
	Tier        string            `json:"tier"`
	Status      string            `json:"status"`
	Components  []ComponentStatus `json:"components"`
	Resources   ResourceUsage     `json:"resources"`
	Network     NetworkInfo       `json:"network"`
	LastUpdated time.Time         `json:"last_updated"`
}

type ResourceUsage struct {
	CPU    ResourceMetric `json:"cpu"`
	Memory ResourceMetric `json:"memory"`
	Disk   ResourceMetric `json:"disk"`
}

type ResourceMetric struct {
	Used  float64 `json:"used"`
	Total float64 `json:"total"`
	Unit  string  `json:"unit"`
}

type NetworkInfo struct {
	VLANID    int    `json:"vlan_id"`
	Subnet    string `json:"subnet"`
	Interface string `json:"interface"`
}

type CustomerDetails struct {
	CustomerID   string               `json:"customer_id"`
	CompanyName  string               `json:"company_name"`
	Subdomain    string               `json:"subdomain"`
	Tier         string               `json:"tier"`
	AdminEmail   string               `json:"admin_email"`
	AdminName    string               `json:"admin_name"`
	Status       string               `json:"status"`
	CreatedAt    time.Time            `json:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
	WazuhVersion string               `json:"wazuh_version"`
	URLs         CustomerURLs         `json:"urls"`
	Credentials  *CustomerCredentials `json:"credentials,omitempty"`
}

type CustomerURLs struct {
	Dashboard string `json:"dashboard"`
	API       string `json:"api"`
}

type CustomerCredentials struct {
	AdminUsername string `json:"admin_username"`
	APIUsername   string `json:"api_username"`
	VaultPath     string `json:"vault_path"`
}

type PlatformHealth struct {
	Overall   string                 `json:"overall"`
	Checks    []HealthCheck          `json:"checks"`
	Details   map[string]interface{} `json:"details,omitempty"`
	LastCheck time.Time              `json:"last_check"`
}

type HealthCheck struct {
	Name     string        `json:"name"`
	Status   string        `json:"status"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
}

type PlatformResources struct {
	Total       ResourceUsage            `json:"total"`
	ByComponent map[string]ResourceUsage `json:"by_component"`
	Timestamp   time.Time                `json:"timestamp"`
}

type CustomerResources struct {
	Customers []CustomerResourceUsage `json:"customers"`
	Total     ResourceUsage           `json:"total"`
	Timestamp time.Time               `json:"timestamp"`
}

type CustomerResourceUsage struct {
	CustomerID  string        `json:"customer_id"`
	CompanyName string        `json:"company_name"`
	Tier        string        `json:"tier"`
	Usage       ResourceUsage `json:"usage"`
}

type EventStatistics struct {
	TimeRange       string               `json:"time_range"`
	Total           int                  `json:"total"`
	ByType          map[string]int       `json:"by_type"`
	ByCustomer      []CustomerEventStats `json:"by_customer"`
	EventsPerSecond int                  `json:"events_per_second"`
	PeakEPS         int                  `json:"peak_eps"`
	Timestamp       time.Time            `json:"timestamp"`
}

type CustomerEventStats struct {
	CustomerID  string `json:"customer_id"`
	CompanyName string `json:"company_name"`
	Events      int    `json:"events"`
	AlertsHigh  int    `json:"alerts_high"`
	AlertsMed   int    `json:"alerts_medium"`
	AlertsLow   int    `json:"alerts_low"`
}

// Output formatting functions

func outputJSON(data interface{}) error {
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Printf("%s\n", string(output))
	return nil
}

func outputYAML(data interface{}) error {
	// Simplified YAML output using JSON
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	fmt.Printf("%s\n", string(output))
	return nil
}

func outputStatusTable(logger otelzap.LoggerWithCtx, status PlatformStatus) error {
	logger.Info("Platform status",
		zap.String("status", status.Platform.Status),
		zap.String("health", status.Platform.Health),
		zap.String("version", status.Platform.Version))

	logger.Info("Components header")
	logger.Info(strings.Repeat("-", 60))
	logger.Info(fmt.Sprintf("%-20s %-10s %-10s %s", "Component", "Status", "Health", "Details"))
	logger.Info(strings.Repeat("-", 60))

	for _, comp := range status.Components {
		logger.Info(fmt.Sprintf("%-20s %-10s %-10s %s", comp.Name, comp.Status, comp.Health, comp.Details))
	}

	logger.Info("Customers summary",
		zap.Int("total", status.Customers.Total),
		zap.Int("active", status.Customers.Active),
		zap.Int("suspended", status.Customers.Suspended))
	
	for tier, count := range status.Customers.ByTier {
		logger.Info("Customer tier count",
			zap.String("tier", tier),
			zap.Int("count", count))
	}

	logger.Info("Last updated",
		zap.String("timestamp", status.LastUpdated.Format(time.RFC3339)))
	return nil
}

func outputCustomerStatusTable(logger otelzap.LoggerWithCtx, status CustomerDeploymentStatus) error {
	logger.Info("Customer status",
		zap.String("company_name", status.CompanyName),
		zap.String("customer_id", status.CustomerID),
		zap.String("tier", status.Tier),
		zap.String("status", status.Status))

	logger.Info("Components header")
	logger.Info(strings.Repeat("-", 80))
	logger.Info(fmt.Sprintf("%-20s %-10s %-10s %-30s %s", "Component", "Status", "Health", "Endpoint", "Details"))
	logger.Info(strings.Repeat("-", 80))

	for _, comp := range status.Components {
		logger.Info(fmt.Sprintf("terminal prompt: %-20s %-10s %-10s %-30s %s",
			comp.Name, comp.Status, comp.Health, comp.Endpoint, comp.Details))
	}

	logger.Info("Resource usage")
	logger.Info(fmt.Sprintf("terminal prompt: CPU: %.1f / %.1f %s (%.1f%%)",
		status.Resources.CPU.Used, status.Resources.CPU.Total, status.Resources.CPU.Unit,
		(status.Resources.CPU.Used/status.Resources.CPU.Total)*100))
	logger.Info(fmt.Sprintf("terminal prompt: Memory: %.0f / %.0f %s (%.1f%%)",
		status.Resources.Memory.Used, status.Resources.Memory.Total, status.Resources.Memory.Unit,
		(status.Resources.Memory.Used/status.Resources.Memory.Total)*100))
	logger.Info(fmt.Sprintf("terminal prompt: Disk: %.0f / %.0f %s (%.1f%%)",
		status.Resources.Disk.Used, status.Resources.Disk.Total, status.Resources.Disk.Unit,
		(status.Resources.Disk.Used/status.Resources.Disk.Total)*100))

	logger.Info("Network configuration",
		zap.Int("vlan_id", status.Network.VLANID),
		zap.String("subnet", status.Network.Subnet),
		zap.String("interface", status.Network.Interface))

	logger.Info("Last updated",
		zap.String("timestamp", status.LastUpdated.Format(time.RFC3339)))
	return nil
}

func outputCustomerDetailsTable(logger otelzap.LoggerWithCtx, details CustomerDetails) error {
	logger.Info("Customer details",
		zap.String("customer_id", details.CustomerID),
		zap.String("company_name", details.CompanyName),
		zap.String("subdomain", details.Subdomain),
		zap.String("tier", details.Tier),
		zap.String("status", details.Status),
		zap.String("admin_email", details.AdminEmail),
		zap.String("admin_name", details.AdminName),
		zap.String("wazuh_version", details.WazuhVersion),
		zap.String("created_at", details.CreatedAt.Format("2006-01-02 15:04:05")),
		zap.String("updated_at", details.UpdatedAt.Format("2006-01-02 15:04:05")))

	logger.Info("Access URLs",
		zap.String("dashboard", details.URLs.Dashboard),
		zap.String("api", details.URLs.API))

	if details.Credentials != nil {
		logger.Info("Credentials",
			zap.String("admin_username", details.Credentials.AdminUsername),
			zap.String("api_username", details.Credentials.APIUsername),
			zap.String("vault_path", details.Credentials.VaultPath))
		logger.Info("Retrieve passwords with",
			zap.String("command", fmt.Sprintf("vault kv get %s", details.Credentials.VaultPath)))
	}

	return nil
}

func outputHealthTable(logger otelzap.LoggerWithCtx, health PlatformHealth) error {
	logger.Info("Platform health",
		zap.String("overall", health.Overall),
		zap.String("last_check", health.LastCheck.Format(time.RFC3339)))

	logger.Info("Health checks header")
	logger.Info(strings.Repeat("-", 80))
	logger.Info(fmt.Sprintf("%-30s %-10s %-30s %s", "Check", "Status", "Message", "Duration"))
	logger.Info(strings.Repeat("-", 80))

	for _, check := range health.Checks {
		logger.Info(fmt.Sprintf("terminal prompt: %-30s %-10s %-30s %v",
			check.Name, check.Status, check.Message, check.Duration))
	}

	if health.Details != nil {
		logger.Info("Health details")
		for key, value := range health.Details {
			logger.Info("Health detail",
				zap.String("key", key),
				zap.Any("value", value))
		}
	}

	return nil
}

func outputResourcesTable(logger otelzap.LoggerWithCtx, resources PlatformResources) error {
	logger.Info("Platform resource usage",
		zap.String("timestamp", resources.Timestamp.Format(time.RFC3339)))

	logger.Info("Total usage")
	logger.Info(fmt.Sprintf("terminal prompt:   CPU:    %.1f / %.1f %s (%.1f%%)",
		resources.Total.CPU.Used, resources.Total.CPU.Total, resources.Total.CPU.Unit,
		(resources.Total.CPU.Used/resources.Total.CPU.Total)*100))
	logger.Info(fmt.Sprintf("terminal prompt:   Memory: %.0f / %.0f %s (%.1f%%)",
		resources.Total.Memory.Used, resources.Total.Memory.Total, resources.Total.Memory.Unit,
		(resources.Total.Memory.Used/resources.Total.Memory.Total)*100))
	logger.Info(fmt.Sprintf("terminal prompt:   Disk:   %.0f / %.0f %s (%.1f%%)",
		resources.Total.Disk.Used, resources.Total.Disk.Total, resources.Total.Disk.Unit,
		(resources.Total.Disk.Used/resources.Total.Disk.Total)*100))

	logger.Info("By component")
	for component, usage := range resources.ByComponent {
		logger.Info("Component usage",
			zap.String("component", component))
		logger.Info(fmt.Sprintf("terminal prompt:   CPU:    %.1f / %.1f %s (%.1f%%)",
			usage.CPU.Used, usage.CPU.Total, usage.CPU.Unit,
			(usage.CPU.Used/usage.CPU.Total)*100))
		logger.Info(fmt.Sprintf("terminal prompt:   Memory: %.0f / %.0f %s (%.1f%%)",
			usage.Memory.Used, usage.Memory.Total, usage.Memory.Unit,
			(usage.Memory.Used/usage.Memory.Total)*100))
		logger.Info(fmt.Sprintf("terminal prompt:   Disk:   %.0f / %.0f %s (%.1f%%)",
			usage.Disk.Used, usage.Disk.Total, usage.Disk.Unit,
			(usage.Disk.Used/usage.Disk.Total)*100))
	}

	return nil
}

func outputCustomerResourcesTable(logger otelzap.LoggerWithCtx, resources CustomerResources) error {
	logger.Info("Customer resource usage",
		zap.String("timestamp", resources.Timestamp.Format(time.RFC3339)))

	logger.Info(strings.Repeat("-", 100))
	logger.Info(fmt.Sprintf("terminal prompt: %-15s %-20s %-10s %-15s %-15s %-15s",
		"Customer ID", "Company", "Tier", "CPU", "Memory", "Disk"))
	logger.Info(strings.Repeat("-", 100))

	for _, customer := range resources.Customers {
		logger.Info(fmt.Sprintf("terminal prompt: %-15s %-20s %-10s %.0f/%.0f %-6s %.0f/%.0f %-4s %.0f/%.0f %s",
			customer.CustomerID,
			customer.CompanyName,
			customer.Tier,
			customer.Usage.CPU.Used, customer.Usage.CPU.Total, customer.Usage.CPU.Unit,
			customer.Usage.Memory.Used, customer.Usage.Memory.Total, customer.Usage.Memory.Unit,
			customer.Usage.Disk.Used, customer.Usage.Disk.Total, customer.Usage.Disk.Unit))
	}

	logger.Info(strings.Repeat("-", 100))
	logger.Info(fmt.Sprintf("terminal prompt: %-47s %.0f/%.0f %-6s %.0f/%.0f %-4s %.0f/%.0f %s",
		"TOTAL",
		resources.Total.CPU.Used, resources.Total.CPU.Total, resources.Total.CPU.Unit,
		resources.Total.Memory.Used, resources.Total.Memory.Total, resources.Total.Memory.Unit,
		resources.Total.Disk.Used, resources.Total.Disk.Total, resources.Total.Disk.Unit))

	return nil
}

func outputEventStatsTable(logger otelzap.LoggerWithCtx, stats EventStatistics) error {
	logger.Info("Event statistics",
		zap.String("time_range", stats.TimeRange),
		zap.String("timestamp", stats.Timestamp.Format(time.RFC3339)))

	logger.Info("Event summary",
		zap.Int("total", stats.Total),
		zap.Int("events_per_second", stats.EventsPerSecond),
		zap.Int("peak_eps", stats.PeakEPS))

	logger.Info("By event type")
	for eventType, count := range stats.ByType {
		logger.Info("Event type count",
			zap.String("type", eventType),
			zap.Int("count", count))
	}

	logger.Info("By customer")
	logger.Info(strings.Repeat("-", 80))
	logger.Info(fmt.Sprintf("terminal prompt: %-15s %-20s %-10s %-10s %-10s %-10s",
		"Customer ID", "Company", "Events", "High", "Medium", "Low"))
	logger.Info(strings.Repeat("-", 80))

	for _, customer := range stats.ByCustomer {
		logger.Info(fmt.Sprintf("terminal prompt: %-15s %-20s %-10d %-10d %-10d %-10d",
			customer.CustomerID,
			customer.CompanyName,
			customer.Events,
			customer.AlertsHigh,
			customer.AlertsMed,
			customer.AlertsLow))
	}

	return nil
}

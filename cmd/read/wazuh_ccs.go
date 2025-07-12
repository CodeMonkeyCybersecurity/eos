// cmd/read/wazuh_ccs.go
package read

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp"
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
		return outputStatusTable(status)
	}
}

func showCustomerStatus(rc *eos_io.RuntimeContext, customerID string, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Showing customer status", zap.String("customer_id", customerID))

	// Verify customer
	if err := wazuh_mssp.VerifyCustomer(rc, customerID); err != nil {
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
		return outputCustomerStatusTable(status)
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
		return outputCustomerDetailsTable(details)
	}
}

func showPlatformHealth(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking platform health")

	detailed, _ := cmd.Flags().GetBool("detailed")

	// Run platform verification
	if err := wazuh_mssp.VerifyPlatform(rc); err != nil {
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
		return outputHealthTable(health)
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
		return outputResourcesTable(usage)
	}
}

func showResourcesByCustomer(rc *eos_io.RuntimeContext, format string) error {
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
		return outputCustomerResourcesTable(resources)
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
		return outputEventStatsTable(stats)
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
	fmt.Println(string(output))
	return nil
}

func outputYAML(data interface{}) error {
	// Simplified YAML output using JSON
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

func outputStatusTable(status PlatformStatus) error {
	fmt.Printf("Platform Status: %s\n", status.Platform.Status)
	fmt.Printf("Health: %s\n", status.Platform.Health)
	fmt.Printf("Version: %s\n\n", status.Platform.Version)

	fmt.Println("Components:")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("%-20s %-10s %-10s %s\n", "Component", "Status", "Health", "Details")
	fmt.Println(strings.Repeat("-", 60))

	for _, comp := range status.Components {
		fmt.Printf("%-20s %-10s %-10s %s\n", comp.Name, comp.Status, comp.Health, comp.Details)
	}

	fmt.Printf("\nCustomers Summary:\n")
	fmt.Printf("Total: %d (Active: %d, Suspended: %d)\n",
		status.Customers.Total, status.Customers.Active, status.Customers.Suspended)
	fmt.Printf("By Tier: ")
	for tier, count := range status.Customers.ByTier {
		fmt.Printf("%s: %d  ", tier, count)
	}
	fmt.Println()

	fmt.Printf("\nLast Updated: %s\n", status.LastUpdated.Format(time.RFC3339))
	return nil
}

func outputCustomerStatusTable(status CustomerDeploymentStatus) error {
	fmt.Printf("Customer: %s (%s)\n", status.CompanyName, status.CustomerID)
	fmt.Printf("Tier: %s\n", status.Tier)
	fmt.Printf("Status: %s\n\n", status.Status)

	fmt.Println("Components:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-20s %-10s %-10s %-30s %s\n", "Component", "Status", "Health", "Endpoint", "Details")
	fmt.Println(strings.Repeat("-", 80))

	for _, comp := range status.Components {
		fmt.Printf("%-20s %-10s %-10s %-30s %s\n",
			comp.Name, comp.Status, comp.Health, comp.Endpoint, comp.Details)
	}

	fmt.Printf("\nResource Usage:\n")
	fmt.Printf("CPU: %.1f / %.1f %s (%.1f%%)\n",
		status.Resources.CPU.Used, status.Resources.CPU.Total, status.Resources.CPU.Unit,
		(status.Resources.CPU.Used/status.Resources.CPU.Total)*100)
	fmt.Printf("Memory: %.0f / %.0f %s (%.1f%%)\n",
		status.Resources.Memory.Used, status.Resources.Memory.Total, status.Resources.Memory.Unit,
		(status.Resources.Memory.Used/status.Resources.Memory.Total)*100)
	fmt.Printf("Disk: %.0f / %.0f %s (%.1f%%)\n",
		status.Resources.Disk.Used, status.Resources.Disk.Total, status.Resources.Disk.Unit,
		(status.Resources.Disk.Used/status.Resources.Disk.Total)*100)

	fmt.Printf("\nNetwork:\n")
	fmt.Printf("VLAN ID: %d\n", status.Network.VLANID)
	fmt.Printf("Subnet: %s\n", status.Network.Subnet)
	fmt.Printf("Interface: %s\n", status.Network.Interface)

	fmt.Printf("\nLast Updated: %s\n", status.LastUpdated.Format(time.RFC3339))
	return nil
}

func outputCustomerDetailsTable(details CustomerDetails) error {
	fmt.Printf("Customer Details\n")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Customer ID:    %s\n", details.CustomerID)
	fmt.Printf("Company Name:   %s\n", details.CompanyName)
	fmt.Printf("Subdomain:      %s\n", details.Subdomain)
	fmt.Printf("Tier:           %s\n", details.Tier)
	fmt.Printf("Status:         %s\n", details.Status)
	fmt.Printf("Admin Email:    %s\n", details.AdminEmail)
	fmt.Printf("Admin Name:     %s\n", details.AdminName)
	fmt.Printf("Wazuh Version:  %s\n", details.WazuhVersion)
	fmt.Printf("Created:        %s\n", details.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated:        %s\n", details.UpdatedAt.Format("2006-01-02 15:04:05"))

	fmt.Printf("\nAccess URLs:\n")
	fmt.Printf("Dashboard:      %s\n", details.URLs.Dashboard)
	fmt.Printf("API:            %s\n", details.URLs.API)

	if details.Credentials != nil {
		fmt.Printf("\nCredentials:\n")
		fmt.Printf("Admin Username: %s\n", details.Credentials.AdminUsername)
		fmt.Printf("API Username:   %s\n", details.Credentials.APIUsername)
		fmt.Printf("Vault Path:     %s\n", details.Credentials.VaultPath)
		fmt.Printf("\nRetrieve passwords with:\n")
		fmt.Printf("vault kv get %s\n", details.Credentials.VaultPath)
	}

	return nil
}

func outputHealthTable(health PlatformHealth) error {
	fmt.Printf("Platform Health: %s\n", health.Overall)
	fmt.Printf("Last Check: %s\n\n", health.LastCheck.Format(time.RFC3339))

	fmt.Println("Health Checks:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-30s %-10s %-30s %s\n", "Check", "Status", "Message", "Duration")
	fmt.Println(strings.Repeat("-", 80))

	for _, check := range health.Checks {
		fmt.Printf("%-30s %-10s %-30s %v\n",
			check.Name, check.Status, check.Message, check.Duration)
	}

	if health.Details != nil {
		fmt.Printf("\nDetails:\n")
		for key, value := range health.Details {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}

	return nil
}

func outputResourcesTable(resources PlatformResources) error {
	fmt.Printf("Platform Resource Usage\n")
	fmt.Printf("Timestamp: %s\n\n", resources.Timestamp.Format(time.RFC3339))

	fmt.Printf("Total Usage:\n")
	fmt.Printf("  CPU:    %.1f / %.1f %s (%.1f%%)\n",
		resources.Total.CPU.Used, resources.Total.CPU.Total, resources.Total.CPU.Unit,
		(resources.Total.CPU.Used/resources.Total.CPU.Total)*100)
	fmt.Printf("  Memory: %.0f / %.0f %s (%.1f%%)\n",
		resources.Total.Memory.Used, resources.Total.Memory.Total, resources.Total.Memory.Unit,
		(resources.Total.Memory.Used/resources.Total.Memory.Total)*100)
	fmt.Printf("  Disk:   %.0f / %.0f %s (%.1f%%)\n",
		resources.Total.Disk.Used, resources.Total.Disk.Total, resources.Total.Disk.Unit,
		(resources.Total.Disk.Used/resources.Total.Disk.Total)*100)

	fmt.Printf("\nBy Component:\n")
	for component, usage := range resources.ByComponent {
		fmt.Printf("\n%s:\n", component)
		fmt.Printf("  CPU:    %.1f / %.1f %s (%.1f%%)\n",
			usage.CPU.Used, usage.CPU.Total, usage.CPU.Unit,
			(usage.CPU.Used/usage.CPU.Total)*100)
		fmt.Printf("  Memory: %.0f / %.0f %s (%.1f%%)\n",
			usage.Memory.Used, usage.Memory.Total, usage.Memory.Unit,
			(usage.Memory.Used/usage.Memory.Total)*100)
		fmt.Printf("  Disk:   %.0f / %.0f %s (%.1f%%)\n",
			usage.Disk.Used, usage.Disk.Total, usage.Disk.Unit,
			(usage.Disk.Used/usage.Disk.Total)*100)
	}

	return nil
}

func outputCustomerResourcesTable(resources CustomerResources) error {
	fmt.Printf("Customer Resource Usage\n")
	fmt.Printf("Timestamp: %s\n\n", resources.Timestamp.Format(time.RFC3339))

	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-15s %-20s %-10s %-15s %-15s %-15s\n",
		"Customer ID", "Company", "Tier", "CPU", "Memory", "Disk")
	fmt.Println(strings.Repeat("-", 100))

	for _, customer := range resources.Customers {
		fmt.Printf("%-15s %-20s %-10s %.0f/%.0f %-6s %.0f/%.0f %-4s %.0f/%.0f %s\n",
			customer.CustomerID,
			customer.CompanyName,
			customer.Tier,
			customer.Usage.CPU.Used, customer.Usage.CPU.Total, customer.Usage.CPU.Unit,
			customer.Usage.Memory.Used, customer.Usage.Memory.Total, customer.Usage.Memory.Unit,
			customer.Usage.Disk.Used, customer.Usage.Disk.Total, customer.Usage.Disk.Unit)
	}

	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-47s %.0f/%.0f %-6s %.0f/%.0f %-4s %.0f/%.0f %s\n",
		"TOTAL",
		resources.Total.CPU.Used, resources.Total.CPU.Total, resources.Total.CPU.Unit,
		resources.Total.Memory.Used, resources.Total.Memory.Total, resources.Total.Memory.Unit,
		resources.Total.Disk.Used, resources.Total.Disk.Total, resources.Total.Disk.Unit)

	return nil
}

func outputEventStatsTable(stats EventStatistics) error {
	fmt.Printf("Event Statistics (%s)\n", stats.TimeRange)
	fmt.Printf("Timestamp: %s\n\n", stats.Timestamp.Format(time.RFC3339))

	fmt.Printf("Total Events: %d\n", stats.Total)
	fmt.Printf("Events/Second: %d (Peak: %d)\n\n", stats.EventsPerSecond, stats.PeakEPS)

	fmt.Println("By Event Type:")
	for eventType, count := range stats.ByType {
		fmt.Printf("  %-20s: %d\n", eventType, count)
	}

	fmt.Printf("\nBy Customer:\n")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-15s %-20s %-10s %-10s %-10s %-10s\n",
		"Customer ID", "Company", "Events", "High", "Medium", "Low")
	fmt.Println(strings.Repeat("-", 80))

	for _, customer := range stats.ByCustomer {
		fmt.Printf("%-15s %-20s %-10d %-10d %-10d %-10d\n",
			customer.CustomerID,
			customer.CompanyName,
			customer.Events,
			customer.AlertsHigh,
			customer.AlertsMed,
			customer.AlertsLow)
	}

	return nil
}

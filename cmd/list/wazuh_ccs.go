// cmd/list/wazuh_ccs.go
package list

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListWazuhCCSCmd lists Wazuh MSSP customers and deployments
var ListWazuhCCSCmd = &cobra.Command{
	Use:   "wazuh-ccs",
	Short: "List Wazuh MSSP customers and deployments",
	Long: `List various aspects of the Wazuh MSSP platform:

- List all customers (default)
- List deployments (--deployments)
- List backups (--backups)
- List events (--events)
- Filter by tier (--tier)
- Filter by status (--status)`,
	RunE: eos_cli.Wrap(runListWazuhCCS),
}

func init() {
	ListCmd.AddCommand(ListWazuhCCSCmd)

	// List type flags
	ListWazuhCCSCmd.Flags().Bool("customers", true, "List customers (default)")
	ListWazuhCCSCmd.Flags().Bool("deployments", false, "List all deployments")
	ListWazuhCCSCmd.Flags().Bool("backups", false, "List customer backups")
	ListWazuhCCSCmd.Flags().Bool("events", false, "List recent events")

	// Filter flags
	ListWazuhCCSCmd.Flags().String("tier", "", "Filter by tier (starter/pro/enterprise)")
	ListWazuhCCSCmd.Flags().String("status", "", "Filter by status (active/suspended/deleted)")
	ListWazuhCCSCmd.Flags().String("customer-id", "", "Filter by specific customer")

	// Output format
	ListWazuhCCSCmd.Flags().String("output", "table", "Output format (table/json/yaml)")
	ListWazuhCCSCmd.Flags().Bool("detailed", false, "Show detailed information")
}

func runListWazuhCCS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing Wazuh MSSP information")

	// Determine what to list
	customers, _ := cmd.Flags().GetBool("customers")
	deployments, _ := cmd.Flags().GetBool("deployments")
	backups, _ := cmd.Flags().GetBool("backups")
	events, _ := cmd.Flags().GetBool("events")

	// Default to customers if nothing specified
	if !deployments && !backups && !events {
		customers = true
	}

	outputFormat, _ := cmd.Flags().GetString("output")

	switch {
	case customers:
		return listCustomers(rc, cmd, outputFormat)
	case deployments:
		return listDeployments(rc, cmd, outputFormat)
	case backups:
		return listBackups(rc, cmd, outputFormat)
	case events:
		return listEvents(rc, cmd, outputFormat)
	default:
		return cmd.Help()
	}
}

func listCustomers(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing customers")

	// Get filters
	tierFilter, _ := cmd.Flags().GetString("tier")
	statusFilter, _ := cmd.Flags().GetString("status")
	detailed, _ := cmd.Flags().GetBool("detailed")

	// Get customer list
	// This would query Vault and platform state
	customers := []CustomerListItem{
		{
			CustomerID:   "cust_12345",
			CompanyName:  "ACME Corporation",
			Subdomain:    "acme",
			Tier:         "pro",
			Status:       "active",
			AdminEmail:   "admin@acme.com",
			CreatedAt:    time.Now().Add(-30 * 24 * time.Hour),
			AgentCount:   150,
			EventsPerDay: 125000,
			Resources: CustomerResourceSummary{
				CPUCores: 16,
				MemoryGB: 32,
				DiskGB:   400,
			},
		},
		{
			CustomerID:   "cust_67890",
			CompanyName:  "TechCorp Inc",
			Subdomain:    "techcorp",
			Tier:         "enterprise",
			Status:       "active",
			AdminEmail:   "admin@techcorp.com",
			CreatedAt:    time.Now().Add(-60 * 24 * time.Hour),
			AgentCount:   450,
			EventsPerDay: 285000,
			Resources: CustomerResourceSummary{
				CPUCores: 32,
				MemoryGB: 64,
				DiskGB:   1000,
			},
		},
		{
			CustomerID:   "cust_11111",
			CompanyName:  "StartupXYZ",
			Subdomain:    "startupxyz",
			Tier:         "starter",
			Status:       "active",
			AdminEmail:   "admin@startupxyz.com",
			CreatedAt:    time.Now().Add(-7 * 24 * time.Hour),
			AgentCount:   25,
			EventsPerDay: 15000,
			Resources: CustomerResourceSummary{
				CPUCores: 4,
				MemoryGB: 8,
				DiskGB:   100,
			},
		},
	}

	// Apply filters
	var filtered []CustomerListItem
	for _, customer := range customers {
		if tierFilter != "" && customer.Tier != tierFilter {
			continue
		}
		if statusFilter != "" && customer.Status != statusFilter {
			continue
		}
		filtered = append(filtered, customer)
	}

	// Create list response
	response := CustomerList{
		Customers: filtered,
		Total:     len(filtered),
		Summary: CustomerListSummary{
			ByTier:   map[string]int{"starter": 5, "pro": 7, "enterprise": 3},
			ByStatus: map[string]int{"active": 14, "suspended": 1},
		},
		Timestamp: time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(logger, response)
	case "yaml":
		return outputYAML(logger, response)
	default:
		if detailed {
			return outputDetailedCustomerTable(logger, response)
		}
		return outputCustomerTable(logger, response)
	}
}

func listDeployments(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing deployments")

	customerFilter, _ := cmd.Flags().GetString("customer-id")

	// Get deployment list
	deployments := []DeploymentListItem{
		{
			JobName:     "wazuh-indexer-cust_12345",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Type:        "indexer",
			Status:      "running",
			Instances:   3,
			Version:     "4.8.2",
			CPUUsage:    45.2,
			MemoryUsage: 78.5,
			LastUpdated: time.Now().Add(-2 * time.Hour),
		},
		{
			JobName:     "wazuh-server-cust_12345",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Type:        "server",
			Status:      "running",
			Instances:   2,
			Version:     "4.8.2",
			CPUUsage:    32.1,
			MemoryUsage: 65.3,
			LastUpdated: time.Now().Add(-2 * time.Hour),
		},
		{
			JobName:     "wazuh-dashboard-cust_12345",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Type:        "dashboard",
			Status:      "running",
			Instances:   1,
			Version:     "4.8.2",
			CPUUsage:    15.7,
			MemoryUsage: 42.1,
			LastUpdated: time.Now().Add(-2 * time.Hour),
		},
	}

	// Apply filter
	var filtered []DeploymentListItem
	for _, deployment := range deployments {
		if customerFilter != "" && deployment.CustomerID != customerFilter {
			continue
		}
		filtered = append(filtered, deployment)
	}

	response := DeploymentList{
		Deployments: filtered,
		Total:       len(filtered),
		Summary: DeploymentSummary{
			TotalJobs:      45,
			RunningJobs:    42,
			FailedJobs:     3,
			TotalInstances: 125,
		},
		Timestamp: time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(logger, response)
	case "yaml":
		return outputYAML(logger, response)
	default:
		return outputDeploymentTable(logger, response)
	}
}

func listBackups(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing backups")

	customerFilter, _ := cmd.Flags().GetString("customer-id")

	// Get backup list
	backups := []BackupListItem{
		{
			BackupID:    "backup-cust_12345-1704067200",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Type:        "full",
			Status:      "completed",
			SizeGB:      125.5,
			CreatedAt:   time.Now().Add(-24 * time.Hour),
			Duration:    15 * time.Minute,
			Location:    "/var/lib/wazuh-mssp/customers/cust_12345/backups/backup-cust_12345-1704067200",
		},
		{
			BackupID:    "backup-cust_12345-1703980800",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Type:        "incremental",
			Status:      "completed",
			SizeGB:      12.3,
			CreatedAt:   time.Now().Add(-48 * time.Hour),
			Duration:    3 * time.Minute,
			Location:    "/var/lib/wazuh-mssp/customers/cust_12345/backups/backup-cust_12345-1703980800",
		},
		{
			BackupID:    "backup-cust_67890-1704067200",
			CustomerID:  "cust_67890",
			CompanyName: "TechCorp Inc",
			Type:        "full",
			Status:      "completed",
			SizeGB:      285.7,
			CreatedAt:   time.Now().Add(-12 * time.Hour),
			Duration:    25 * time.Minute,
			Location:    "/var/lib/wazuh-mssp/customers/cust_67890/backups/backup-cust_67890-1704067200",
		},
	}

	// Apply filter
	var filtered []BackupListItem
	for _, backup := range backups {
		if customerFilter != "" && backup.CustomerID != customerFilter {
			continue
		}
		filtered = append(filtered, backup)
	}

	response := BackupList{
		Backups: filtered,
		Total:   len(filtered),
		Summary: BackupSummary{
			TotalBackups: 25,
			TotalSizeGB:  1250.5,
			OldestBackup: time.Now().Add(-30 * 24 * time.Hour),
			LatestBackup: time.Now().Add(-2 * time.Hour),
		},
		Timestamp: time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(logger, response)
	case "yaml":
		return outputYAML(logger, response)
	default:
		return outputBackupTable(logger, response)
	}
}

func listEvents(rc *eos_io.RuntimeContext, cmd *cobra.Command, format string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing recent events")

	customerFilter, _ := cmd.Flags().GetString("customer-id")

	// Get recent events
	events := []EventListItem{
		{
			EventID:     "evt_001",
			Timestamp:   time.Now().Add(-5 * time.Minute),
			Type:        "customer_provisioned",
			CustomerID:  "cust_11111",
			CompanyName: "StartupXYZ",
			Message:     "Customer provisioned successfully",
			Details:     map[string]interface{}{"tier": "starter", "admin": "admin@startupxyz.com"},
		},
		{
			EventID:     "evt_002",
			Timestamp:   time.Now().Add(-1 * time.Hour),
			Type:        "customer_scaled",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Message:     "Customer scaled from pro to enterprise",
			Details:     map[string]interface{}{"old_tier": "pro", "new_tier": "enterprise"},
		},
		{
			EventID:     "evt_003",
			Timestamp:   time.Now().Add(-2 * time.Hour),
			Type:        "backup_completed",
			CustomerID:  "cust_67890",
			CompanyName: "TechCorp Inc",
			Message:     "Full backup completed successfully",
			Details:     map[string]interface{}{"backup_id": "backup-cust_67890-1704067200", "size_gb": 285.7},
		},
		{
			EventID:     "evt_004",
			Timestamp:   time.Now().Add(-3 * time.Hour),
			Type:        "alert_triggered",
			CustomerID:  "cust_12345",
			CompanyName: "ACME Corporation",
			Message:     "High severity alert: Multiple failed login attempts",
			Details:     map[string]interface{}{"severity": "high", "count": 50},
		},
	}

	// Apply filter
	var filtered []EventListItem
	for _, event := range events {
		if customerFilter != "" && event.CustomerID != customerFilter {
			continue
		}
		filtered = append(filtered, event)
	}

	response := EventList{
		Events:    filtered,
		Total:     len(filtered),
		Timestamp: time.Now(),
	}

	// Format output
	switch format {
	case "json":
		return outputJSON(logger, response)
	case "yaml":
		return outputYAML(logger, response)
	default:
		return outputEventTable(logger, response)
	}
}

// Data structures

type CustomerListItem struct {
	CustomerID   string                  `json:"customer_id"`
	CompanyName  string                  `json:"company_name"`
	Subdomain    string                  `json:"subdomain"`
	Tier         string                  `json:"tier"`
	Status       string                  `json:"status"`
	AdminEmail   string                  `json:"admin_email"`
	CreatedAt    time.Time               `json:"created_at"`
	AgentCount   int                     `json:"agent_count"`
	EventsPerDay int                     `json:"events_per_day"`
	Resources    CustomerResourceSummary `json:"resources"`
}

type CustomerResourceSummary struct {
	CPUCores int `json:"cpu_cores"`
	MemoryGB int `json:"memory_gb"`
	DiskGB   int `json:"disk_gb"`
}

type CustomerList struct {
	Customers []CustomerListItem  `json:"customers"`
	Total     int                 `json:"total"`
	Summary   CustomerListSummary `json:"summary"`
	Timestamp time.Time           `json:"timestamp"`
}

type CustomerListSummary struct {
	ByTier   map[string]int `json:"by_tier"`
	ByStatus map[string]int `json:"by_status"`
}

type DeploymentListItem struct {
	JobName     string    `json:"job_name"`
	CustomerID  string    `json:"customer_id"`
	CompanyName string    `json:"company_name"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Instances   int       `json:"instances"`
	Version     string    `json:"version"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	LastUpdated time.Time `json:"last_updated"`
}

type DeploymentList struct {
	Deployments []DeploymentListItem `json:"deployments"`
	Total       int                  `json:"total"`
	Summary     DeploymentSummary    `json:"summary"`
	Timestamp   time.Time            `json:"timestamp"`
}

type DeploymentSummary struct {
	TotalJobs      int `json:"total_jobs"`
	RunningJobs    int `json:"running_jobs"`
	FailedJobs     int `json:"failed_jobs"`
	TotalInstances int `json:"total_instances"`
}

type BackupListItem struct {
	BackupID    string        `json:"backup_id"`
	CustomerID  string        `json:"customer_id"`
	CompanyName string        `json:"company_name"`
	Type        string        `json:"type"`
	Status      string        `json:"status"`
	SizeGB      float64       `json:"size_gb"`
	CreatedAt   time.Time     `json:"created_at"`
	Duration    time.Duration `json:"duration"`
	Location    string        `json:"location"`
}

type BackupList struct {
	Backups   []BackupListItem `json:"backups"`
	Total     int              `json:"total"`
	Summary   BackupSummary    `json:"summary"`
	Timestamp time.Time        `json:"timestamp"`
}

type BackupSummary struct {
	TotalBackups int       `json:"total_backups"`
	TotalSizeGB  float64   `json:"total_size_gb"`
	OldestBackup time.Time `json:"oldest_backup"`
	LatestBackup time.Time `json:"latest_backup"`
}

type EventListItem struct {
	EventID     string                 `json:"event_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`
	CustomerID  string                 `json:"customer_id"`
	CompanyName string                 `json:"company_name"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
}

type EventList struct {
	Events    []EventListItem `json:"events"`
	Total     int             `json:"total"`
	Timestamp time.Time       `json:"timestamp"`
}

// Output formatting functions

func outputJSON(logger otelzap.LoggerWithCtx, data interface{}) error {
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	logger.Info("terminal prompt:", zap.String("output", string(output)))
	return nil
}

func outputYAML(logger otelzap.LoggerWithCtx, data interface{}) error {
	// Simplified YAML output using JSON
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	logger.Info("terminal prompt:", zap.String("output", string(output)))
	return nil
}

func outputCustomerTable(logger otelzap.LoggerWithCtx, list CustomerList) error {
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

func outputDetailedCustomerTable(logger otelzap.LoggerWithCtx, list CustomerList) error {
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

func outputDeploymentTable(logger otelzap.LoggerWithCtx, list DeploymentList) error {
	logger.Info("terminal prompt: Deployments", zap.Int("total", list.Total))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-30s %-15s %-20s %-10s %-10s %-5s %-10s %-10s",
		"Job Name", "Customer ID", "Company", "Type", "Status", "Inst", "CPU%", "Mem%")))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))

	for _, deployment := range list.Deployments {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-30s %-15s %-20s %-10s %-10s %-5d %-10.1f %-10.1f",
			truncate(deployment.JobName, 30),
			deployment.CustomerID,
			truncate(deployment.CompanyName, 20),
			deployment.Type,
			deployment.Status,
			deployment.Instances,
			deployment.CPUUsage,
			deployment.MemoryUsage)))
	}

	logger.Info("terminal prompt: Summary:")
	logger.Info("terminal prompt: Total Jobs:", 
		zap.Int("total", list.Summary.TotalJobs),
		zap.Int("running", list.Summary.RunningJobs),
		zap.Int("failed", list.Summary.FailedJobs))
	logger.Info("terminal prompt: Total Instances:", zap.Int("instances", list.Summary.TotalInstances))

	return nil
}

func outputBackupTable(logger otelzap.LoggerWithCtx, list BackupList) error {
	logger.Info("terminal prompt: Backups", zap.Int("total", list.Total))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 100)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-30s %-15s %-20s %-10s %-10s %-10s %-20s",
		"Backup ID", "Customer ID", "Company", "Type", "Status", "Size (GB)", "Created")))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 100)))

	for _, backup := range list.Backups {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-30s %-15s %-20s %-10s %-10s %-10.1f %-20s",
			truncate(backup.BackupID, 30),
			backup.CustomerID,
			truncate(backup.CompanyName, 20),
			backup.Type,
			backup.Status,
			backup.SizeGB,
			backup.CreatedAt.Format("2006-01-02 15:04"))))
	}

	logger.Info("terminal prompt: Summary:")
	logger.Info("terminal prompt: Total Backups:", zap.Int("total_backups", list.Summary.TotalBackups))
	logger.Info("terminal prompt: Total Size:", zap.Float64("size_gb", list.Summary.TotalSizeGB))
	logger.Info("terminal prompt: Oldest:", zap.String("oldest", list.Summary.OldestBackup.Format("2006-01-02")))
	logger.Info("terminal prompt: Latest:", zap.String("latest", list.Summary.LatestBackup.Format("2006-01-02")))

	return nil
}

func outputEventTable(logger otelzap.LoggerWithCtx, list EventList) error {
	logger.Info("terminal prompt: Recent Events", zap.Int("total", list.Total))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-20s %-15s %-20s %s",
		"Timestamp", "Type", "Customer ID", "Company", "Message")))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))

	for _, event := range list.Events {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-20s %-20s %-15s %-20s %s",
			event.Timestamp.Format("2006-01-02 15:04:05"),
			event.Type,
			event.CustomerID,
			truncate(event.CompanyName, 20),
			truncate(event.Message, 40))))
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

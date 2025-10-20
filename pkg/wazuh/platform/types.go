// Package platform provides Wazuh MSSP platform status and management functionality.
package platform

import "time"

// PlatformStatus represents the overall status of the Wazuh MSSP platform.
type PlatformStatus struct {
	Platform   ComponentStatus     `json:"platform"`
	Components []ComponentStatus   `json:"components"`
	Customers  CustomersSummary    `json:"customers"`
	Timestamp  time.Time           `json:"timestamp"`
}

// ComponentStatus represents the status of a platform component.
type ComponentStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Health  string `json:"health"`
	Version string `json:"version,omitempty"`
	Details string `json:"details,omitempty"`
}

// CustomersSummary provides a summary of customer statistics.
type CustomersSummary struct {
	Total     int `json:"total"`
	Active    int `json:"active"`
	Suspended int `json:"suspended"`
	Deleted   int `json:"deleted"`
}

// CustomerDeploymentStatus represents the deployment status of a specific customer.
type CustomerDeploymentStatus struct {
	CustomerID  string            `json:"customer_id"`
	CompanyName string            `json:"company_name"`
	Tier        string            `json:"tier"`
	Status      string            `json:"status"`
	Components  []ComponentStatus `json:"components"`
	Resources   ResourceUsage     `json:"resources"`
	Network     NetworkInfo       `json:"network"`
	Timestamp   time.Time         `json:"timestamp"`
}

// ResourceUsage represents resource utilization metrics.
type ResourceUsage struct {
	CPU    ResourceMetric `json:"cpu"`
	Memory ResourceMetric `json:"memory"`
	Disk   ResourceMetric `json:"disk"`
}

// ResourceMetric represents a specific resource metric.
type ResourceMetric struct {
	Used  string `json:"used"`
	Total string `json:"total"`
	Percent float64 `json:"percent"`
}

// NetworkInfo contains network configuration details.
type NetworkInfo struct {
	VLAN    int    `json:"vlan"`
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
}

// CustomerDetails contains detailed information about a customer.
type CustomerDetails struct {
	CustomerID  string               `json:"customer_id"`
	CompanyName string               `json:"company_name"`
	AdminName   string               `json:"admin_name"`
	AdminEmail  string               `json:"admin_email"`
	Tier        string               `json:"tier"`
	Status      string               `json:"status"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	URLs        CustomerURLs         `json:"urls"`
	Credentials *CustomerCredentials `json:"credentials,omitempty"`
	Network     NetworkInfo          `json:"network"`
}

// CustomerURLs contains customer access URLs.
type CustomerURLs struct {
	Dashboard string `json:"dashboard"`
	API       string `json:"api"`
}

// CustomerCredentials contains customer credentials (sensitive).
type CustomerCredentials struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"` // Omitted unless explicitly requested
}

// PlatformHealth represents overall platform health status.
type PlatformHealth struct {
	Overall string        `json:"overall"`
	Checks  []HealthCheck `json:"checks"`
	Issues  int           `json:"issues"`
	Timestamp time.Time   `json:"timestamp"`
}

// HealthCheck represents an individual health check result.
type HealthCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// PlatformResources represents aggregated resource usage across the platform.
type PlatformResources struct {
	Total     ResourceUsage           `json:"total"`
	Available ResourceUsage           `json:"available"`
	Customers []CustomerResourceUsage `json:"customers,omitempty"`
}

// CustomerResources represents resources grouped by customer.
type CustomerResources struct {
	Customers []CustomerResourceUsage `json:"customers"`
	Timestamp time.Time               `json:"timestamp"`
}

// CustomerResourceUsage represents resource usage for a specific customer.
type CustomerResourceUsage struct {
	CustomerID  string        `json:"customer_id"`
	CompanyName string        `json:"company_name"`
	Resources   ResourceUsage `json:"resources"`
}

// EventStatistics represents event statistics for the platform.
type EventStatistics struct {
	TimeRange  string               `json:"time_range"`
	Total      int64                `json:"total"`
	PerSecond  float64              `json:"per_second"`
	PerMinute  float64              `json:"per_minute"`
	PerHour    float64              `json:"per_hour"`
	ByCustomer []CustomerEventStats `json:"by_customer,omitempty"`
	Timestamp  time.Time            `json:"timestamp"`
}

// CustomerEventStats represents event statistics for a specific customer.
type CustomerEventStats struct {
	CustomerID  string  `json:"customer_id"`
	CompanyName string  `json:"company_name"`
	EventCount  int64   `json:"event_count"`
	PerSecond   float64 `json:"per_second"`
}

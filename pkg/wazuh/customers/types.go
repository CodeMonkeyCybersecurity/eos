// Package customers provides Wazuh MSSP customer management functionality.
package customers

import "time"

// CustomerListItem represents a single customer in the MSSP platform.
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

// CustomerResourceSummary represents resource allocation for a customer.
type CustomerResourceSummary struct {
	CPUCores int `json:"cpu_cores"`
	MemoryGB int `json:"memory_gb"`
	DiskGB   int `json:"disk_gb"`
}

// CustomerList represents a list of customers with summary information.
type CustomerList struct {
	Customers []CustomerListItem  `json:"customers"`
	Total     int                 `json:"total"`
	Summary   CustomerListSummary `json:"summary"`
	Timestamp time.Time           `json:"timestamp"`
}

// CustomerListSummary provides summary statistics for customers.
type CustomerListSummary struct {
	ByTier   map[string]int `json:"by_tier"`
	ByStatus map[string]int `json:"by_status"`
}

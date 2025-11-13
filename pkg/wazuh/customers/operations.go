package customers

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListOptions contains options for listing customers.
type ListOptions struct {
	TierFilter   string
	StatusFilter string
	Detailed     bool
}

// ListCustomers retrieves and filters the list of MSSP customers.
// This function contains the business logic for listing customers and applying filters.
//
// TODO: Replace mock data with actual Vault and platform state queries.
func ListCustomers(rc *eos_io.RuntimeContext, opts ListOptions) (CustomerList, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing customers",
		zap.String("tier_filter", opts.TierFilter),
		zap.String("status_filter", opts.StatusFilter))

	// Get customer list
	// TODO: Replace with actual Vault and platform state queries
	customers := getMockCustomers()

	// Apply filters
	var filtered []CustomerListItem
	for _, customer := range customers {
		if opts.TierFilter != "" && customer.Tier != opts.TierFilter {
			continue
		}
		if opts.StatusFilter != "" && customer.Status != opts.StatusFilter {
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

	return response, nil
}

// getMockCustomers returns mock customer data for development/testing.
// TODO: Replace with actual data source queries (Vault, Consul, database).
func getMockCustomers() []CustomerListItem {
	return []CustomerListItem{
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
}

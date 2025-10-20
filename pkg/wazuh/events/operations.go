package events

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListOptions contains options for listing events.
type ListOptions struct {
	CustomerFilter string
}

// ListEvents retrieves and filters recent platform events.
// TODO: Replace mock data with actual event log queries.
func ListEvents(rc *eos_io.RuntimeContext, opts ListOptions) (EventList, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing recent events", zap.String("customer_filter", opts.CustomerFilter))

	// Get recent events
	// TODO: Replace with actual event log queries
	events := getMockEvents()

	// Apply filter
	var filtered []EventListItem
	for _, event := range events {
		if opts.CustomerFilter != "" && event.CustomerID != opts.CustomerFilter {
			continue
		}
		filtered = append(filtered, event)
	}

	response := EventList{
		Events:    filtered,
		Total:     len(filtered),
		Timestamp: time.Now(),
	}

	return response, nil
}

// getMockEvents returns mock event data.
// TODO: Replace with actual event log queries.
func getMockEvents() []EventListItem {
	return []EventListItem{
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
}

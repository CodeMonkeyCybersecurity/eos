package backups

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListOptions contains options for listing backups.
type ListOptions struct {
	CustomerFilter string
}

// ListBackups retrieves and filters the list of customer backups.
// TODO: Replace mock data with actual backup storage queries.
func ListBackups(rc *eos_io.RuntimeContext, opts ListOptions) (BackupList, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing backups", zap.String("customer_filter", opts.CustomerFilter))

	// Get backup list
	// TODO: Replace with actual backup storage queries
	backups := getMockBackups()

	// Apply filter
	var filtered []BackupListItem
	for _, backup := range backups {
		if opts.CustomerFilter != "" && backup.CustomerID != opts.CustomerFilter {
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

	return response, nil
}

// getMockBackups returns mock backup data.
// TODO: Replace with actual backup storage queries.
func getMockBackups() []BackupListItem {
	return []BackupListItem{
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
}

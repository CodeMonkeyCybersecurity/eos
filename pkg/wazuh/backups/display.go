package backups

import (
	"fmt"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OutputBackupTable formats and displays backup list as a table.
func OutputBackupTable(logger otelzap.LoggerWithCtx, list BackupList) error {
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

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

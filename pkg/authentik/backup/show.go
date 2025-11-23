// pkg/authentik/backup/show.go
package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Show displays detailed information about a specific backup
// ASSESS → INTERVENE → EVALUATE pattern
func Show(rc *eos_io.RuntimeContext, config *ShowConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	var targetFile string

	// ASSESS - Determine which backup to show
	if config.BackupFile != "" {
		targetFile = config.BackupFile
	} else if config.Latest {
		// Find latest backup
		entries, err := os.ReadDir(config.BackupDir)
		if err != nil {
			return fmt.Errorf("failed to read backup directory: %w", err)
		}

		var latestTime time.Time
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "authentik-backup-") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			if info.ModTime().After(latestTime) {
				latestTime = info.ModTime()
				targetFile = filepath.Join(config.BackupDir, entry.Name())
			}
		}

		if targetFile == "" {
			logger.Info("No backups found", zap.String("directory", config.BackupDir))
			return nil
		}
	} else {
		return fmt.Errorf("please specify a backup file or use --latest flag")
	}

	// INTERVENE - Parse backup file
	backup, err := ParseBackupFile(targetFile)
	if err != nil {
		return fmt.Errorf("failed to parse backup: %w", err)
	}

	// EVALUATE - Display detailed information
	totalResources := backup.Providers + backup.Applications + backup.PropertyMappings +
		backup.Flows + backup.Stages + backup.Groups + backup.Policies +
		backup.Certificates + backup.Blueprints + backup.Outposts + backup.Tenants

	logger.Info("Authentik Backup Details",
		zap.String("file", backup.Path),
		zap.String("created", backup.ModTime.Format("2006-01-02 15:04:05")),
		zap.Int64("size_bytes", backup.Size),
		zap.String("source_url", backup.SourceURL),
		zap.String("version", backup.AuthentikVersion))

	logger.Info("Resource Counts",
		zap.Int("providers", backup.Providers),
		zap.Int("applications", backup.Applications),
		zap.Int("property_mappings", backup.PropertyMappings),
		zap.Int("flows", backup.Flows),
		zap.Int("stages", backup.Stages),
		zap.Int("groups", backup.Groups),
		zap.Int("policies", backup.Policies),
		zap.Int("certificates", backup.Certificates),
		zap.Int("blueprints", backup.Blueprints),
		zap.Int("outposts", backup.Outposts),
		zap.Int("tenants", backup.Tenants),
		zap.Int("total", totalResources))

	logger.Info("Restore this backup with: eos backup authentik restore " + backup.Path + " (coming soon)")
	return nil
}

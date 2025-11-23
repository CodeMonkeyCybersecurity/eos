// pkg/authentik/backup/list.go
package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// List displays all available Authentik backups
// ASSESS → INTERVENE → EVALUATE pattern
func List(rc *eos_io.RuntimeContext, config *ListConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	backupDir := config.BackupDir

	// ASSESS - Check if backup directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		logger.Warn("Backup directory does not exist",
			zap.String("directory", backupDir))
		logger.Info("To create first backup, run: eos backup authentik")
		return nil
	}

	// INTERVENE - Find all backup files
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	backups := []BackupFileInfo{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "authentik-backup-") {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		fullPath := filepath.Join(backupDir, entry.Name())
		info, err := ParseBackupFile(fullPath)
		if err != nil {
			logger.Warn("Failed to parse backup file",
				zap.String("file", entry.Name()),
				zap.Error(err))
			continue
		}
		backups = append(backups, info)
	}

	if len(backups) == 0 {
		logger.Info("No Authentik backups found",
			zap.String("directory", backupDir))
		logger.Info("To create first backup, run: eos backup authentik")
		return nil
	}

	// Sort by modification time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].ModTime.After(backups[j].ModTime)
	})

	// EVALUATE - Display list
	logger.Info("Authentik Backups Found",
		zap.Int("total_backups", len(backups)),
		zap.String("directory", backupDir))

	for i, backup := range backups {
		sizeKB := backup.Size / 1024
		totalResources := backup.Providers + backup.Applications + backup.PropertyMappings +
			backup.Flows + backup.Stages + backup.Groups + backup.Policies +
			backup.Certificates + backup.Blueprints + backup.Outposts + backup.Tenants

		logger.Info(fmt.Sprintf("Backup %d", i+1),
			zap.String("file", filepath.Base(backup.Path)),
			zap.String("created", backup.ModTime.Format("2006-01-02 15:04")),
			zap.Int64("size_kb", sizeKB),
			zap.String("source", backup.SourceURL),
			zap.Int("resources", totalResources))
	}

	logger.Info("View details with: eos backup authentik show --latest")
	return nil
}

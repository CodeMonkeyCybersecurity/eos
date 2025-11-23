// pkg/authentik/backup/restore.go
package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Restore restores an Authentik configuration from a backup file
// ASSESS → INTERVENE → EVALUATE pattern
func Restore(rc *eos_io.RuntimeContext, config *RestoreConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate restore configuration
	if config.URL == "" || config.Token == "" {
		return eos_err.NewUserError("--url and --token are required for restore")
	}

	// Auto-add https:// if missing
	url := config.URL
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
		logger.Info("Added https:// prefix to URL", zap.String("url", url))
	}

	// Load backup file
	logger.Info("Loading backup file", zap.String("file", config.BackupFile))
	backupData, err := os.ReadFile(config.BackupFile)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	var backup authentik.AuthentikConfig
	if strings.HasSuffix(config.BackupFile, ".json") {
		err = json.Unmarshal(backupData, &backup)
	} else {
		err = yaml.Unmarshal(backupData, &backup)
	}
	if err != nil {
		return fmt.Errorf("failed to parse backup file: %w", err)
	}

	logger.Info("Backup loaded successfully",
		zap.String("source", backup.Metadata.SourceURL),
		zap.String("version", backup.Metadata.AuthentikVersion),
		zap.Time("exported", backup.Metadata.ExportedAt),
		zap.Int("providers", len(backup.Providers)),
		zap.Int("applications", len(backup.Applications)))

	if config.DryRun {
		logger.Info("DRY RUN MODE - No changes will be made")
	}

	// INTERVENE - Create pre-restore backup if requested
	if config.CreateBackup && !config.DryRun {
		logger.Info("Creating pre-restore backup")
		preBackupFile := fmt.Sprintf("/mnt/eos-backups/authentik/pre-restore-%s.yaml",
			time.Now().Format("20060102-150405"))

		types := []string{"providers", "applications", "mappings", "flows",
			"stages", "groups", "policies", "certificates", "blueprints", "outposts", "tenants"}

		preBackupConfig, err := authentik.ExtractConfigurationAPI(rc.Ctx, url, config.Token, types, nil, nil, false)
		if err != nil {
			logger.Warn("Failed to create pre-restore backup", zap.Error(err))
		} else {
			preBackupData, _ := yaml.Marshal(preBackupConfig)
			if err := os.WriteFile(preBackupFile, preBackupData, shared.SecretFilePerm); err != nil {
				logger.Warn("Failed to save pre-restore backup", zap.Error(err))
			} else {
				logger.Info("Pre-restore backup created", zap.String("file", preBackupFile))
			}
		}
	}

	// EVALUATE - For now, log what would be restored and provide next steps
	logger.Info("Restore functionality is being implemented",
		zap.String("status", "coming_soon"),
		zap.String("backup_file", config.BackupFile),
		zap.String("target_url", url),
		zap.Bool("dry_run", config.DryRun),
		zap.Bool("skip_existing", config.SkipExisting),
		zap.Bool("update_existing", config.UpdateExisting),
		zap.Strings("only_types", config.OnlyTypes),
		zap.Strings("skip_types", config.SkipTypes))

	logger.Info("Restore command is available but implementation is in progress")
	logger.Info("To complete restore implementation, the existing pkg/authentik/import.go logic needs to be refactored to use structured logging and the consolidated client")

	return eos_err.NewUserError("restore functionality is coming soon - implementation in progress")
}

// FindLatestBackup finds the most recent backup file in the specified directory
func FindLatestBackup(backupDir string) (string, error) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return "", fmt.Errorf("failed to read backup directory: %w", err)
	}

	var latestTime time.Time
	var latestFile string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "authentik-backup-") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().After(latestTime) {
			latestTime = info.ModTime()
			latestFile = filepath.Join(backupDir, entry.Name())
		}
	}

	if latestFile == "" {
		return "", fmt.Errorf("no backups found in %s", backupDir)
	}

	return latestFile, nil
}

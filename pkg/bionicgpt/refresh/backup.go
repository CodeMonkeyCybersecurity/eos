// Package refresh - Backup operations for Moni refresh
package refresh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// createBackup creates a backup of configuration files and databases
// Returns the backup directory path
func (r *Refresher) createBackup(ctx context.Context) (string, error) {
	logger := otelzap.Ctx(ctx)

	// Create backup directory with timestamp
	timestamp := time.Now().Format(bionicgpt.BackupTimestampFormat)
	backupName := fmt.Sprintf("%s%s", bionicgpt.BackupPrefixRefresh, timestamp)
	backupPath := filepath.Join(r.backupDir, backupName)

	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	logger.Info("Created backup directory", zap.String("path", backupPath))

	// Backup configuration files
	if err := r.backupConfigFiles(ctx, backupPath); err != nil {
		return "", fmt.Errorf("failed to backup config files: %w", err)
	}

	// Backup databases
	if err := r.backupDatabases(ctx, backupPath); err != nil {
		// Don't fail if database backup fails - just warn
		logger.Warn("Database backup failed (continuing anyway)", zap.Error(err))
	}

	// Create rollback script
	if err := r.createRollbackScript(ctx, backupPath, backupName); err != nil {
		logger.Warn("Failed to create rollback script", zap.Error(err))
	}

	logger.Info("Backup completed", zap.String("path", backupPath))
	return backupPath, nil
}

// backupConfigFiles backs up configuration files
func (r *Refresher) backupConfigFiles(ctx context.Context, backupPath string) error {
	logger := otelzap.Ctx(ctx)

	filesToBackup := []string{
		r.envFile,
		r.composeFile,
		filepath.Join(r.config.InstallDir, bionicgpt.LiteLLMConfigFileName),
		filepath.Join(r.config.InstallDir, bionicgpt.FixModelsFileName),
	}

	for _, srcPath := range filesToBackup {
		// Skip if file doesn't exist (optional files)
		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			logger.Debug("Skipping non-existent file", zap.String("path", srcPath))
			continue
		}

		// Copy file to backup directory
		destPath := filepath.Join(backupPath, filepath.Base(srcPath))
		if err := copyFile(srcPath, destPath); err != nil {
			return fmt.Errorf("failed to backup %s: %w", srcPath, err)
		}

		logger.Debug("Backed up config file",
			zap.String("src", srcPath),
			zap.String("dest", destPath))
	}

	logger.Info("Configuration files backed up")
	return nil
}

// backupDatabases backs up PostgreSQL databases
func (r *Refresher) backupDatabases(ctx context.Context, backupPath string) error {
	logger := otelzap.Ctx(ctx)

	// Backup main database (bionic-gpt)
	mainBackupPath := filepath.Join(backupPath, "bionic-gpt-backup.sql")
	if err := r.backupPostgresDB(ctx, bionicgpt.ContainerNamePostgres, bionicgpt.DefaultPostgresUser, bionicgpt.DefaultPostgresDB, mainBackupPath); err != nil {
		logger.Warn("Failed to backup main database", zap.Error(err))
	} else {
		logger.Info("Main database backed up", zap.String("path", mainBackupPath))
	}

	// Backup LiteLLM database
	litellmBackupPath := filepath.Join(backupPath, "litellm-backup.sql")
	if err := r.backupPostgresDB(ctx, bionicgpt.ContainerNameLiteLLMDB, bionicgpt.LiteLLMDefaultUser, bionicgpt.LiteLLMDefaultDB, litellmBackupPath); err != nil {
		logger.Warn("Failed to backup LiteLLM database", zap.Error(err))
	} else {
		logger.Info("LiteLLM database backed up", zap.String("path", litellmBackupPath))
	}

	return nil
}

// backupPostgresDB backs up a PostgreSQL database using pg_dump
func (r *Refresher) backupPostgresDB(ctx context.Context, containerName, user, database, outputPath string) error {
	cmd := exec.CommandContext(ctx,
		"docker", "exec", containerName,
		"pg_dump", "-U", user, database)

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("pg_dump failed: %w", err)
	}

	if err := os.WriteFile(outputPath, output, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

// createRollbackScript creates a rollback script for the backup
func (r *Refresher) createRollbackScript(ctx context.Context, backupPath, backupName string) error {
	logger := otelzap.Ctx(ctx)

	scriptPath := filepath.Join(backupPath, bionicgpt.RollbackScriptName)

	// Generate rollback script
	scriptContent := fmt.Sprintf(`#!/bin/bash
# Moni Configuration Rollback Script
# Generated: %s
# Backup: %s

set -e

echo "⚠️  Rolling back Moni configuration..."
cd "%s"

# Stop services
docker-compose down

# Restore configuration files
if [ -f "%s/.env" ]; then
    cp "%s/.env" .
    echo "✓ Restored .env"
fi

if [ -f "%s/docker-compose.yml" ]; then
    cp "%s/docker-compose.yml" .
    echo "✓ Restored docker-compose.yml"
fi

if [ -f "%s/litellm_config.yaml" ]; then
    cp "%s/litellm_config.yaml" .
    echo "✓ Restored litellm_config.yaml"
fi

# Start databases
docker-compose up -d postgres litellm-db
echo "Waiting for databases..."
sleep 10

# Restore main database
if [ -f "%s/bionic-gpt-backup.sql" ]; then
    docker exec -i bionicgpt-postgres psql -U postgres bionic-gpt < "%s/bionic-gpt-backup.sql"
    echo "✓ Restored main database"
fi

# Restore LiteLLM database
if [ -f "%s/litellm-backup.sql" ]; then
    docker exec -i bionicgpt-litellm-db psql -U litellm litellm < "%s/litellm-backup.sql"
    echo "✓ Restored LiteLLM database"
fi

# Start all services
docker-compose up -d

echo "✓ Rollback complete"
`,
		time.Now().Format(time.RFC3339),
		backupName,
		r.config.InstallDir,
		backupPath, backupPath,
		backupPath, backupPath,
		backupPath, backupPath,
		backupPath, backupPath,
		backupPath, backupPath,
	)

	if err := os.WriteFile(scriptPath, []byte(scriptContent), bionicgpt.RollbackScriptPerm); err != nil {
		return fmt.Errorf("failed to write rollback script: %w", err)
	}

	logger.Info("Created rollback script", zap.String("path", scriptPath))
	return nil
}

// copyFile copies a file from src to dest
func copyFile(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	if err := os.WriteFile(dest, data, 0600); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	return nil
}

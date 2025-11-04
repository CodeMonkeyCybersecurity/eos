// Package refresh provides Moni (BionicGPT) configuration refresh operations
// following the Assess → Intervene → Evaluate pattern.
//
// Refresh Process:
//  1. ASSESS: Pre-flight checks (Docker, files, environment variables)
//  2. INTERVENE:
//     a. Create backup (config files + databases)
//     b. Stop services (docker compose down)
//     c. Start fresh (docker compose up -d --force-recreate)
//     d. Clear caches (LiteLLM verification tokens)
//     e. Update database (models and prompts configuration)
//     f. Restart app services
//  3. EVALUATE: Validate deployment (containers running, database state)
//
// CRITICAL LESSONS (from bash script debugging):
//   - docker compose down + up --force-recreate is REQUIRED to reload env vars
//   - LiteLLM cache MUST be cleared via DELETE FROM "LiteLLM_VerificationToken"
//   - Database updates MUST use DELETE + INSERT (UPDATE silently fails)
//   - SQL MUST be piped via docker exec -i < file.sql (heredoc doesn't work)
//   - All database operations MUST verify success with SELECT queries
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package refresh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Config contains configuration for Moni refresh operation
type Config struct {
	// Installation paths
	InstallDir string // Base installation directory (default: /opt/bionicgpt)

	// Operational flags
	Force        bool // Skip confirmation prompt
	NoBackup     bool // Skip backup creation (NOT RECOMMENDED)
	ValidateOnly bool // Only validate, don't make changes
}

// Validate validates the refresh configuration
func (c *Config) Validate() error {
	if c.InstallDir == "" {
		return fmt.Errorf("install directory cannot be empty")
	}

	// Check if directory exists
	if _, err := os.Stat(c.InstallDir); os.IsNotExist(err) {
		return fmt.Errorf("install directory does not exist: %s", c.InstallDir)
	}

	return nil
}

// Refresher handles Moni configuration refresh operations
type Refresher struct {
	rc     *eos_io.RuntimeContext
	config *Config

	// Computed paths (set during initialization)
	composeFile string
	envFile     string
	backupDir   string
}

// NewRefresher creates a new Moni refresher
func NewRefresher(rc *eos_io.RuntimeContext, config *Config) *Refresher {
	return &Refresher{
		rc:          rc,
		config:      config,
		composeFile: filepath.Join(config.InstallDir, bionicgpt.DockerComposeFileName),
		envFile:     filepath.Join(config.InstallDir, bionicgpt.EnvFileName),
		backupDir:   filepath.Join(config.InstallDir, bionicgpt.BackupDirName),
	}
}

// Execute executes the refresh operation following Assess → Intervene → Evaluate
func (r *Refresher) Execute(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Starting Moni configuration refresh",
		zap.String("install_dir", r.config.InstallDir),
		zap.Bool("force", r.config.Force),
		zap.Bool("no_backup", r.config.NoBackup),
		zap.Bool("validate_only", r.config.ValidateOnly))

	// ========================================
	// ASSESS: Pre-flight checks
	// ========================================
	logger.Info("Phase 1: Pre-flight checks")
	if err := r.preFlightChecks(ctx); err != nil {
		return fmt.Errorf("pre-flight checks failed: %w", err)
	}
	logger.Info("Pre-flight checks passed")

	// If validate-only, stop here
	if r.config.ValidateOnly {
		logger.Info("Validation-only mode: running validation checks")
		return r.validate(ctx)
	}

	// ========================================
	// Confirmation (unless --force)
	// ========================================
	if !r.config.Force {
		if err := r.confirmRefresh(ctx); err != nil {
			return err
		}
	}

	// ========================================
	// INTERVENE: Refresh operations
	// ========================================

	// Phase 2: Create backup
	if !r.config.NoBackup {
		logger.Info("Phase 2: Creating backup")
		backupPath, err := r.createBackup(ctx)
		if err != nil {
			return fmt.Errorf("backup creation failed: %w", err)
		}
		logger.Info("Backup created successfully",
			zap.String("backup_path", backupPath))
	} else {
		logger.Warn("Skipping backup (--no-backup flag)")
	}

	// Phase 3: Stop services
	logger.Info("Phase 3: Stopping services")
	if err := r.stopServices(ctx); err != nil {
		return fmt.Errorf("failed to stop services: %w", err)
	}
	logger.Info("Services stopped successfully")

	// Phase 4: Start fresh (--force-recreate)
	logger.Info("Phase 4: Starting services with fresh configuration")
	if err := r.startFresh(ctx); err != nil {
		return fmt.Errorf("failed to start services: %w", err)
	}
	logger.Info("Services started successfully")

	// Phase 5: Wait for databases
	logger.Info("Phase 5: Waiting for databases to be ready")
	if err := r.waitForDatabases(ctx); err != nil {
		return fmt.Errorf("databases not ready: %w", err)
	}
	logger.Info("Databases are ready")

	// Phase 6: Clear caches
	logger.Info("Phase 6: Clearing caches")
	if err := r.clearCaches(ctx); err != nil {
		return fmt.Errorf("failed to clear caches: %w", err)
	}
	logger.Info("Caches cleared successfully")

	// Phase 7: Update database
	logger.Info("Phase 7: Updating database configuration")
	if err := r.updateDatabase(ctx); err != nil {
		return fmt.Errorf("failed to update database: %w", err)
	}
	logger.Info("Database updated successfully")

	// Phase 8: Restart app services
	logger.Info("Phase 8: Restarting application services")
	if err := r.restartAppServices(ctx); err != nil {
		return fmt.Errorf("failed to restart app services: %w", err)
	}
	logger.Info("Application services restarted")

	// ========================================
	// EVALUATE: Validation
	// ========================================
	logger.Info("Phase 9: Validation")
	if err := r.validate(ctx); err != nil {
		logger.Warn("Some validation checks failed", zap.Error(err))
		// Don't fail the operation - validation issues are warnings
	} else {
		logger.Info("All validation checks passed")
	}

	// ========================================
	// Summary
	// ========================================
	logger.Info("================================================================================")
	logger.Info("Moni Configuration Refresh Complete")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Refresh completed successfully",
		zap.String("completed_at", time.Now().Format(time.RFC3339)))
	logger.Info("")
	if !r.config.NoBackup {
		logger.Info("Backup location: " + r.backupDir)
		logger.Info("To rollback, run the rollback script in the backup directory")
	}
	logger.Info("")
	logger.Info("Access Moni at your configured URL")
	logger.Info("")
	logger.Info("================================================================================")

	return nil
}

// confirmRefresh prompts user for confirmation before proceeding
func (r *Refresher) confirmRefresh(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("")
	logger.Info("This will:")
	logger.Info("  • Stop all Moni services")
	logger.Info("  • Clear LiteLLM cache")
	logger.Info("  • Update database models")
	logger.Info("  • Restart services with fresh configuration")
	logger.Info("")
	logger.Info("Estimated downtime: ~2 minutes")
	logger.Info("")

	confirmed := interaction.PromptYesNo("Continue with refresh?", false)

	if !confirmed {
		logger.Warn("Refresh cancelled by user")
		return fmt.Errorf("refresh cancelled by user")
	}

	return nil
}

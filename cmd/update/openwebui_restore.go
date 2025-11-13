package update

import (
	"context"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/openwebui"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	openwebuiRestoreBackupFile string
	openwebuiRestoreNoConfirm  bool
)

var openwebuiRestoreCmd = &cobra.Command{
	Use:   "openwebui-restore",
	Short: "Restore Open WebUI from backup",
	Long: `Restore Open WebUI data from a previous backup.

This command will:
  1. Stop the Open WebUI container
  2. Restore data from the specified backup file
  3. Restart the container

WARNING: This will replace all current data with the backup.
         Make sure you have a recent backup before proceeding.

The backup file should be a .tar.gz file created by 'eos update openwebui'.
Backups are stored in /opt/openwebui/backups/ by default.

Examples:
  # List available backups
  ls -lh /opt/openwebui/backups/

  # Restore from specific backup
  eos update openwebui-restore --backup /opt/openwebui/backups/openwebui-backup-20250213-120000.tar.gz

  # Restore without confirmation prompt
  eos update openwebui-restore --backup /path/to/backup.tar.gz --no-confirm`,
	RunE: eos.Wrap(runRestoreOpenWebUI),
}

func init() {
	openwebuiRestoreCmd.Flags().StringVar(&openwebuiRestoreBackupFile, "backup", "",
		"Path to backup file to restore (required)")
	openwebuiRestoreCmd.Flags().BoolVar(&openwebuiRestoreNoConfirm, "no-confirm", false,
		"Skip confirmation prompt")

	_ = openwebuiRestoreCmd.MarkFlagRequired("backup")

	UpdateCmd.AddCommand(openwebuiRestoreCmd)
}

func runRestoreOpenWebUI(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Open WebUI restore from backup")

	// Validate backup file exists
	if _, err := os.Stat(openwebuiRestoreBackupFile); os.IsNotExist(err) {
		return eos_err.NewUserError("Backup file not found: %s", openwebuiRestoreBackupFile)
	}

	info, err := os.Stat(openwebuiRestoreBackupFile)
	if err != nil {
		return fmt.Errorf("failed to stat backup file: %w", err)
	}

	logger.Info("Backup file found",
		zap.String("path", openwebuiRestoreBackupFile),
		zap.Int64("size_bytes", info.Size()))

	// Confirm with user unless --no-confirm
	if !openwebuiRestoreNoConfirm {
		logger.Warn("This will replace all current Open WebUI data with the backup")
		logger.Info("terminal prompt: Type 'yes' to confirm")

		confirmation, err := eos_io.PromptInput(rc, "Confirm restore (yes/no): ", "restore_confirmation")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if strings.ToLower(strings.TrimSpace(confirmation)) != "yes" {
			logger.Info("Restore cancelled by user")
			return nil
		}
	}

	// Create updater instance to use shared restore logic
	updater := openwebui.NewOpenWebUIUpdater(rc, &openwebui.UpdateConfig{
		InstallDir: "/opt/openwebui",
	})

	// Stop container
	logger.Info("Stopping Open WebUI container")
	if err := stopOpenWebUIContainer(rc.Ctx); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	// Restore data using shared function
	logger.Info("Restoring data from backup (this may take a few minutes)")
	if err := updater.RestoreBackup(rc.Ctx, openwebuiRestoreBackupFile); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	// Start container
	logger.Info("Starting Open WebUI container")
	if err := startOpenWebUIContainer(rc.Ctx); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	logger.Info("Open WebUI restored successfully from backup")
	logger.Info("Please clear your browser cache and refresh the page")

	return nil
}

func stopOpenWebUIContainer(ctx context.Context) error {
	composeFile := "/opt/openwebui/docker-compose.yml"

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", composeFile, "down"},
		Dir:     "/opt/openwebui",
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to stop container: %s", output)
	}

	return nil
}

func startOpenWebUIContainer(ctx context.Context) error {
	composeFile := "/opt/openwebui/docker-compose.yml"

	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", composeFile, "up", "-d"},
		Dir:     "/opt/openwebui",
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to start container: %s", output)
	}

	return nil
}

// restoreOpenWebUIBackup is now handled by openwebui.RestoreBackup()
// This function has been removed to avoid code duplication

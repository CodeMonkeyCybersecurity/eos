package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/openwebui"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	openwebuiInstallDir      string
	openwebuiTargetVersion   string
	openwebuiSkipBackup      bool
	openwebuiSkipHealthCheck bool
	openwebuiAutoRollback    bool
)

var openwebuiCmd = &cobra.Command{
	Use:   "openwebui",
	Short: "Update Open WebUI to latest stable version",
	Long: `Safely update Open WebUI to the latest stable version with automatic backup and rollback.

This command follows a safe update process:
  1. ASSESS: Check current version and determine latest stable release
  2. BACKUP: Create timestamped backup of all data (webui.db, uploads/, vector_db/)
  3. UPDATE: Stop container, pull new version, restart with new image
  4. VERIFY: Health check to ensure application is working
  5. ROLLBACK: Automatic rollback if health check fails (when --auto-rollback is enabled)

Data Safety:
  - All user data is preserved in Docker volume (open-webui-data)
  - Automatic backup created before update
  - Backups stored in /opt/openwebui/backups/
  - Can restore from backup if needed

Version Selection:
  - By default, updates to latest stable (non-prerelease) GitHub release
  - Use --version to specify exact version (e.g., v0.6.32)
  - Stable versions only - no dev/main branch updates

Examples:
  # Update to latest stable release with backup
  eos update openwebui

  # Update to specific version
  eos update openwebui --version v0.6.32

  # Update with automatic rollback on failure
  eos update openwebui --auto-rollback

  # Skip backup (not recommended)
  eos update openwebui --skip-backup

  # Skip health check after update
  eos update openwebui --skip-health-check`,
	RunE: eos.Wrap(runUpdateOpenWebUI),
}

func init() {
	openwebuiCmd.Flags().StringVar(&openwebuiInstallDir, "install-dir", "/opt/openwebui",
		"Installation directory")
	openwebuiCmd.Flags().StringVar(&openwebuiTargetVersion, "version", "latest",
		"Target version to update to (e.g., v0.6.32, or 'latest' for newest stable)")
	openwebuiCmd.Flags().BoolVar(&openwebuiSkipBackup, "skip-backup", false,
		"Skip backup before update (not recommended)")
	openwebuiCmd.Flags().BoolVar(&openwebuiSkipHealthCheck, "skip-health-check", false,
		"Skip health check after update")
	openwebuiCmd.Flags().BoolVar(&openwebuiAutoRollback, "auto-rollback", true,
		"Automatically rollback if update fails or health check fails")

	UpdateCmd.AddCommand(openwebuiCmd)
}

func runUpdateOpenWebUI(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Open WebUI update")

	config := &openwebui.UpdateConfig{
		InstallDir:      openwebuiInstallDir,
		TargetVersion:   openwebuiTargetVersion,
		SkipBackup:      openwebuiSkipBackup,
		SkipHealthCheck: openwebuiSkipHealthCheck,
		AutoRollback:    openwebuiAutoRollback,
	}

	logger.Debug("Update configuration",
		zap.String("install_dir", config.InstallDir),
		zap.String("target_version", config.TargetVersion),
		zap.Bool("skip_backup", config.SkipBackup),
		zap.Bool("auto_rollback", config.AutoRollback))

	updater := openwebui.NewOpenWebUIUpdater(rc, config)

	if err := updater.Update(); err != nil {
		logger.Error("Update failed", zap.Error(err))
		return err
	}

	logger.Info("Open WebUI update completed successfully")
	logger.Info("Please clear your browser cache and refresh the page")

	return nil
}

// cmd/update/moni.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au
*/
package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt/apikeys"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt/postinstall"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt/refresh"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	// Moni refresh flags
	moniRefreshForce        bool
	moniRefreshNoBackup     bool
	moniRefreshValidateOnly bool
	moniRefreshInstallDir   string

	// Moni post-install and API key rotation flags
	moniPostInstall   bool
	moniRotateAPIKeys bool
	moniInstallDir    string
)

// MoniCmd is the command for Moni (BionicGPT) operations
var MoniCmd = &cobra.Command{
	Use:     "moni",
	Aliases: []string{"bionicgpt"},
	Short:   "Update Moni (BionicGPT) configuration",
	Long: `Update Moni (BionicGPT) multi-tenant LLM platform configuration.

The 'moni' command provides operations to manage your BionicGPT deployment:
  • Post-installation configuration (--post-install)
  • API key rotation (--rotate-api-keys)
  • Configuration refresh (--refresh)
  • Service restart
  • Cache clearing
  • Database configuration updates

BionicGPT (also known as Moni) is a multi-tenant RAG-enabled LLM platform
with document processing, embeddings, and Azure OpenAI integration.`,
	RunE: eos.Wrap(runMoniOperations),
}

func init() {
	// Refresh subcommand
	refreshCmd := &cobra.Command{
		Use:   "refresh",
		Short: "Refresh Moni configuration and restart services",
		Long: `Safely refresh Moni by:
  1. Creating backup of configuration and databases
  2. Stopping all services
  3. Starting with fresh configuration (--force-recreate)
  4. Clearing LiteLLM cache (verification tokens)
  5. Updating database models configuration
  6. Restarting application services
  7. Validating deployment

This operation ensures environment variables are reloaded, caches are cleared,
and the database configuration is synchronized with the latest settings.

Estimated downtime: ~2 minutes

Examples:
  # Full refresh with confirmation prompt
  eos update moni --refresh

  # Skip confirmation prompt
  eos update moni --refresh --force

  # Skip backup (not recommended)
  eos update moni --refresh --no-backup

  # Validation only (no changes)
  eos update moni --refresh --validate-only

  # Custom installation directory
  eos update moni --refresh --install-dir /opt/moni`,
		RunE: eos.Wrap(runMoniRefresh),
	}

	refreshCmd.Flags().BoolVar(&moniRefreshForce, "force", false,
		"Skip confirmation prompt")
	refreshCmd.Flags().BoolVar(&moniRefreshNoBackup, "no-backup", false,
		"Skip backup creation (not recommended)")
	refreshCmd.Flags().BoolVar(&moniRefreshValidateOnly, "validate-only", false,
		"Only run validation, don't make changes")
	refreshCmd.Flags().StringVar(&moniRefreshInstallDir, "install-dir", "/opt/bionicgpt",
		"Path to Moni installation directory")

	// Add --refresh flag to parent command for convenience
	MoniCmd.Flags().BoolVar(&moniRefreshForce, "refresh", false,
		"Refresh Moni configuration and restart services")

	// Add post-install flag
	MoniCmd.Flags().BoolVar(&moniPostInstall, "post-install", false,
		"Run post-installation configuration (upsert models, regenerate API keys)")

	// Add rotate-api-keys flag
	MoniCmd.Flags().BoolVar(&moniRotateAPIKeys, "rotate-api-keys", false,
		"Rotate API keys (generate new virtual key, update .env and database)")

	// Add install-dir flag for both operations
	MoniCmd.Flags().StringVar(&moniInstallDir, "install-dir", "/opt/bionicgpt",
		"Path to Moni installation directory")

	MoniCmd.AddCommand(refreshCmd)
}

// runMoniOperations handles the main moni command flags
// Orchestration layer: delegates to appropriate package based on flag
func runMoniOperations(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check which operation was requested
	if moniPostInstall {
		return runMoniPostInstall(rc, cmd, args)
	}

	if moniRotateAPIKeys {
		return runMoniRotateAPIKeys(rc, cmd, args)
	}

	// If no operation specified, show help
	logger.Info("No operation specified. Use --post-install or --rotate-api-keys")
	return cmd.Help()
}

// runMoniPostInstall handles the post-installation configuration
// Orchestration layer: delegates to pkg/bionicgpt/postinstall for business logic
func runMoniPostInstall(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Moni post-installation configuration",
		zap.String("install_dir", moniInstallDir))

	// Build configuration
	config := &postinstall.Config{
		InstallDir: moniInstallDir,
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Execute post-installation
	if err := postinstall.Execute(rc, config); err != nil {
		logger.Error("Post-installation failed", zap.Error(err))
		return fmt.Errorf("post-installation failed: %w", err)
	}

	logger.Info("Post-installation completed successfully")
	return nil
}

// runMoniRotateAPIKeys handles the API key rotation
// Orchestration layer: delegates to pkg/bionicgpt/apikeys for business logic
func runMoniRotateAPIKeys(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Moni API key rotation",
		zap.String("install_dir", moniInstallDir))

	// Build configuration
	config := &apikeys.Config{
		InstallDir: moniInstallDir,
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Execute API key rotation
	if err := apikeys.Execute(rc, config); err != nil {
		logger.Error("API key rotation failed", zap.Error(err))
		return fmt.Errorf("API key rotation failed: %w", err)
	}

	logger.Info("API key rotation completed successfully")
	return nil
}

// runMoniRefresh handles the refresh operation
// Orchestration layer: delegates to pkg/bionicgpt/refresh for business logic
func runMoniRefresh(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Moni configuration refresh",
		zap.String("install_dir", moniRefreshInstallDir),
		zap.Bool("force", moniRefreshForce),
		zap.Bool("no_backup", moniRefreshNoBackup),
		zap.Bool("validate_only", moniRefreshValidateOnly))

	// Build refresh configuration
	config := &refresh.Config{
		InstallDir:   moniRefreshInstallDir,
		Force:        moniRefreshForce,
		NoBackup:     moniRefreshNoBackup,
		ValidateOnly: moniRefreshValidateOnly,
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create refresher and execute
	refresher := refresh.NewRefresher(rc, config)
	if err := refresher.Execute(rc.Ctx); err != nil {
		logger.Error("Moni refresh failed", zap.Error(err))
		return fmt.Errorf("refresh failed: %w", err)
	}

	logger.Info("Moni refresh completed successfully")
	return nil
}

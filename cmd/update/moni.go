// cmd/update/moni.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au
*/
package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
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

	// Moni API key rotation flags
	moniRotateAPIKeysDryRun      bool
	moniRotateAPIKeysSkipBackup  bool
	moniRotateAPIKeysSkipVerify  bool
	moniRotateAPIKeysSkipRestart bool
	moniRotateAPIKeysInstallDir  string
)

// MoniCmd is the command for Moni (BionicGPT) operations
var MoniCmd = &cobra.Command{
	Use:     "moni",
	Aliases: []string{"bionicgpt"},
	Short:   "Update Moni (BionicGPT) configuration",
	Long: `Update Moni (BionicGPT) multi-tenant LLM platform configuration.

The 'moni' command provides operations to manage your BionicGPT deployment:
  • Configuration refresh (--refresh)
  • Service restart
  • Cache clearing
  • Database configuration updates

BionicGPT (also known as Moni) is a multi-tenant RAG-enabled LLM platform
with document processing, embeddings, and Azure OpenAI integration.`,
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

	// Rotate API keys subcommand
	rotateAPIKeysCmd := &cobra.Command{
		Use:   "rotate-api-keys",
		Short: "Rotate LiteLLM virtual API keys for Moni",
		Long: `Rotate the virtual API keys used by Moni to access LiteLLM models.

This operation regenerates the virtual key with access to all configured models:
  • Moni (GPT-5-mini)
  • Moni-4.1 (GPT-4.1-mini)
  • Moni-o3 (o3-mini)
  • nomic-embed-text (Ollama embeddings)

The rotation process:
  1. ASSESS: Check prerequisites (database, LiteLLM health, current keys)
  2. INTERVENE: Generate new key, update .env, update database, restart app
  3. EVALUATE: Verify new key works and is properly configured

Safety features:
  • Automatic backup of .env file before changes
  • Transaction-like behavior with automatic rollback on failure
  • Comprehensive verification tests after rotation
  • Old keys are deleted after successful rotation

Estimated downtime: ~30 seconds (during app restart)

Examples:
  # Full API key rotation with confirmation
  eos update moni rotate-api-keys

  # Dry run (show what would be done)
  eos update moni rotate-api-keys --dry-run

  # Skip backup (not recommended)
  eos update moni rotate-api-keys --skip-backup

  # Skip verification tests
  eos update moni rotate-api-keys --skip-verify

  # Custom installation directory
  eos update moni rotate-api-keys --install-dir /opt/moni`,
		RunE: eos.Wrap(runMoniRotateAPIKeys),
	}

	rotateAPIKeysCmd.Flags().BoolVar(&moniRotateAPIKeysDryRun, "dry-run", false,
		"Show what would be done without making changes")
	rotateAPIKeysCmd.Flags().BoolVar(&moniRotateAPIKeysSkipBackup, "skip-backup", false,
		"Skip .env backup (not recommended)")
	rotateAPIKeysCmd.Flags().BoolVar(&moniRotateAPIKeysSkipVerify, "skip-verify", false,
		"Skip verification tests after rotation")
	rotateAPIKeysCmd.Flags().BoolVar(&moniRotateAPIKeysSkipRestart, "skip-restart", false,
		"Skip app restart after rotation")
	rotateAPIKeysCmd.Flags().StringVar(&moniRotateAPIKeysInstallDir, "install-dir", "/opt/bionicgpt",
		"Path to Moni installation directory")

	MoniCmd.AddCommand(refreshCmd, rotateAPIKeysCmd)
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

// runMoniRotateAPIKeys handles the API key rotation operation
// Orchestration layer: delegates to pkg/bionicgpt for business logic
func runMoniRotateAPIKeys(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Moni API key rotation",
		zap.String("install_dir", moniRotateAPIKeysInstallDir),
		zap.Bool("dry_run", moniRotateAPIKeysDryRun),
		zap.Bool("skip_backup", moniRotateAPIKeysSkipBackup),
		zap.Bool("skip_verify", moniRotateAPIKeysSkipVerify),
		zap.Bool("skip_restart", moniRotateAPIKeysSkipRestart))

	// Build rotation configuration
	config := &bionicgpt.RotateAPIKeysConfig{
		InstallDir:  moniRotateAPIKeysInstallDir,
		DryRun:      moniRotateAPIKeysDryRun,
		SkipBackup:  moniRotateAPIKeysSkipBackup,
		SkipVerify:  moniRotateAPIKeysSkipVerify,
		SkipRestart: moniRotateAPIKeysSkipRestart,
	}

	// Execute rotation
	if err := bionicgpt.RotateAPIKeys(rc, config); err != nil {
		logger.Error("Moni API key rotation failed", zap.Error(err))
		return fmt.Errorf("API key rotation failed: %w", err)
	}

	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("✅ API KEY ROTATION COMPLETE")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("")
	logger.Info("🔑 New virtual key has been generated and configured")
	logger.Info("")
	logger.Info("🤖 Authorized Models:")
	logger.Info("   • Moni (GPT-5-mini)")
	logger.Info("   • Moni-4.1 (GPT-4.1-mini)")
	logger.Info("   • Moni-o3 (o3-mini)")
	logger.Info("   • nomic-embed-text (Ollama)")
	logger.Info("")
	logger.Info("🧪 Test in Moni UI:")
	logger.Info("   http://localhost:8513")
	logger.Info("   Try: 'What is your name?'")
	logger.Info("")
	logger.Info("📝 Monitor logs:")
	logger.Info("   docker compose -f /opt/bionicgpt/docker-compose.yml logs -f app litellm-proxy")
	logger.Info("")

	return nil
}

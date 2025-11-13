// cmd/update/moni.go
/*
Copyright © 2025 CODE MONKEY CYBERSECURITY git@cybermonkey.net.au
*/
package update

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt/apikeys"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt/postinstall"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt/refresh"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/moni"
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
	// Moni post-install and API key rotation flags
	moniPostInstall   bool
	moniRotateAPIKeys bool
	moniInstallDir    string

	// Moni init (worker) flags
	moniInit           bool
	moniSkipSSL        bool
	moniSkipDatabase   bool
	moniSkipSecurity   bool
	moniSkipVerification bool
	moniValidateCerts  bool
	moniFixCerts       bool
	moniVerifyDB       bool
	moniVerifyRLS      bool
	moniVerifyCSP      bool
	moniVerifySecurity bool
	moniCleanupBackups bool
	moniWorkDir        string
	moniForce          bool
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
	// Add post-install flag
	MoniCmd.Flags().BoolVar(&moniPostInstall, "post-install", false,
		"Run post-installation configuration (upsert models, regenerate API keys)")

	// Add rotate-api-keys flag
	MoniCmd.Flags().BoolVar(&moniRotateAPIKeys, "rotate-api-keys", false,
		"Rotate API keys (generate new virtual key, update .env and database)")

	// Add install-dir flag for both operations
	MoniCmd.Flags().StringVar(&moniInstallDir, "install-dir", "/opt/bionicgpt",
		"Path to Moni installation directory")

	// Moni init (worker) flags - full initialization
	MoniCmd.Flags().BoolVar(&moniInit, "init", false,
		"Run full Moni initialization (SSL, database, security)")

	// Phase control flags
	MoniCmd.Flags().BoolVar(&moniSkipSSL, "skip-ssl", false,
		"Skip SSL certificate generation")
	MoniCmd.Flags().BoolVar(&moniSkipDatabase, "skip-database", false,
		"Skip database configuration")
	MoniCmd.Flags().BoolVar(&moniSkipSecurity, "skip-security", false,
		"Skip security hardening")
	MoniCmd.Flags().BoolVar(&moniSkipVerification, "skip-verification", false,
		"Skip security verification")

	// Targeted action flags
	MoniCmd.Flags().BoolVar(&moniValidateCerts, "validate-certs", false,
		"Validate SSL certificate readability")
	MoniCmd.Flags().BoolVar(&moniFixCerts, "fix-certs", false,
		"Fix SSL certificate permissions")
	MoniCmd.Flags().BoolVar(&moniVerifyDB, "verify-db", false,
		"Verify database configuration")
	MoniCmd.Flags().BoolVar(&moniVerifyRLS, "verify-rls", false,
		"Verify Row Level Security (RLS)")
	MoniCmd.Flags().BoolVar(&moniVerifyCSP, "verify-csp", false,
		"Verify Content Security Policy (CSP)")
	MoniCmd.Flags().BoolVar(&moniVerifySecurity, "verify-security", false,
		"Run all security verifications (RLS + CSP)")
	MoniCmd.Flags().BoolVar(&moniCleanupBackups, "cleanup-backups", false,
		"Cleanup old .env backups")

	// Work directory flag
	MoniCmd.Flags().StringVar(&moniWorkDir, "work-dir", "/opt/moni",
		"Working directory for Moni initialization (default: /opt/moni)")

	// Force flag (skip confirmations for RLS breaking changes)
	MoniCmd.Flags().BoolVar(&moniForce, "force", false,
		"Skip confirmation prompts (use for automation/CI/CD)")

	MoniCmd.AddCommand(refreshCmd)
}

// runMoniOperations handles the main moni command flags
// Orchestration layer: delegates to appropriate package based on flag
func runMoniOperations(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check which operation was requested (priority order)

	// 1. Init/worker operations (new functionality)
	if moniInit || moniValidateCerts || moniFixCerts || moniVerifyDB ||
		moniVerifyRLS || moniVerifyCSP || moniVerifySecurity || moniCleanupBackups {
		return runMoniInit(rc, cmd, args)
	}

	// 2. Post-install
	if moniPostInstall {
		return runMoniPostInstall(rc, cmd, args)
	}

	// 3. API key rotation
	if moniRotateAPIKeys {
		return runMoniRotateAPIKeys(rc, cmd, args)
	}

	// If no operation specified, show help
	logger.Info("No operation specified")
	logger.Info("Common operations:")
	logger.Info("  --init             # Full initialization (SSL, database, security)")
	logger.Info("  --post-install     # Post-installation configuration")
	logger.Info("  --rotate-api-keys  # Rotate API keys")
	logger.Info("  --validate-certs   # Validate SSL certificates")
	logger.Info("  --verify-security  # Security verification")
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

// runMoniInit handles the Moni initialization worker
// Orchestration layer: delegates to pkg/moni for business logic
func runMoniInit(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build worker configuration
	config := &moni.WorkerConfig{
		SkipSSL:            moniSkipSSL,
		SkipDatabase:       moniSkipDatabase,
		SkipSecurity:       moniSkipSecurity,
		SkipVerification:   moniSkipVerification,
		ValidateCertsOnly:  moniValidateCerts,
		FixCertsOnly:       moniFixCerts,
		VerifyDBOnly:       moniVerifyDB,
		VerifyRLSOnly:      moniVerifyRLS,
		VerifyCSPOnly:      moniVerifyCSP,
		VerifySecurityOnly: moniVerifySecurity,
		CleanupBackups:     moniCleanupBackups,
		WorkDir:            moniWorkDir,
		Force:              moniForce,
	}

	// Log operation
	if moniInit {
		logger.Info("Starting Moni full initialization",
			zap.String("work_dir", moniWorkDir))
	} else if moniValidateCerts {
		logger.Info("Validating SSL certificates")
	} else if moniFixCerts {
		logger.Info("Fixing SSL certificate permissions")
	} else if moniVerifyDB {
		logger.Info("Verifying database configuration")
	} else if moniVerifyRLS {
		logger.Info("Verifying Row Level Security")
	} else if moniVerifyCSP {
		logger.Info("Verifying Content Security Policy")
	} else if moniVerifySecurity {
		logger.Info("Running security verification")
	} else if moniCleanupBackups {
		logger.Info("Cleaning up old backups")
	}

	// Run worker
	result, err := moni.RunWorker(rc, config)
	if err != nil {
		logger.Error("Moni worker failed", zap.Error(err))
		return fmt.Errorf("moni worker failed: %w", err)
	}

	// Check result
	if !result.Success {
		logger.Error("Moni operation did not complete successfully")

		if len(result.CriticalIssues) > 0 {
			logger.Error("Critical issues detected:")
			for _, issue := range result.CriticalIssues {
				logger.Error(fmt.Sprintf("  • %s", issue))
			}
		}

		return fmt.Errorf("moni operation failed")
	}

	logger.Info("Moni operation completed successfully")
	return nil
}

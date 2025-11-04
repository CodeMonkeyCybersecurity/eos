package create

import (
	"fmt"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/repository"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createRepoCmd = &cobra.Command{
	Use:   "repo [path]",
	Short: "Create a local git repository and provision a matching Gitea remote",
	Long: `Initialize a local git repository, create a remote on Gitea, add it as a git remote, and push the initial commit.

The command supports interactive and non-interactive usage. When required information is missing it will prompt
for details unless --non-interactive is specified. To review the intended actions without applying them, use --dry-run.

Examples:
  eos create repo .
  eos create repo . --name my-service --private
  eos create repo ./service --org codemonkey --remote upstream
  eos create repo . --dry-run
  eos create repo . --non-interactive --name hecate --private --no-push`,
	Args:         cobra.MaximumNArgs(1),
	RunE:         eos.Wrap(runCreateRepo),
	SilenceUsage: true, // Don't print usage on runtime errors (P1 fix)
}

func init() {
	CreateCmd.AddCommand(createRepoCmd)

	createRepoCmd.Flags().StringP("name", "n", "", "Repository name (default: directory name)")
	createRepoCmd.Flags().StringP("description", "d", "", "Repository description")
	createRepoCmd.Flags().BoolP("private", "p", false, "Make repository private")
	createRepoCmd.Flags().StringP("org", "o", "", "Create repository under an organization")
	createRepoCmd.Flags().String("remote", "origin", "Git remote name to use")
	createRepoCmd.Flags().String("branch", "main", "Default branch name")
	createRepoCmd.Flags().Bool("no-push", false, "Do not push to the remote after creation")
	createRepoCmd.Flags().Bool("dry-run", false, "Show planned actions without applying changes")
	createRepoCmd.Flags().Bool("non-interactive", false, "Disable interactive prompts")
	createRepoCmd.Flags().Bool("save-config", false, "Persist answers for future runs in .eos/create-repo.yaml")
}

func runCreateRepo(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// ========================================
	// P0 FIX #1: Setup signal handling FIRST
	// ========================================
	handler := eos.NewSignalHandler(rc.Ctx)
	defer handler.Stop()

	// Use handler's cancellable context for all operations
	ctx := handler.Context()
	logger := otelzap.Ctx(ctx)

	logger.Info("Starting repository creation with comprehensive preflight checks")

	// ========================================
	// PREFLIGHT PHASE: Fail-fast validation
	// ========================================

	// Parse --non-interactive flag early (needed for preflight fallbacks)
	nonInteractive, _ := cmd.Flags().GetBool("non-interactive")

	// Check 1: Warn about sudo usage
	eos.CheckAndWarnPrivileges(ctx, "git", false)

	// Check 2: Resolve path early (needed for subsequent checks)
	path := "."
	if len(args) > 0 {
		path = args[0]
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return eos_err.NewFilesystemError(
			"Failed to resolve repository path",
			err,
			fmt.Sprintf("Check path: %s", path),
		)
	}

	logger.Debug("Repository path resolved", zap.String("path", absPath))

	// ========================================
	// P0 FIX #2: Acquire repository lock
	// ========================================
	logger.Debug("Acquiring repository lock to prevent concurrent operations")
	lockCleanup, err := git.AcquireRepositoryLock(ctx, absPath)
	if err != nil {
		return err // Already has good error message from AcquireRepositoryLock
	}
	// Register cleanup - will run on normal exit OR Ctrl-C
	handler.RegisterCleanup(func() error {
		logger.Debug("Releasing repository lock")
		lockCleanup()
		return nil
	})

	// ========================================
	// P0 FIX #3: Run comprehensive preflight checks with human-centric fallback
	// ========================================

	// Check 3: Basic git environment (installed, identity configured)
	// HUMAN-CENTRIC (P0 #13): Offer interactive setup instead of failing
	logger.Info("Running git environment preflight checks")
	gitPreflightConfig := git.DefaultGitPreflightConfig()
	if err := git.RunGitPreflightChecks(ctx, gitPreflightConfig); err != nil {
		// Check if this is a git identity issue that we can help with
		if strings.Contains(err.Error(), "git identity not configured") {
			logger.Info("Git identity missing - offering interactive configuration")

			// Offer interactive configuration (respects --non-interactive flag)
			configured, configErr := git.ConfigureGitIdentityInteractive(ctx, nonInteractive)
			if configErr != nil {
				return fmt.Errorf("failed to configure git identity: %w", configErr)
			}

			if !configured {
				// User declined or non-interactive mode
				// Return original error with context
				return fmt.Errorf("preflight check failed: %w\n\n"+
					"Eos checks your environment BEFORE asking questions to avoid wasting your time.\n"+
					"Please fix the issue above and try again.", err)
			}

			// Success! Identity is now configured, continue with repo creation
			logger.Info("Git identity configured successfully - continuing with repository creation")
		} else {
			// Some other preflight error (git not installed, etc.)
			return eos_err.ClassifyError(err, "git environment validation")
		}
	}

	// Check 4: Filesystem validation (disk space, write permissions, path safety)
	logger.Debug("Checking filesystem prerequisites")

	// Check disk space (1GB minimum for safety)
	if err := git.CheckDiskSpace(ctx, absPath, 1*1024*1024*1024); err != nil {
		return err
	}

	// Check write permissions
	if err := git.CheckWritePermissions(ctx, absPath); err != nil {
		return err
	}

	// Validate path safety (symlinks, temp dirs, path traversal)
	if err := git.ValidatePathSafety(ctx, absPath); err != nil {
		return err
	}

	logger.Info("All preflight checks passed - proceeding with repository creation")

	// ========================================
	// CONFIGURATION PHASE: Parse flags and preferences
	// ========================================

	name, _ := cmd.Flags().GetString("name")
	description, _ := cmd.Flags().GetString("description")
	private, _ := cmd.Flags().GetBool("private")
	org, _ := cmd.Flags().GetString("org")
	remote, _ := cmd.Flags().GetString("remote")
	branch, _ := cmd.Flags().GetString("branch")
	noPush, _ := cmd.Flags().GetBool("no-push")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	// nonInteractive already parsed above for preflight checks
	saveConfig, _ := cmd.Flags().GetBool("save-config")

	opts := &repository.RepoOptions{
		Path:           absPath,
		Name:           name,
		Description:    description,
		Private:        private,
		Organization:   org,
		Remote:         remote,
		Branch:         branch,
		DryRun:         dryRun,
		NoPush:         noPush,
		NonInteractive: nonInteractive,
		SaveConfig:     saveConfig,
	}

	prefsPath := repository.PreferencesPath(absPath)
	prefs, err := repository.LoadRepoPreferences(prefsPath)
	if err != nil {
		return eos_err.NewFilesystemError(
			"Failed to load repository preferences",
			err,
			fmt.Sprintf("Check if %s is readable", prefsPath),
		)
	}

	opts.ApplyDefaults(prefs)
	opts.EnsurePathDefaults()

	// ========================================
	// INTERACTIVE PHASE: Prompt for missing values
	// ========================================

	needsPrompt := !nonInteractive && (!cmd.Flags().Changed("name") ||
		!cmd.Flags().Changed("private") ||
		!cmd.Flags().Changed("org") ||
		!cmd.Flags().Changed("branch") ||
		!cmd.Flags().Changed("remote"))

	if !nonInteractive && needsPrompt {
		logger.Debug("Prompting for missing configuration values")
		if _, err := repository.PromptRepoOptions(absPath, opts, prefs); err != nil {
			return eos_err.NewUserCancelledError("repository configuration")
		}
	}

	// ========================================
	// REMOTE SETUP PHASE: Configure Gitea client
	// ========================================

	var giteaClient *repository.GiteaClient
	credOpts := repository.CredentialOptions{
		Interactive: !nonInteractive,
	}

	// Use RuntimeContext with handler's context for Gitea config
	// (GiteaConfig expects RuntimeContext, not bare context)
	rcWithHandler := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	cfg, cfgErr := repository.GetGiteaConfig(rcWithHandler, credOpts)
	if cfgErr != nil {
		if dryRun {
			logger.Warn("Gitea credentials unavailable; dry-run will skip remote operations", zap.Error(cfgErr))
		} else {
			return eos_err.NewNetworkError(
				"Failed to load Gitea configuration",
				cfgErr,
				"Check VAULT_ADDR and Vault connectivity",
				"Ensure Gitea credentials are stored in Vault",
			)
		}
	} else {
		client, err := repository.NewGiteaClient(cfg)
		if err != nil {
			if dryRun {
				logger.Warn("Failed to initialize Gitea client; remote operations skipped", zap.Error(err))
			} else {
				return eos_err.NewNetworkError(
					"Failed to create Gitea client",
					err,
					"Check Gitea URL is accessible",
					"Verify Gitea credentials are correct",
				)
			}
		} else {
			giteaClient = client
		}
	}

	// ========================================
	// EXECUTION PHASE: Create repository
	// ========================================

	logger.Info("Creating repository",
		zap.String("name", opts.Name),
		zap.String("path", absPath),
		zap.Bool("dry_run", dryRun))

	gitWrapper := &repository.GitWrapper{Path: absPath}

	creator := repository.NewCreator(rcWithHandler, opts, gitWrapper, giteaClient, prefs, prefsPath)
	if _, err := creator.Create(); err != nil {
		// Classify the error for proper exit code
		return eos_err.ClassifyError(err, "repository creation")
	}

	logger.Info("Repository creation completed successfully")
	return nil
}

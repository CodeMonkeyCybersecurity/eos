package git

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// Package-level variables for deploy command flags
var (
	deployRepositoryPath string
	deployBranch         string
	deployMergeBranch    string
	deployLogFile        string
	deployDryRun         bool
	deployForce          bool
)

// deployCmd handles Git deployment workflows
var deployCmd = &cobra.Command{
	Use:     "deploy",
	Aliases: []string{"dp"},
	Short:   "Automated Git deployment workflow",
	Long: `Automated Git deployment workflow for code deployment.

This command provides automated deployment functionality:
- Pull latest changes from remote
- Merge development branches
- Push changes to remote
- Logging of deployment operations
- Dry-run mode for testing

Examples:
  eos git deploy                                  # Deploy current directory
  eos git deploy --repository /path/to/repo      # Deploy specific repository
  eos git deploy --branch main --merge-branch development
  eos git deploy --dry-run                       # Test deployment without changes`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if deployRepositoryPath == "" {
			var err error
			deployRepositoryPath, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
		}

		manager := git_management.NewGitManager()

		if !manager.IsGitRepository(rc, deployRepositoryPath) {
			return fmt.Errorf("not a git repository: %s", deployRepositoryPath)
		}

		// Set defaults
		if deployBranch == "" {
			deployBranch = "main"
		}
		if deployLogFile == "" {
			deployLogFile = fmt.Sprintf("%s/deploy.log", deployRepositoryPath)
		}

		// Build deployment options
		options := &git_management.GitDeploymentOptions{
			RepositoryPath: deployRepositoryPath,
			Branch:         deployBranch,
			MergeBranch:    deployMergeBranch,
			LogFile:        deployLogFile,
			DryRun:         deployDryRun,
			Force:          deployForce,
		}

		logger.Info("Starting Git deployment",
			zap.String("repository", deployRepositoryPath),
			zap.String("branch", deployBranch),
			zap.String("merge_branch", deployMergeBranch),
			zap.Bool("dry_run", deployDryRun),
			zap.Bool("force", deployForce))

		if deployDryRun {
			return runDryRunDeployment(rc, manager, options)
		}

		return manager.DeployWithGit(rc, options)
	}),
}

func init() {
	deployCmd.Flags().StringVarP(&deployRepositoryPath, "repository", "r", "", "Path to Git repository (default: current directory)")
	deployCmd.Flags().StringVarP(&deployBranch, "branch", "b", "main", "Branch to deploy")
	deployCmd.Flags().StringVar(&deployMergeBranch, "merge-branch", "", "Branch to merge before deployment")
	deployCmd.Flags().StringVar(&deployLogFile, "log-file", "", "Path to log file (default: repository/deploy.log)")
	deployCmd.Flags().BoolVar(&deployDryRun, "dry-run", false, "Simulate deployment without making changes")
	deployCmd.Flags().BoolVarP(&deployForce, "force", "f", false, "Force push changes")
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func runDryRunDeployment(rc *eos_io.RuntimeContext, manager *git_management.GitManager, options *git_management.GitDeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: Git Deployment Dry Run")
	logger.Info("terminal prompt: =====================\n")

	// Get repository info
	repo, err := manager.GetRepositoryInfo(rc, options.RepositoryPath)
	if err != nil {
		return fmt.Errorf("failed to get repository info: %w", err)
	}

	logger.Info("terminal prompt: Repository: %s", options.RepositoryPath)
	logger.Info("terminal prompt: Target Branch: %s", options.Branch)
	if options.MergeBranch != "" {
		logger.Info("terminal prompt: Merge Branch: %s", options.MergeBranch)
	}
	logger.Info("terminal prompt: Current Branch: %s", repo.Status.Branch)
	logger.Info("terminal prompt: Repository Status: ")
	if repo.Status.IsClean {
		logger.Info("terminal prompt: Clean")
	} else {
		logger.Info("terminal prompt: Has changes")
		logger.Info("terminal prompt:   - Staged: %d files", len(repo.Status.Staged))
		logger.Info("terminal prompt:   - Modified: %d files", len(repo.Status.Modified))
		logger.Info("terminal prompt:   - Untracked: %d files", len(repo.Status.Untracked))
	}

	if repo.Status.AheadCount > 0 || repo.Status.BehindCount > 0 {
		logger.Info("terminal prompt: Sync Status: ")
		if repo.Status.AheadCount > 0 {
			logger.Info("terminal prompt: %d ahead", repo.Status.AheadCount)
		}
		if repo.Status.BehindCount > 0 {
			if repo.Status.AheadCount > 0 {
				logger.Info("terminal prompt: , ")
			}
			logger.Info("terminal prompt: %d behind", repo.Status.BehindCount)
		}
		logger.Info("terminal prompt: \n")
	}

	logger.Info("terminal prompt: Remotes:")
	for name, url := range repo.RemoteURLs {
		logger.Info("terminal prompt:   %s: %s", name, url)
	}

	logger.Info("terminal prompt: Deployment Plan:")
	logger.Info("terminal prompt: 1. Pull latest changes from origin/%s", options.Branch)
	if options.MergeBranch != "" {
		logger.Info("terminal prompt: 2. Merge %s into %s", options.MergeBranch, options.Branch)
	}
	if options.Force {
		logger.Info("terminal prompt: 3. Force push to origin/%s", options.Branch)
	} else {
		logger.Info("terminal prompt: 3. Push to origin/%s", options.Branch)
	}

	logger.Info("Dry run deployment completed", zap.String("repository", options.RepositoryPath))
	return nil
}

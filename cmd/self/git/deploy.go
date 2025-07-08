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

// newDeployCmd creates the Git deployment command
func newDeployCmd() *cobra.Command {
	var (
		repositoryPath string
		branch         string
		mergeBranch    string
		logFile        string
		dryRun         bool
		force          bool
	)

	cmd := &cobra.Command{
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

			if repositoryPath == "" {
				var err error
				repositoryPath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, repositoryPath) {
				return fmt.Errorf("not a git repository: %s", repositoryPath)
			}

			// Set defaults
			if branch == "" {
				branch = "main"
			}
			if logFile == "" {
				logFile = fmt.Sprintf("%s/deploy.log", repositoryPath)
			}

			// Build deployment options
			options := &git_management.GitDeploymentOptions{
				RepositoryPath: repositoryPath,
				Branch:         branch,
				MergeBranch:    mergeBranch,
				LogFile:        logFile,
				DryRun:         dryRun,
				Force:          force,
			}

			logger.Info("Starting Git deployment", 
				zap.String("repository", repositoryPath),
				zap.String("branch", branch),
				zap.String("merge_branch", mergeBranch),
				zap.Bool("dry_run", dryRun),
				zap.Bool("force", force))

			if dryRun {
				return runDryRunDeployment(rc, manager, options)
			}

			return manager.DeployWithGit(rc, options)
		}),
	}

	cmd.Flags().StringVarP(&repositoryPath, "repository", "r", "", "Path to Git repository (default: current directory)")
	cmd.Flags().StringVarP(&branch, "branch", "b", "main", "Branch to deploy")
	cmd.Flags().StringVar(&mergeBranch, "merge-branch", "", "Branch to merge before deployment")
	cmd.Flags().StringVar(&logFile, "log-file", "", "Path to log file (default: repository/deploy.log)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Simulate deployment without making changes")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force push changes")

	return cmd
}

func runDryRunDeployment(rc *eos_io.RuntimeContext, manager *git_management.GitManager, options *git_management.GitDeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Printf("Git Deployment Dry Run\n")
	fmt.Printf("=====================\n\n")

	// Get repository info
	repo, err := manager.GetRepositoryInfo(rc, options.RepositoryPath)
	if err != nil {
		return fmt.Errorf("failed to get repository info: %w", err)
	}

	fmt.Printf("Repository: %s\n", options.RepositoryPath)
	fmt.Printf("Target Branch: %s\n", options.Branch)
	if options.MergeBranch != "" {
		fmt.Printf("Merge Branch: %s\n", options.MergeBranch)
	}
	fmt.Printf("Current Branch: %s\n", repo.Status.Branch)
	fmt.Printf("Repository Status: ")
	if repo.Status.IsClean {
		fmt.Printf("Clean\n")
	} else {
		fmt.Printf("Has changes\n")
		fmt.Printf("  - Staged: %d files\n", len(repo.Status.Staged))
		fmt.Printf("  - Modified: %d files\n", len(repo.Status.Modified))
		fmt.Printf("  - Untracked: %d files\n", len(repo.Status.Untracked))
	}

	if repo.Status.AheadCount > 0 || repo.Status.BehindCount > 0 {
		fmt.Printf("Sync Status: ")
		if repo.Status.AheadCount > 0 {
			fmt.Printf("%d ahead", repo.Status.AheadCount)
		}
		if repo.Status.BehindCount > 0 {
			if repo.Status.AheadCount > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%d behind", repo.Status.BehindCount)
		}
		fmt.Printf("\n")
	}

	fmt.Printf("\nRemotes:\n")
	for name, url := range repo.RemoteURLs {
		fmt.Printf("  %s: %s\n", name, url)
	}

	fmt.Printf("\nDeployment Plan:\n")
	fmt.Printf("1. Pull latest changes from origin/%s\n", options.Branch)
	if options.MergeBranch != "" {
		fmt.Printf("2. Merge %s into %s\n", options.MergeBranch, options.Branch)
	}
	if options.Force {
		fmt.Printf("3. Force push to origin/%s\n", options.Branch)
	} else {
		fmt.Printf("3. Push to origin/%s\n", options.Branch)
	}

	logger.Info("Dry run deployment completed", zap.String("repository", options.RepositoryPath))
	return nil
}
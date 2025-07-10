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

var InitCmd = &cobra.Command{
	Use:     "init",
	Aliases: []string{"initialize"},
	Short:   "Initialize a new Git repository",
	Long: `Initialize a new Git repository with optional remote and initial commit.

This command provides comprehensive repository initialization:
- Create new Git repository
- Set up remote repository
- Create initial commit
- Configure default branch
- Optional GitHub CLI integration

Examples:
  eos git init                                    # Initialize current directory
  eos git init --path /new/repo                  # Initialize specific directory
  eos git init --remote-url https://github.com/user/repo.git --initial-commit
  eos git init --interactive                     # Interactive mode`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		remoteURL, _ := cmd.Flags().GetString("remote-url")
		remoteName, _ := cmd.Flags().GetString("remote-name")
		defaultBranch, _ := cmd.Flags().GetString("default-branch")
		initialCommit, _ := cmd.Flags().GetBool("initial-commit")
		commitMessage, _ := cmd.Flags().GetString("commit-message")
		setupGitHub, _ := cmd.Flags().GetBool("setup-github")
		interactive, _ := cmd.Flags().GetBool("interactive")
			logger := otelzap.Ctx(rc.Ctx)

			if path == "" {
				var err error
				path, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			manager := git_management.NewGitManager()

			// Interactive mode
			if interactive {
				return runInteractiveInit(rc, manager)
			}

			// Build initialization options
			options := &git_management.GitInitOptions{
				Path:           path,
				InitialCommit:  initialCommit,
				CommitMessage:  commitMessage,
				RemoteURL:      remoteURL,
				RemoteName:     remoteName,
				DefaultBranch:  defaultBranch,
				SetupGitHub:    setupGitHub,
			}

			logger.Info("Initializing Git repository", 
				zap.String("path", path),
				zap.String("remote_url", remoteURL),
				zap.Bool("initial_commit", initialCommit))

			return manager.InitRepository(rc, options)
		}),
}

func init() {
	InitCmd.Flags().StringP("path", "p", "", "Path for new repository (default: current directory)")
	InitCmd.Flags().String("remote-url", "", "Remote repository URL")
	InitCmd.Flags().String("remote-name", "origin", "Remote name")
	InitCmd.Flags().String("default-branch", "main", "Default branch name")
	InitCmd.Flags().BoolP("initial-commit", "c", false, "Create initial commit")
	InitCmd.Flags().String("commit-message", "Initial commit", "Initial commit message")
	InitCmd.Flags().Bool("setup-github", false, "Setup GitHub repository using gh CLI")
	InitCmd.Flags().BoolP("interactive", "i", false, "Interactive mode")
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func runInteractiveInit(rc *eos_io.RuntimeContext, manager *git_management.GitManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Printf("Interactive Git Repository Initialization\n")
	fmt.Printf("========================================\n\n")

	options := &git_management.GitInitOptions{}

	// Repository path
	fmt.Print("Enter repository path (or press Enter for current directory): ")
	var pathInput string
	fmt.Scanln(&pathInput)
	if pathInput != "" {
		options.Path = pathInput
	} else {
		var err error
		options.Path, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
	}

	// Check if directory already has Git
	if manager.IsGitRepository(rc, options.Path) {
		fmt.Printf("Warning: %s is already a Git repository\n", options.Path)
		fmt.Print("Continue anyway? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			return fmt.Errorf("initialization cancelled")
		}
	}

	// Default branch
	fmt.Print("Enter default branch name [main]: ")
	var branch string
	fmt.Scanln(&branch)
	if branch != "" {
		options.DefaultBranch = branch
	} else {
		options.DefaultBranch = "main"
	}

	// Remote URL
	fmt.Print("Enter remote repository URL (optional): ")
	var remoteURL string
	fmt.Scanln(&remoteURL)
	options.RemoteURL = remoteURL

	if remoteURL != "" {
		fmt.Print("Enter remote name [origin]: ")
		var remoteName string
		fmt.Scanln(&remoteName)
		if remoteName != "" {
			options.RemoteName = remoteName
		} else {
			options.RemoteName = "origin"
		}
	}

	// Initial commit
	fmt.Print("Create initial commit? [Y/n]: ")
	var commitResponse string
	fmt.Scanln(&commitResponse)
	options.InitialCommit = commitResponse != "n" && commitResponse != "N"

	if options.InitialCommit {
		fmt.Print("Enter initial commit message [Initial commit]: ")
		var commitMsg string
		fmt.Scanln(&commitMsg)
		if commitMsg != "" {
			options.CommitMessage = commitMsg
		} else {
			options.CommitMessage = "Initial commit"
		}
	}

	// GitHub setup
	if remoteURL != "" {
		fmt.Print("Setup GitHub repository using gh CLI? [y/N]: ")
		var githubResponse string
		fmt.Scanln(&githubResponse)
		options.SetupGitHub = githubResponse == "y" || githubResponse == "Y"
	}

	logger.Info("Starting interactive repository initialization", 
		zap.String("path", options.Path),
		zap.String("remote", options.RemoteURL))

	return manager.InitRepository(rc, options)
}
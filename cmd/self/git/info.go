package git

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Package-level variables for info command flags
var (
	infoPath       string
	infoOutputJSON bool
	infoDetailed   bool
)

// infoCmd provides comprehensive Git repository information
var infoCmd = &cobra.Command{
	Use:     "info",
	Aliases: []string{"information"},
	Short:   "Get comprehensive Git repository information",
	Long: `Get comprehensive information about a Git repository.

This command provides detailed repository information including:
- Repository path and remotes
- Branch information and status
- Commit history and tracking
- File status and changes

Examples:
  eos git info                     # Info for current directory
  eos git info --path /repo        # Info for specific repository
  eos git info --json              # JSON output
  eos git info --detailed          # Detailed information`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if infoPath == "" {
			var err error
			infoPath, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}
		}

		manager := git_management.NewGitManager()

		if !manager.IsGitRepository(rc, infoPath) {
			return fmt.Errorf("not a git repository: %s", infoPath)
		}

		logger.Info("Getting Git repository information", zap.String("path", infoPath))

		repo, err := manager.GetRepositoryInfo(rc, infoPath)
		if err != nil {
			return fmt.Errorf("failed to get repository info: %w", err)
		}

		if infoOutputJSON {
			return outputJSONInfo(repo)
		}

		return outputTableInfo(logger, repo, infoDetailed)
	}),
}

func init() {
	infoCmd.Flags().StringVarP(&infoPath, "path", "p", "", "Path to Git repository (default: current directory)")
	infoCmd.Flags().BoolVar(&infoOutputJSON, "json", false, "Output in JSON format")
	infoCmd.Flags().BoolVarP(&infoDetailed, "detailed", "d", false, "Show detailed information")
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputJSONInfo(repo *git_management.GitRepository) error {
	data, err := json.MarshalIndent(repo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	// For JSON output, we still need to print to stdout
	fmt.Println(string(data))
	return nil
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputTableInfo(logger otelzap.LoggerWithCtx, repo *git_management.GitRepository, detailed bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() {
		if err := w.Flush(); err != nil {
			logger.Warn("Failed to flush tabwriter", zap.Error(err))
		}
	}()

	logger.Info("terminal prompt: Git Repository Information")
	logger.Info("terminal prompt: =========================")

	// Basic repository info
	fmt.Fprintf(w, "Repository Path:\t%s\n", repo.Path)

	// Status information
	if repo.Status != nil {
		fmt.Fprintf(w, "Current Branch:\t%s\n", repo.Status.Branch)
		fmt.Fprintf(w, "Repository Status:\t")
		if repo.Status.IsClean {
			fmt.Fprintf(w, "Clean\n")
		} else {
			fmt.Fprintf(w, "Has Changes\n")
		}

		if repo.Status.LastCommitHash != "" {
			fmt.Fprintf(w, "Last Commit:\t%s\n", repo.Status.LastCommitHash[:8])
			if repo.Status.LastCommitDate != "" {
				fmt.Fprintf(w, "Commit Date:\t%s\n", repo.Status.LastCommitDate)
			}
		}

		if repo.Status.AheadCount > 0 || repo.Status.BehindCount > 0 {
			fmt.Fprintf(w, "Sync Status:\t")
			if repo.Status.AheadCount > 0 {
				fmt.Fprintf(w, "%d ahead", repo.Status.AheadCount)
			}
			if repo.Status.BehindCount > 0 {
				if repo.Status.AheadCount > 0 {
					fmt.Fprintf(w, ", ")
				}
				fmt.Fprintf(w, "%d behind", repo.Status.BehindCount)
			}
			fmt.Fprintf(w, "\n")
		}
	}

	fmt.Fprintf(w, "\n")

	// Remote information
	logger.Info("terminal prompt: Remotes:")
	if len(repo.RemoteURLs) == 0 {
		logger.Info("terminal prompt:   No remotes configured")
	} else {
		for name, url := range repo.RemoteURLs {
			logger.Info("terminal prompt: Remote", 
				zap.String("name", name),
				zap.String("url", url))
		}
	}

	// Branch information
	if len(repo.Branches) > 0 {
		logger.Info("terminal prompt: Branches:")
		for i, branch := range repo.Branches {
			if detailed {
				logger.Info("terminal prompt: Branch", zap.String("branch", branch))
			} else {
				// Show only first few branches if not detailed
				if i < 5 {
					logger.Info("terminal prompt: Branch", zap.String("branch", branch))
				}
			}
		}
		if !detailed && len(repo.Branches) > 5 {
			logger.Info("terminal prompt: More branches available", 
				zap.Int("additional", len(repo.Branches)-5))
		}
	}

	// File status details
	if detailed && repo.Status != nil {
		if len(repo.Status.Staged) > 0 {
			logger.Info("terminal prompt: Staged Files", zap.Int("count", len(repo.Status.Staged)))
			for _, file := range repo.Status.Staged {
				logger.Info("terminal prompt: + Staged", zap.String("file", file))
			}
		}

		if len(repo.Status.Modified) > 0 {
			logger.Info("terminal prompt: Modified Files", zap.Int("count", len(repo.Status.Modified)))
			for _, file := range repo.Status.Modified {
				logger.Info("terminal prompt: M Modified", zap.String("file", file))
			}
		}

		if len(repo.Status.Untracked) > 0 {
			logger.Info("terminal prompt: Untracked Files", zap.Int("count", len(repo.Status.Untracked)))
			for _, file := range repo.Status.Untracked {
				logger.Info("terminal prompt: ? Untracked", zap.String("file", file))
			}
		}
	} else if repo.Status != nil && (!repo.Status.IsClean) {
		logger.Info("terminal prompt: File Changes:")
		logger.Info("terminal prompt: File counts",
			zap.Int("staged", len(repo.Status.Staged)),
			zap.Int("modified", len(repo.Status.Modified)),
			zap.Int("untracked", len(repo.Status.Untracked)))
		logger.Info("terminal prompt: (use --detailed to see file names)")
	}

	return nil
}

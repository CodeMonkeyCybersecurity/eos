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

		return outputTableInfo(repo, infoDetailed)
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
	fmt.Println(string(data))
	return nil
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputTableInfo(repo *git_management.GitRepository, detailed bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Printf("Git Repository Information\n")
	fmt.Printf("=========================\n\n")

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
	fmt.Printf("Remotes:\n")
	if len(repo.RemoteURLs) == 0 {
		fmt.Printf("  No remotes configured\n")
	} else {
		for name, url := range repo.RemoteURLs {
			fmt.Printf("  %s: %s\n", name, url)
		}
	}

	// Branch information
	if len(repo.Branches) > 0 {
		fmt.Printf("\nBranches:\n")
		for _, branch := range repo.Branches {
			if detailed {
				fmt.Printf("  %s\n", branch)
			} else {
				// Show only first few branches if not detailed
				if len(repo.Branches) <= 5 {
					fmt.Printf("  %s\n", branch)
				}
			}
		}
		if !detailed && len(repo.Branches) > 5 {
			fmt.Printf("  ... and %d more (use --detailed to see all)\n", len(repo.Branches)-5)
		}
	}

	// File status details
	if detailed && repo.Status != nil {
		if len(repo.Status.Staged) > 0 {
			fmt.Printf("\nStaged Files (%d):\n", len(repo.Status.Staged))
			for _, file := range repo.Status.Staged {
				fmt.Printf("  + %s\n", file)
			}
		}

		if len(repo.Status.Modified) > 0 {
			fmt.Printf("\nModified Files (%d):\n", len(repo.Status.Modified))
			for _, file := range repo.Status.Modified {
				fmt.Printf("  M %s\n", file)
			}
		}

		if len(repo.Status.Untracked) > 0 {
			fmt.Printf("\nUntracked Files (%d):\n", len(repo.Status.Untracked))
			for _, file := range repo.Status.Untracked {
				fmt.Printf("  ? %s\n", file)
			}
		}
	} else if repo.Status != nil && (!repo.Status.IsClean) {
		fmt.Printf("\nFile Changes:\n")
		fmt.Printf("  Staged: %d files\n", len(repo.Status.Staged))
		fmt.Printf("  Modified: %d files\n", len(repo.Status.Modified))
		fmt.Printf("  Untracked: %d files\n", len(repo.Status.Untracked))
		fmt.Printf("  (use --detailed to see file names)\n")
	}

	return nil
}

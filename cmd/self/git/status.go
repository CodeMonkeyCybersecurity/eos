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

var StatusCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"st"},
	Short:   "Get Git repository status",
	Long: `Get comprehensive status information about a Git repository.

This command provides detailed information about:
- Current branch and tracking status
- Staged, modified, and untracked files
- Commits ahead/behind remote
- Last commit information

Examples:
  eos git status                    # Status of current directory
  eos git status --path /repo       # Status of specific repository
  eos git status --json            # JSON output
  eos git status --detailed        # Detailed file information`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		outputJSON, _ := cmd.Flags().GetBool("json")
		detailed, _ := cmd.Flags().GetBool("detailed")
			logger := otelzap.Ctx(rc.Ctx)

			if path == "" {
				var err error
				path, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			logger.Info("Getting Git repository status", zap.String("path", path))

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, path) {
				return fmt.Errorf("not a git repository: %s", path)
			}

			status, err := manager.GetStatus(rc, path)
			if err != nil {
				return fmt.Errorf("failed to get repository status: %w", err)
			}

			if outputJSON {
				return outputJSONStatus(status)
			}

			return outputTableStatus(status, detailed)
		}),
}

func init() {
	StatusCmd.Flags().StringP("path", "p", "", "Path to Git repository (default: current directory)")
	StatusCmd.Flags().Bool("json", false, "Output in JSON format")
	StatusCmd.Flags().BoolP("detailed", "d", false, "Show detailed file information")
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputJSONStatus(status *git_management.GitStatus) error {
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}
// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputTableStatus(status *git_management.GitStatus, detailed bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Printf("Git Repository Status\n")
	fmt.Printf("=====================\n\n")

	// Branch information
	fmt.Fprintf(w, "Branch:\t%s\n", status.Branch)
	
	if status.AheadCount > 0 || status.BehindCount > 0 {
		fmt.Fprintf(w, "Tracking:\t")
		if status.AheadCount > 0 {
			fmt.Fprintf(w, "%d ahead", status.AheadCount)
		}
		if status.BehindCount > 0 {
			if status.AheadCount > 0 {
				fmt.Fprintf(w, ", ")
			}
			fmt.Fprintf(w, "%d behind", status.BehindCount)
		}
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "Clean:\t%t\n", status.IsClean)
	
	if status.LastCommitHash != "" {
		fmt.Fprintf(w, "Last Commit:\t%s\n", status.LastCommitHash[:8])
		if status.LastCommitDate != "" {
			fmt.Fprintf(w, "Commit Date:\t%s\n", status.LastCommitDate)
		}
	}

	fmt.Fprintf(w, "\n")

	// File counts
	fmt.Fprintf(w, "Staged Files:\t%d\n", len(status.Staged))
	fmt.Fprintf(w, "Modified Files:\t%d\n", len(status.Modified))
	fmt.Fprintf(w, "Untracked Files:\t%d\n", len(status.Untracked))

	// Detailed file listing if requested
	if detailed {
		if len(status.Staged) > 0 {
			fmt.Printf("\nStaged Files:\n")
			for _, file := range status.Staged {
				fmt.Printf("  + %s\n", file)
			}
		}

		if len(status.Modified) > 0 {
			fmt.Printf("\nModified Files:\n")
			for _, file := range status.Modified {
				fmt.Printf("  M %s\n", file)
			}
		}

		if len(status.Untracked) > 0 {
			fmt.Printf("\nUntracked Files:\n")
			for _, file := range status.Untracked {
				fmt.Printf("  ? %s\n", file)
			}
		}
	}

	return nil
}
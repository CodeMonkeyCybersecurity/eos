// cmd/update/cleanup.go
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
)

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up unused packages and system files",
	Long: `Remove orphaned packages, unused dependencies, and old kernels.
	
This command performs comprehensive system cleanup by:
- Finding and removing orphaned packages (using deborphan)
- Running apt autoremove for unused dependencies  
- Identifying and optionally removing unused kernel packages

By default, runs in interactive mode for safety.`,
	RunE: eos_cli.Wrap(runSystemCleanup),
}

var (
	nonInteractive bool
	orphansOnly    bool
	kernelsOnly    bool
)

func init() {
	UpdateCmd.AddCommand(cleanupCmd)

	cleanupCmd.Flags().BoolVarP(&nonInteractive, "yes", "y", false,
		"Run in non-interactive mode (skip prompts)")
	cleanupCmd.Flags().BoolVar(&orphansOnly, "orphans-only", false,
		"Only remove orphaned packages")
	cleanupCmd.Flags().BoolVar(&kernelsOnly, "kernels-only", false,
		"Only remove unused kernels")
}

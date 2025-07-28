// cmd/nuke/nuke.go
// Top-level nuke command that delegates to delete nuke

package nuke

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/delete"
)

// NukeCmd is the top-level nuke command that delegates to delete nuke
var NukeCmd = &cobra.Command{
	Use:   "nuke",
	Short: "Destroy all eos-managed infrastructure (alias for 'delete nuke')",
	Long: `Completely remove all infrastructure created by eos.
This is an alias for 'eos delete nuke' for convenience.

WARNING: This is a destructive operation that cannot be undone!

The nuke process will:
1. Stop and remove all running services
2. Uninstall all packages installed by eos
3. Remove all configuration files and directories
4. Clean up any Salt states and pillars
5. Remove state tracking files

Examples:
  eos nuke              # Destroy all infrastructure (with confirmation)
  eos nuke --force      # Skip confirmation prompt
  eos nuke --all        # Also remove eos itself
  eos nuke --keep-data  # Preserve data directories
  eos nuke --dev        # Development mode - preserve dev tools`,
	// Delegate to the actual nuke command in delete
	RunE: func(cmd *cobra.Command, args []string) error {
		// Find the nuke command in delete
		for _, subCmd := range delete.DeleteCmd.Commands() {
			if subCmd.Name() == "nuke" {
				// Copy flag values
				if cmd.Flags().Changed("all") {
					subCmd.Flags().Set("all", cmd.Flag("all").Value.String())
				}
				if cmd.Flags().Changed("force") {
					subCmd.Flags().Set("force", cmd.Flag("force").Value.String())
				}
				if cmd.Flags().Changed("keep-data") {
					subCmd.Flags().Set("keep-data", cmd.Flag("keep-data").Value.String())
				}
				if cmd.Flags().Changed("exclude") {
					subCmd.Flags().Set("exclude", cmd.Flag("exclude").Value.String())
				}
				if cmd.Flags().Changed("dev") {
					subCmd.Flags().Set("dev", cmd.Flag("dev").Value.String())
				}
				
				// Execute the actual command
				return subCmd.RunE(cmd, args)
			}
		}
		return nil
	},
}

func init() {
	// Copy flags from delete nuke
	NukeCmd.Flags().Bool("all", false, "Remove everything including eos itself")
	NukeCmd.Flags().Bool("force", false, "Skip confirmation prompts")
	NukeCmd.Flags().Bool("keep-data", false, "Keep data directories (logs, databases)")
	NukeCmd.Flags().StringSlice("exclude", []string{}, "Components to exclude from removal")
	NukeCmd.Flags().Bool("dev", false, "Development mode - preserve development tools")
}
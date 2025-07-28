package delete

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nuke"
	"github.com/spf13/cobra"
)

var nukeCmd = &cobra.Command{
	Use:   "nuke",
	Short: "Destroy all eos-managed infrastructure",
	Long: `Completely remove all infrastructure created by eos.
This command will destroy components in reverse order of creation to ensure clean removal.

WARNING: This is a destructive operation that cannot be undone!

The nuke process will:
1. Stop and remove all running services
2. Uninstall all packages installed by eos
3. Remove all configuration files and directories
4. Clean up any Salt states and pillars
5. Remove state tracking files

Use --force to skip confirmation prompts.`,
	RunE: eos_cli.Wrap(runNuke),
}

func init() {
	DeleteCmd.AddCommand(nukeCmd)

	nukeCmd.Flags().Bool("all", false, "Remove everything including eos itself")
	nukeCmd.Flags().Bool("force", false, "Skip confirmation prompts")
	nukeCmd.Flags().Bool("keep-data", false, "Keep data directories (logs, databases)")
	nukeCmd.Flags().StringSlice("exclude", []string{}, "Components to exclude from removal")
	nukeCmd.Flags().Bool("dev", false, "Development mode - preserve development tools")
}

func runNuke(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Parse flags into configuration
	config := &nuke.Config{
		RemoveAll:   cmd.Flag("all").Value.String() == "true",
		Force:       cmd.Flag("force").Value.String() == "true",
		KeepData:    cmd.Flag("keep-data").Value.String() == "true",
		DevMode:     cmd.Flag("dev").Value.String() == "true",
	}

	// Get exclude list
	var err error
	config.ExcludeList, err = cmd.Flags().GetStringSlice("exclude")
	if err != nil {
		config.ExcludeList = []string{}
	}

	// Delegate to nuke package helper
	return nuke.ExecuteNuke(rc, config)
}
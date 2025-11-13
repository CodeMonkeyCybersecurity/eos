package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var containerComposeCmd = &cobra.Command{
	Use:     "container-compose",
	Aliases: []string{"docker-compose", "stop-compose", "compose-stop"},
	Short:   "Stop all Docker Compose projects",
	Long: `Stop all Docker Compose projects found in search directories.

This command finds all compose projects and stops them using 'docker compose down'.
It can handle running containers and provides confirmation prompts for safety.

Examples:
  eos update container-compose                          # Stop all projects with confirmation
  eos update container-compose --force                 # Stop without confirmation
  eos update container-compose --dry-run               # Show what would be stopped
  eos update container-compose --remove-volumes        # Remove volumes when stopping
  eos update container-compose --path /opt             # Stop projects in specific path`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		searchPaths, _ := cmd.Flags().GetStringSlice("path")
		force, _ := cmd.Flags().GetBool("force")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		noConfirm, _ := cmd.Flags().GetBool("no-confirm")
		removeVolumes, _ := cmd.Flags().GetBool("remove-volumes")
		removeImages, _ := cmd.Flags().GetBool("remove-images")
		timeout, _ := cmd.Flags().GetInt("timeout")
		ignoreRunning, _ := cmd.Flags().GetBool("ignore-running")
		outputJSON, _ := cmd.Flags().GetBool("json")

		options := &container_management.ComposeStopOptions{
			SearchPaths:    searchPaths,
			ConfirmEach:    !noConfirm,
			Force:          force,
			StopContainers: true,
			IgnoreRunning:  ignoreRunning,
			DryRun:         dryRun,
			RemoveVolumes:  removeVolumes,
			RemoveImages:   removeImages,
			Timeout:        timeout,
		}

		logger.Info("Stopping Docker Compose projects",
			zap.Strings("search_paths", searchPaths),
			zap.Bool("force", force),
			zap.Bool("dry_run", dryRun))

		result, err := container_management.StopAllComposeProjects(rc, nil, options)
		if err != nil {
			logger.Error("Failed to stop compose projects", zap.Error(err))
			return err
		}

		if outputJSON {
			return container_management.OutputComposeStopJSON(result)
		}

		return container_management.OutputComposeStopTable(result)
	}),
}

func init() {
	containerComposeCmd.Flags().StringSliceP("path", "p", []string{}, "Search paths (default: $HOME, /opt, /srv, /home)")
	containerComposeCmd.Flags().Bool("force", false, "Force stop without confirmation")
	containerComposeCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	containerComposeCmd.Flags().Bool("no-confirm", false, "Don't confirm each project (same as --force)")
	containerComposeCmd.Flags().Bool("remove-volumes", false, "Remove named volumes declared in the volumes section")
	containerComposeCmd.Flags().Bool("remove-images", false, "Remove all images used by services")
	containerComposeCmd.Flags().Int("timeout", 30, "Timeout in seconds for stopping containers")
	containerComposeCmd.Flags().Bool("ignore-running", false, "Don't check for running containers first")
	containerComposeCmd.Flags().Bool("json", false, "Output in JSON format")

	// Register with parent command
	UpdateCmd.AddCommand(containerComposeCmd)
}

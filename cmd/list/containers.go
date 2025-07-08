package list

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListContainers creates the container listing command
func ListContainers() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "ps"},
		Short:   "List running Docker containers",
		Long: `List all running Docker containers with their details.

Shows container ID, name, image, status, and port mappings.

Examples:
  eos container list                       # List running containers
  eos container list --json               # Output in JSON format
  eos container list --all                # List all containers (running and stopped)`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			outputJSON, _ := cmd.Flags().GetBool("json")
			showAll, _ := cmd.Flags().GetBool("all")

			logger.Info("Listing Docker containers",
				zap.Bool("json", outputJSON),
				zap.Bool("all", showAll))

			manager := container_management.NewContainerManager(nil)
			result, err := manager.ListRunningContainers(rc)
			if err != nil {
				logger.Error("Failed to list containers", zap.Error(err))
				return err
			}

			if outputJSON {
				return container.OutputContainerJSON(result)
			}

			return container.OutputContainerTable(result)
		}),
	}

	cmd.Flags().Bool("json", false, "Output in JSON format")
	cmd.Flags().BoolP("all", "a", false, "Show all containers (running and stopped)")

	return cmd
}

var containerComposeCmd = &cobra.Command{
	Use:     "container-compose",
	Aliases: []string{"docker-compose", "compose-projects", "compose"},
	Short:   "List Docker Compose projects with status",
	Long: `List all Docker Compose projects with their current status.

Shows project path, compose file, and running status for each found project.

Examples:
  eos list container-compose                          # List all projects
  eos list container-compose --path /opt             # List projects in specific path
  eos list container-compose --json                  # Output in JSON format`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		searchPaths, _ := cmd.Flags().GetStringSlice("path")
		outputJSON, _ := cmd.Flags().GetBool("json")

		logger.Info("Listing Docker Compose projects",
			zap.Strings("search_paths", searchPaths))

		manager := container_management.NewContainerManager(nil)
		result, err := manager.FindComposeProjects(rc, searchPaths)
		if err != nil {
			logger.Error("Failed to list compose projects", zap.Error(err))
			return err
		}

		if outputJSON {
			return container.OutputComposeListJSON(result)
		}

		return container.OutputComposeListTable(result)
	}),
}

func init() {
	containerComposeCmd.Flags().StringSliceP("path", "p", []string{}, "Search paths (default: $HOME, /opt, /srv, /home)")
	containerComposeCmd.Flags().Bool("json", false, "Output in JSON format")

	// Register with parent command
	ListCmd.AddCommand(containerComposeCmd)
}

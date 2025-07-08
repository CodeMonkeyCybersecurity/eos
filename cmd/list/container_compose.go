package list

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container_management"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

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
			return outputComposeListJSON(result)
		}

		return outputComposeListTable(result)
	}),
}

func init() {
	containerComposeCmd.Flags().StringSliceP("path", "p", []string{}, "Search paths (default: $HOME, /opt, /srv, /home)")
	containerComposeCmd.Flags().Bool("json", false, "Output in JSON format")

	// Register with parent command
	ListCmd.AddCommand(containerComposeCmd)
}

func outputComposeListJSON(result *container_management.ComposeSearchResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputComposeListTable(result *container_management.ComposeSearchResult) error {
	if result.TotalFound == 0 {
		fmt.Println("No compose projects found.")
		return nil
	}

	fmt.Printf("Found %d compose projects\n\n", result.TotalFound)

	// Print header
	fmt.Printf("%-40s %-20s %-10s %s\n", "PATH", "COMPOSE FILE", "STATUS", "LAST SEEN")
	fmt.Println(strings.Repeat("-", 90))

	// Print projects
	for _, project := range result.Projects {
		status := project.Status
		if status == "" {
			status = "unknown"
		}

		fmt.Printf("%-40s %-20s %-10s %s\n",
			truncateString(project.Path, 40),
			project.ComposeFile,
			status,
			project.LastSeen.Format("01-02 15:04"))
	}

	return nil
}

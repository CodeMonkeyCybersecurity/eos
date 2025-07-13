package read

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
	Aliases: []string{"docker-compose", "compose-projects", "find-compose"},
	Short:   "Find and inspect Docker Compose projects",
	Long: `Find and inspect Docker Compose projects in specified directories.

Searches recursively through directories looking for docker-compose.yml, 
docker-compose.yaml, compose.yml, or compose.yaml files.

Examples:
  eos read container-compose                          # Search default paths
  eos read container-compose --path /opt --path /srv # Search specific paths
  eos read container-compose --json                  # Output in JSON format`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		searchPaths, _ := cmd.Flags().GetStringSlice("path")
		outputJSON, _ := cmd.Flags().GetBool("json")

		logger.Info("Finding Docker Compose projects",
			zap.Strings("search_paths", searchPaths),
			zap.Bool("json", outputJSON))

		manager := container_management.NewContainerManager(nil)
		result, err := manager.FindComposeProjects(rc, searchPaths)
		if err != nil {
			logger.Error("Failed to find compose projects", zap.Error(err))
			return err
		}

		if outputJSON {
			return outputComposeSearchJSON(result)
		}

		return outputComposeSearchTable(result)
	}),
}

func init() {
	containerComposeCmd.Flags().StringSliceP("path", "p", []string{}, "Search paths (default: $HOME, /opt, /srv, /home)")
	containerComposeCmd.Flags().Bool("json", false, "Output in JSON format")

	// Register with parent command
	ReadCmd.AddCommand(containerComposeCmd)
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
// Output formatting functions
func outputComposeSearchJSON(result *container_management.ComposeSearchResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputComposeSearchTable(result *container_management.ComposeSearchResult) error {
	logger.Info("terminal prompt: Searched paths: %s", strings.Join(result.SearchPaths, ", "))
	logger.Info("terminal prompt: Search duration: %v", result.SearchDuration)
	logger.Info("terminal prompt: Projects found: %d\n", result.TotalFound)

	if result.TotalFound == 0 {
		logger.Info("terminal prompt: No compose projects found.")
		return nil
	}

	for _, project := range result.Projects {
		logger.Info("terminal prompt: Path: %s", project.Path)
		logger.Info("terminal prompt:   Compose file: %s", project.ComposeFile)
		if project.Status != "" {
			logger.Info("terminal prompt:   Status: %s", project.Status)
		}
		logger.Info("terminal prompt:   Last seen: %s", project.LastSeen.Format("2006-01-02 15:04:05"))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", )))
	}

	return nil
}

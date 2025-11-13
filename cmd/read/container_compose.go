package read

import (
	"encoding/json"
	"fmt"
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

		result, err := container_management.FindComposeProjects(rc, nil, searchPaths)
		if err != nil {
			logger.Error("Failed to find compose projects", zap.Error(err))
			return err
		}

		if outputJSON {
			return outputComposeSearchJSON(logger, result)
		}

		return outputComposeSearchTable(logger, result)
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
func outputComposeSearchJSON(logger otelzap.LoggerWithCtx, result *container_management.ComposeSearchResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	logger.Info("terminal prompt: JSON output", zap.String("data", string(data)))
	return nil
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func outputComposeSearchTable(logger otelzap.LoggerWithCtx, result *container_management.ComposeSearchResult) error {
	logger.Info("terminal prompt: Searched paths", zap.String("paths", strings.Join(result.SearchPaths, ", ")))
	logger.Info("terminal prompt: Search duration", zap.Duration("duration", result.SearchDuration))
	logger.Info("terminal prompt: Projects found", zap.Int("count", result.TotalFound))

	if result.TotalFound == 0 {
		logger.Info("terminal prompt: No compose projects found.")
		return nil
	}

	for _, project := range result.Projects {
		logger.Info("terminal prompt: Path", zap.String("path", project.Path))
		logger.Info("terminal prompt:   Compose file", zap.String("file", project.ComposeFile))
		if project.Status != "" {
			logger.Info("terminal prompt:   Status", zap.String("status", project.Status))
		}
		logger.Info("terminal prompt:   Last seen", zap.String("time", project.LastSeen.Format("2006-01-02 15:04:05")))
	}

	return nil
}

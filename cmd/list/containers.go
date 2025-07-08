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
				return outputContainerJSON(result)
			}

			return outputContainerTable(result)
		}),
	}

	cmd.Flags().Bool("json", false, "Output in JSON format")
	cmd.Flags().BoolP("all", "a", false, "Show all containers (running and stopped)")

	return cmd
}

// outputContainerJSON outputs container list in JSON format
func outputContainerJSON(result *container_management.ContainerListResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputContainerTable outputs container list in table format
func outputContainerTable(result *container_management.ContainerListResult) error {
	if result.Total == 0 {
		fmt.Println("No containers found.")
		return nil
	}

	fmt.Printf("Containers: %d total, %d running, %d stopped\n",
		result.Total, result.Running, result.Stopped)
	fmt.Printf("Listed at: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	// Print header
	fmt.Printf("%-12s %-20s %-30s %-20s %s\n",
		"CONTAINER ID", "NAME", "IMAGE", "STATUS", "PORTS")
	fmt.Println(strings.Repeat("-", 100))

	// Print containers
	for _, container := range result.Containers {
		portStr := formatPorts(container.Ports)
		fmt.Printf("%-12s %-20s %-30s %-20s %s\n",
			truncateString(container.ID, 12),
			truncateString(container.Name, 20),
			truncateString(container.Image, 30),
			truncateString(container.Status, 20),
			portStr)
	}

	return nil
}

// formatPorts formats the ports map for display
func formatPorts(ports map[string]string) string {
	if len(ports) == 0 {
		return "-"
	}

	var portStrs []string
	for containerPort, hostPort := range ports {
		portStrs = append(portStrs, fmt.Sprintf("%s->%s", hostPort, containerPort))
	}

	result := strings.Join(portStrs, ", ")
	return truncateString(result, 25)
}

// truncateString truncates a string if it's longer than maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

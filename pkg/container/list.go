package container

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container_management"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

// OutputContainerJSON outputs container list in JSON format
func OutputContainerJSON(result *container_management.ContainerListResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// OutputContainerTable outputs container list in table format
func OutputContainerTable(result *container_management.ContainerListResult) error {
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
		portStr := FormatPorts(container.Ports)
		fmt.Printf("%-12s %-20s %-30s %-20s %s\n",
			utils.TruncateString(container.ID, 12),
			utils.TruncateString(container.Name, 20),
			utils.TruncateString(container.Image, 30),
			utils.TruncateString(container.Status, 20),
			portStr)
	}

	return nil
}

// FormatPorts formats the ports map for display
func FormatPorts(ports map[string]string) string {
	if len(ports) == 0 {
		return "-"
	}

	var portStrs []string
	for containerPort, hostPort := range ports {
		portStrs = append(portStrs, fmt.Sprintf("%s->%s", hostPort, containerPort))
	}

	result := strings.Join(portStrs, ", ")
	return utils.TruncateString(result, 25)
}

func OutputComposeListJSON(result *container_management.ComposeSearchResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func OutputComposeListTable(result *container_management.ComposeSearchResult) error {
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
			utils.TruncateString(project.Path, 40),
			project.ComposeFile,
			status,
			project.LastSeen.Format("01-02 15:04"))
	}

	return nil
}

package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ContainerDiagnostics runs container-specific diagnostics
// Migrated from cmd/ragequit/ragequit.go containerDiagnostics
func ContainerDiagnostics(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if containers are present
	logger.Info("Assessing container diagnostics requirements")
	
	hasDocker := system.CommandExists("docker")
	hasPodman := system.CommandExists("podman")
	hasKubectl := system.CommandExists("kubectl")
	hasLXC := system.CommandExists("lxc")
	
	if !hasDocker && !hasPodman && !hasKubectl && !hasLXC {
		logger.Info("No container runtimes detected, skipping container diagnostics")
		return nil
	}
	
	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-containers.txt")
	
	var output strings.Builder
	output.WriteString("=== Container Diagnostics ===\n")
	output.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339)))
	
	// INTERVENE - Collect container information
	logger.Debug("Collecting container information")
	
	// Docker diagnostics
	if hasDocker {
		output.WriteString("=== Docker Information ===\n")
		
		// Docker version
		if dockerVersion := system.RunCommandWithTimeout("docker", []string{"version"}, 5*time.Second); dockerVersion != "" {
			output.WriteString(dockerVersion)
			output.WriteString("\n")
		}
		
		// Docker info
		if dockerInfo := system.RunCommandWithTimeout("docker", []string{"info"}, 5*time.Second); dockerInfo != "" {
			output.WriteString("\n=== Docker System Info ===\n")
			output.WriteString(dockerInfo)
			output.WriteString("\n")
		}
		
		// Running containers
		if dockerPs := system.RunCommandWithTimeout("docker", []string{"ps", "-a"}, 5*time.Second); dockerPs != "" {
			output.WriteString("\n=== Docker Containers ===\n")
			output.WriteString(dockerPs)
			output.WriteString("\n")
		}
		
		// Docker images
		if dockerImages := system.RunCommandWithTimeout("docker", []string{"images"}, 5*time.Second); dockerImages != "" {
			output.WriteString("\n=== Docker Images ===\n")
			output.WriteString(dockerImages)
			output.WriteString("\n")
		}
		
		// Docker networks
		if dockerNetworks := system.RunCommandWithTimeout("docker", []string{"network", "ls"}, 5*time.Second); dockerNetworks != "" {
			output.WriteString("\n=== Docker Networks ===\n")
			output.WriteString(dockerNetworks)
			output.WriteString("\n")
		}
		
		// Docker volumes
		if dockerVolumes := system.RunCommandWithTimeout("docker", []string{"volume", "ls"}, 5*time.Second); dockerVolumes != "" {
			output.WriteString("\n=== Docker Volumes ===\n")
			output.WriteString(dockerVolumes)
			output.WriteString("\n")
		}
		
		// Get logs from problematic containers
		if dockerPs := system.RunCommandWithTimeout("docker", 
			[]string{"ps", "-a", "--format", "{{.ID}} {{.Status}}"}, 5*time.Second); dockerPs != "" {
			lines := strings.Split(dockerPs, "\n")
			for _, line := range lines {
				if strings.Contains(line, "Exited") || strings.Contains(line, "Error") {
					parts := strings.Fields(line)
					if len(parts) > 0 {
						containerID := parts[0]
						output.WriteString(fmt.Sprintf("\n=== Logs for container %s ===\n", containerID))
						if logs := system.RunCommandWithTimeout("docker", 
							[]string{"logs", "--tail", "50", containerID}, 5*time.Second); logs != "" {
							output.WriteString(logs)
							output.WriteString("\n")
						}
					}
				}
			}
		}
	}
	
	// Podman diagnostics
	if hasPodman {
		output.WriteString("\n=== Podman Information ===\n")
		
		if podmanVersion := system.RunCommandWithTimeout("podman", []string{"version"}, 5*time.Second); podmanVersion != "" {
			output.WriteString(podmanVersion)
			output.WriteString("\n")
		}
		
		if podmanPs := system.RunCommandWithTimeout("podman", []string{"ps", "-a"}, 5*time.Second); podmanPs != "" {
			output.WriteString("\n=== Podman Containers ===\n")
			output.WriteString(podmanPs)
			output.WriteString("\n")
		}
	}
	
	// Kubernetes diagnostics
	if hasKubectl {
		output.WriteString("\n=== Kubernetes Information ===\n")
		
		if k8sVersion := system.RunCommandWithTimeout("kubectl", []string{"version", "--short"}, 5*time.Second); k8sVersion != "" {
			output.WriteString(k8sVersion)
			output.WriteString("\n")
		}
		
		if k8sNodes := system.RunCommandWithTimeout("kubectl", []string{"get", "nodes", "-o", "wide"}, 5*time.Second); k8sNodes != "" {
			output.WriteString("\n=== Kubernetes Nodes ===\n")
			output.WriteString(k8sNodes)
			output.WriteString("\n")
		}
		
		if k8sPods := system.RunCommandWithTimeout("kubectl", []string{"get", "pods", "--all-namespaces"}, 5*time.Second); k8sPods != "" {
			output.WriteString("\n=== Kubernetes Pods ===\n")
			output.WriteString(k8sPods)
			output.WriteString("\n")
		}
		
		// Get events for troubleshooting
		if k8sEvents := system.RunCommandWithTimeout("kubectl", 
			[]string{"get", "events", "--all-namespaces", "--sort-by='.lastTimestamp'"}, 5*time.Second); k8sEvents != "" {
			output.WriteString("\n=== Recent Kubernetes Events ===\n")
			lines := strings.Split(k8sEvents, "\n")
			if len(lines) > 50 {
				output.WriteString(strings.Join(lines[:50], "\n"))
				output.WriteString("\n... (truncated)\n")
			} else {
				output.WriteString(k8sEvents)
			}
			output.WriteString("\n")
		}
	}
	
	// LXC/LXD diagnostics
	if hasLXC {
		output.WriteString("\n=== LXC/LXD Information ===\n")
		
		if lxcList := system.RunCommandWithTimeout("lxc", []string{"list"}, 5*time.Second); lxcList != "" {
			output.WriteString(lxcList)
			output.WriteString("\n")
		}
	}
	
	// EVALUATE - Write results
	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		return fmt.Errorf("failed to write container diagnostics: %w", err)
	}
	
	logger.Info("Container diagnostics completed",
		zap.String("output_file", outputFile))
	
	return nil
}
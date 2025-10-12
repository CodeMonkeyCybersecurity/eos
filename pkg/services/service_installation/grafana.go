// pkg/service_installation/grafana.go
package service_installation

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var interactive bool

func RunInteractiveGrafanaSetup(options *ServiceInstallOptions) error {
	fmt.Printf("Interactive Grafana Setup\n")
	fmt.Printf("============================\n\n")

	// Version
	fmt.Printf("Grafana version [%s]: ", options.Version)
	var version string
	if _, err := fmt.Scanln(&version); err != nil {
		fmt.Printf("Warning: Failed to read version input, using default: %v\n", err)
	}
	if version != "" {
		options.Version = version
	}

	// Port
	fmt.Printf("Port [%d]: ", options.Port)
	var portStr string
	if _, err := fmt.Scanln(&portStr); err != nil {
		fmt.Printf("Warning: Failed to read port input, using default: %v\n", err)
	}
	if portStr != "" {
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
			options.Port = port
		}
	}

	// Admin password
	fmt.Print("Set custom admin password? [y/N]: ")
	var setPassword string
	if _, err := fmt.Scanln(&setPassword); err != nil {
		fmt.Printf("Warning: Failed to read password option, using default: %v\n", err)
	}
	if setPassword == "y" || setPassword == "Y" {
		fmt.Print("Admin password: ")
		var password string
		if _, err := fmt.Scanln(&password); err != nil {
			// Handle input error
		}
		if password != "" {
			options.Environment["GF_SECURITY_ADMIN_PASSWORD"] = password
		}
	}

	// Anonymous access
	fmt.Print("Enable anonymous access? [y/N]: ")
	var anonymous string
	if _, err := fmt.Scanln(&anonymous); err != nil {
		// Handle input error
	}
	if anonymous == "y" || anonymous == "Y" {
		options.Environment["GF_AUTH_ANONYMOUS_ENABLED"] = "true"
		options.Environment["GF_AUTH_ANONYMOUS_ORG_ROLE"] = "Viewer"
	}

	// Persistence
	fmt.Print("Enable data persistence? [Y/n]: ")
	var persistence string
	if _, err := fmt.Scanln(&persistence); err != nil {
		// Handle input error
	}
	if persistence != "n" && persistence != "N" {
		options.Volumes = append(options.Volumes, VolumeMount{
			Source:      "grafana-data",
			Destination: "/var/lib/grafana",
		})
	}

	fmt.Printf("\nConfiguration Summary:\n")
	fmt.Printf("   Version: %s\n", options.Version)
	fmt.Printf("   Port: %d\n", options.Port)
	fmt.Printf("   Persistence: %t\n", len(options.Volumes) > 0)
	fmt.Printf("   Anonymous Access: %s\n", options.Environment["GF_AUTH_ANONYMOUS_ENABLED"])

	fmt.Print("\nProceed with installation? [Y/n]: ")
	var proceed string
	_, _ = fmt.Scanln(&proceed)
	if proceed == "n" || proceed == "N" {
		return fmt.Errorf("installation cancelled by user")
	}

	return nil
}

// installGrafana installs Grafana using Docker
func (sim *ServiceInstallationManager) installGrafana(rc *eos_io.RuntimeContext, options *ServiceInstallOptions, result *InstallationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Installing Grafana",
		zap.String("version", options.Version),
		zap.Int("port", options.Port),
		zap.String("method", string(options.Method)))

	if options.DryRun {
		result.Success = true
		result.Message = "Dry run completed - Grafana would be installed"
		return nil
	}

	// Step 1: Pull Grafana Docker image
	step1 := InstallationStep{
		Name:        "Pull Image",
		Description: fmt.Sprintf("Pulling Grafana Docker image (version: %s)", options.Version),
		Status:      "running",
	}
	step1Start := time.Now()

	image := fmt.Sprintf("grafana/grafana:%s", options.Version)
	if err := sim.runCommand(rc, "Pull Grafana image", "docker", "pull", image); err != nil {
		step1.Status = "failed"
		step1.Error = err.Error()
		step1.Duration = time.Since(step1Start)
		result.Steps = append(result.Steps, step1)
		return err
	}

	step1.Status = "completed"
	step1.Duration = time.Since(step1Start)
	result.Steps = append(result.Steps, step1)

	// Step 2: Create Grafana container
	step2 := InstallationStep{
		Name:        "Create Container",
		Description: "Creating and starting Grafana container",
		Status:      "running",
	}
	step2Start := time.Now()

	containerName := "grafana"
	if options.Name != "" {
		containerName = options.Name
	}

	// Remove existing container if it exists
	exec.Command("docker", "rm", "-f", containerName).Run()

	// Build docker run command
	args := []string{
		"run", "-d",
		"--name", containerName,
		"-p", fmt.Sprintf("%d:3000", options.Port),
	}

	// Add environment variables
	for key, value := range options.Environment {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	// Add volumes
	for _, volume := range options.Volumes {
		volumeSpec := fmt.Sprintf("%s:%s", volume.Source, volume.Destination)
		if volume.ReadOnly {
			volumeSpec += ":ro"
		}
		args = append(args, "-v", volumeSpec)
	}

	// Add restart policy
	args = append(args, "--restart", "unless-stopped")

	// Add image
	args = append(args, image)

	if err := sim.runCommand(rc, "Create Grafana container", "docker", args...); err != nil {
		step2.Status = "failed"
		step2.Error = err.Error()
		step2.Duration = time.Since(step2Start)
		result.Steps = append(result.Steps, step2)
		return err
	}

	step2.Status = "completed"
	step2.Duration = time.Since(step2Start)
	result.Steps = append(result.Steps, step2)

	// Set result details
	result.Success = true
	result.Version = options.Version
	result.Port = options.Port
	result.Message = fmt.Sprintf("Grafana installed successfully and running on port %d", options.Port)
	result.Endpoints = []string{fmt.Sprintf("http://localhost:%d", options.Port)}

	// Add default credentials to result
	result.Credentials = map[string]string{
		"username": "admin",
		"password": "admin",
		"note":     "Change default password on first login",
	}

	logger.Info("Grafana installation completed successfully",
		zap.String("container", containerName),
		zap.Int("port", options.Port))

	return nil
}

// getGrafanaStatus retrieves Grafana service status
func (sim *ServiceInstallationManager) getGrafanaStatus(rc *eos_io.RuntimeContext, status *ServiceStatus) (*ServiceStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Grafana container is running
	cmd := exec.Command("docker", "ps", "--filter", "name=grafana", "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}")
	output, err := cmd.Output()
	if err != nil {
		status.Status = "not_installed"
		return status, nil
	}

	if string(output) == "" {
		status.Status = "stopped"
		return status, nil
	}

	status.Status = "running"
	status.Method = MethodDocker

	// Parse port from docker output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "grafana") {
			parts := strings.Split(line, "\t")
			if len(parts) >= 3 {
				ports := parts[2]
				// Extract port number (format: 0.0.0.0:3000->3000/tcp)
				if strings.Contains(ports, "->3000/tcp") {
					portStr := strings.Split(ports, ":")[1]
					portStr = strings.Split(portStr, "->")[0]
					if port, err := strconv.Atoi(portStr); err == nil {
						status.Port = port
					}
				}
			}
			break
		}
	}

	// Get container details
	cmd = exec.Command("docker", "inspect", "grafana", "--format", "{{.State.StartedAt}}")
	if output, err := cmd.Output(); err == nil {
		if startTime, err := time.Parse(time.RFC3339, strings.TrimSpace(string(output))); err == nil {
			status.Uptime = time.Since(startTime)
		}
	}

	// Perform health check
	if status.Port > 0 {
		endpoint := fmt.Sprintf("http://localhost:%d/api/health", status.Port)
		healthCheck, err := sim.PerformHealthCheck(rc, ServiceTypeGrafana, endpoint)
		if err == nil {
			status.HealthCheck = healthCheck
		}
	}

	logger.Info("Grafana status retrieved",
		zap.String("status", status.Status),
		zap.Int("port", status.Port))

	return status, nil
}

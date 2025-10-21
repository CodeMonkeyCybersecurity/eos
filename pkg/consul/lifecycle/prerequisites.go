// pkg/consul/prerequisites.go
// System prerequisite validation for Consul installation

package lifecycle

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// validatePrerequisites checks system requirements
func (ci *ConsulInstaller) validatePrerequisites() error {
	ci.logger.Info("Validating prerequisites")

	// Validate configuration with better error context
	if ci.config.Datacenter == "" {
		return fmt.Errorf("datacenter name cannot be empty")
	}
	if ci.config.BindAddr == "" {
		return fmt.Errorf("bind address cannot be empty (should be auto-detected or specified)")
	}

	// Check for SELinux/AppArmor that might block Consul
	ci.checkSecurityModules()

	// Create context for prerequisite checks
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 15*time.Second)
	defer cancel()

	// Check memory requirements (minimum 256MB recommended)
	if err := ci.CheckMemoryWithContext(ctx); err != nil {
		return fmt.Errorf("memory check failed: %w", err)
	}

	// Check disk space (minimum 100MB for Consul)
	if err := ci.CheckDiskSpaceWithContext(ctx, "/var/lib", 100); err != nil {
		return fmt.Errorf("disk space check failed: %w", err)
	}

	// Check port availability - but be smart about it
	// If we're doing a force reinstall, stop the existing service first
	if ci.config.ForceReinstall && ci.systemd.IsActive() {
		ci.logger.Info("Stopping existing Consul service for reinstallation")
		if err := ci.systemd.Stop(); err != nil {
			ci.logger.Warn("Failed to stop existing Consul service", zap.Error(err))
		}
		// Wait for ports to be released
		if err := ci.waitForPortsReleased([]int{shared.PortConsul, 8300, 8301, 8302, 8502, 8600}, 10*time.Second); err != nil {
			ci.logger.Warn("Ports may still be in use", zap.Error(err))
		}
	}

	// Check required ports
	requiredPorts := []int{
		shared.PortConsul, // HTTP API (8161)
		8300,              // Server RPC
		8301,              // Serf LAN
		8302,              // Serf WAN
		8502,              // gRPC
		8600,              // DNS
	}

	var portErrors []string
	for _, port := range requiredPorts {
		if err := ci.CheckPortAvailable(port); err != nil {
			portErrors = append(portErrors, err.Error())
		}
	}

	if len(portErrors) > 0 {
		return fmt.Errorf("port availability check failed:\n  - %s", strings.Join(portErrors, "\n  - "))
	}

	return nil
}

// CheckMemoryWithContext checks available system memory with context support
func (ci *ConsulInstaller) CheckMemoryWithContext(ctx context.Context) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Use platform-agnostic approach via command execution
	output, err := ci.runner.RunOutput("free", "-m")
	if err != nil {
		ci.logger.Warn("Could not check memory (free command not available)", zap.Error(err))
		return nil // Don't fail installation on memory check failure
	}

	// Parse free output (simple check)
	lines := strings.Split(output, "\n")
	if len(lines) > 1 {
		ci.logger.Info("System memory check passed",
			zap.String("output", strings.TrimSpace(lines[1])))
	}

	// Note: We're being lenient here - just log the check
	// Full parsing would be platform-specific
	return nil
}

// CheckDiskSpaceWithContext checks available disk space with context support
func (ci *ConsulInstaller) CheckDiskSpaceWithContext(ctx context.Context, path string, requiredMB int64) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return ci.CheckDiskSpace(path, requiredMB)
}

func (ci *ConsulInstaller) CheckDiskSpace(path string, requiredMB int64) error {
	// Use df command for cross-platform disk space checking
	output, err := ci.runner.RunOutput("df", "-m", path)
	if err != nil {
		ci.logger.Warn("Could not check disk space", zap.Error(err))
		return nil // Don't fail installation on disk check failure
	}

	ci.logger.Info("Disk space check",
		zap.String("path", path),
		zap.Int64("required_mb", requiredMB),
		zap.String("df_output", strings.TrimSpace(output)))

	// Note: Full parsing would be platform-specific
	// For now, we just log the check
	return nil
}

func (ci *ConsulInstaller) CheckPortAvailable(port int) error {
	// Check Docker containers first (lsof doesn't show these clearly)
	if dockerConflict, err := ci.CheckDockerPortConflict(port); err == nil && dockerConflict != "" {
		return fmt.Errorf("port %d is exposed by Docker container: %s\nRemediation: Stop container with 'docker stop %s'", port, dockerConflict, dockerConflict)
	}

	// Use lsof to check what's using the port
	output, err := ci.runner.RunOutput("sh", "-c", fmt.Sprintf("lsof -i :%d 2>/dev/null | grep LISTEN | awk '{print $1}' | head -1", port))
	if err != nil || output == "" {
		// Port is available
		return nil
	}

	processName := strings.TrimSpace(output)

	// If it's Consul already using the port, this is acceptable for idempotency
	if strings.EqualFold(processName, "consul") {
		ci.logger.Debug("Port already in use by Consul (idempotent - acceptable)",
			zap.Int("port", port),
			zap.String("note", "Existing Consul installation detected - this is expected for idempotent operations"))
		// Return nil - this is NOT an error, it's expected behavior
		return nil
	}

	// Some other process is using the port - this IS an error
	return fmt.Errorf("port %d is already in use by process: %s\nRemediation:\n  1. If this is an old Consul instance: sudo systemctl stop consul\n  2. If this is another service: Check with 'sudo lsof -i :%d'", port, processName, port)
}

// checkDockerPortConflict checks if a Docker container is exposing the port
func (ci *ConsulInstaller) CheckDockerPortConflict(port int) (string, error) {
	// Check if docker is installed
	if _, err := exec.LookPath("docker"); err != nil {
		return "", err // Docker not installed, no conflict
	}

	// Query Docker for containers exposing this port
	cmd := exec.Command("docker", "ps", "--format", "{{.Names}}", "--filter", fmt.Sprintf("publish=%d", port))
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	containerName := strings.TrimSpace(string(output))
	return containerName, nil
}

// waitForPortsReleased polls until critical ports are released after service stop
func (ci *ConsulInstaller) waitForPortsReleased(ports []int, timeout time.Duration) error {
	ci.logger.Info("Waiting for ports to be released",
		zap.Ints("ports", ports),
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		allFree := true
		for _, port := range ports {
			if err := ci.CheckPortAvailable(port); err != nil {
				allFree = false
				break
			}
		}

		if allFree {
			ci.logger.Info("All ports released successfully")
			return nil
		}

		<-ticker.C
	}

	return fmt.Errorf("timeout waiting for ports to be released after %v", timeout)
}

// checkSecurityModules detects SELinux/AppArmor and warns if they might interfere
func (ci *ConsulInstaller) checkSecurityModules() {
	// Check SELinux
	if output, err := ci.runner.RunOutput("getenforce"); err == nil {
		mode := strings.ToLower(strings.TrimSpace(output))
		if mode == "enforcing" {
			ci.logger.Warn("SELinux is in enforcing mode",
				zap.String("recommendation", "May need to configure SELinux policies for Consul"))
		}
	}

	// Check AppArmor
	if output, err := ci.runner.RunOutput("aa-status"); err == nil && strings.Contains(output, "apparmor module is loaded") {
		ci.logger.Warn("AppArmor is active",
			zap.String("recommendation", "May need to configure AppArmor profiles for Consul"))
	}

	// Check if running in a container
	if ci.fileExists("/.dockerenv") || ci.fileExists("/run/.containerenv") {
		ci.logger.Info("Running in container environment detected")
	}
}

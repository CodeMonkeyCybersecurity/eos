package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/debug/metis"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckProjectStructureWithResult validates that all required Metis project files and directories exist.
func CheckProjectStructureWithResult(rc *eos_io.RuntimeContext, projectDir string, verbose bool) metis.CheckResult {
	err := checkProjectStructure(rc, projectDir, verbose)
	result := metis.CheckResult{
		Name:     "Project Structure",
		Category: "Infrastructure",
		Passed:   err == nil,
		Error:    err,
	}

	if err != nil {
		result.Remediation = []string{
			"Install Metis using: eos create metis",
			"Or clone from repository: git clone <metis-repo> /opt/metis",
			fmt.Sprintf("Ensure directory exists: sudo mkdir -p %s", projectDir),
			"Verify required subdirectories: worker/, webhook/",
		}
	} else {
		result.Details = fmt.Sprintf("All required files present in %s", projectDir)
	}

	return result
}

func checkProjectStructure(rc *eos_io.RuntimeContext, projectDir string, verbose bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	requiredPaths := []string{
		projectDir,
		filepath.Join(projectDir, "worker"),
		filepath.Join(projectDir, "webhook"),
		filepath.Join(projectDir, "worker", "main.go"),
		filepath.Join(projectDir, "webhook", "main.go"),
		filepath.Join(projectDir, "config.yaml"),
	}

	for _, path := range requiredPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("missing required path: %s", path)
		}
		if verbose {
			logger.Debug("Found", zap.String("path", path))
		}
	}

	return nil
}

// CheckTemporalCLIWithResult verifies the Temporal CLI is installed and executable.
func CheckTemporalCLIWithResult(rc *eos_io.RuntimeContext) metis.CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	temporalPath, err := exec.LookPath("temporal")
	if err != nil {
		return metis.CheckResult{
			Name:     "Temporal CLI",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("temporal CLI not found in PATH"),
			Remediation: []string{
				"Install Temporal CLI: curl -sSf https://temporal.download/cli.sh | sh",
				"Or run: eos repair metis --auto-yes",
				"Verify installation: temporal --version",
			},
		}
	}

	// Verify it's executable
	cmd := exec.CommandContext(rc.Ctx, temporalPath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return metis.CheckResult{
			Name:     "Temporal CLI",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("temporal binary found but not executable: %w", err),
			Remediation: []string{
				"Fix permissions: sudo chmod 755 " + temporalPath,
				"Or reinstall: eos repair metis --auto-yes",
			},
		}
	}

	logger.Debug("Temporal CLI check passed", zap.String("path", temporalPath), zap.String("version", string(output)))

	return metis.CheckResult{
		Name:     "Temporal CLI",
		Category: "Infrastructure",
		Passed:   true,
		Details:  fmt.Sprintf("Found at %s", temporalPath),
	}
}

// CheckBinaryAccessibilityWithResult ensures Temporal binary is accessible to non-root users.
func CheckBinaryAccessibilityWithResult(rc *eos_io.RuntimeContext) metis.CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		logger.Warn("Could not determine current user", zap.Error(err))
	}

	// Check if temporal is in PATH and accessible
	temporalPath, err := exec.LookPath("temporal")
	if err != nil {
		return metis.CheckResult{
			Name:     "Binary Accessibility",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("temporal not in PATH"),
			Remediation: []string{
				"Run: eos repair metis --auto-yes",
				"This will copy the binary to /usr/local/bin/temporal",
			},
		}
	}

	// Try to run as non-root user if we're root
	if currentUser != nil && currentUser.Uid == "0" {
		// We're running as root, test if ubuntu user can access it
		cmd := exec.CommandContext(rc.Ctx, "sudo", "-u", "ubuntu", "temporal", "--version")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return metis.CheckResult{
				Name:     "Binary Accessibility",
				Category: "Infrastructure",
				Passed:   false,
				Error:    fmt.Errorf("temporal binary not accessible to non-root users: %s", string(output)),
				Remediation: []string{
					"Binary might be in /root/ directory which non-root users can't access",
					"Run: eos repair metis --auto-yes",
					"This will copy the binary to /usr/local/bin/temporal",
					"Or manually: sudo cp /root/.temporalio/bin/temporal /usr/local/bin/temporal",
				},
			}
		}
		logger.Debug("Binary accessible to non-root users", zap.String("output", string(output)))
	}

	// Test basic execution
	cmd := exec.CommandContext(rc.Ctx, temporalPath, "--version")
	if err := cmd.Run(); err != nil {
		return metis.CheckResult{
			Name:     "Binary Accessibility",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("temporal binary not executable: %w", err),
			Remediation: []string{
				"Fix permissions: sudo chmod 755 " + temporalPath,
			},
		}
	}

	return metis.CheckResult{
		Name:     "Binary Accessibility",
		Category: "Infrastructure",
		Passed:   true,
		Details:  fmt.Sprintf("Temporal binary accessible at %s", temporalPath),
	}
}

// CheckPortStatusWithResult checks if required ports are listening and identifies processes.
func CheckPortStatusWithResult(rc *eos_io.RuntimeContext) metis.CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ports := []struct {
		port    int
		service string
	}{
		{7233, "Temporal gRPC"},
		{8233, "Temporal UI"},
		{8080, "Metis Webhook"},
	}

	var listening []string
	var notListening []string
	var allDetails []string

	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", p.port), 2*time.Second)
		if err != nil {
			notListening = append(notListening, fmt.Sprintf("%d (%s)", p.port, p.service))
			allDetails = append(allDetails, fmt.Sprintf("  ✗ Port %d (%s): not listening", p.port, p.service))
			logger.Debug("Port not listening",
				zap.Int("port", p.port),
				zap.String("service", p.service))
			continue
		}
		conn.Close()

		// Get process info using lsof
		cmd := exec.CommandContext(rc.Ctx, "lsof", "-i", fmt.Sprintf(":%d", p.port), "-t")
		output, err := cmd.Output()

		var processInfo string
		if err == nil && len(output) > 0 {
			pid := strings.TrimSpace(string(output))
			// Get process name
			cmdName := exec.CommandContext(rc.Ctx, "ps", "-p", pid, "-o", "comm=")
			processName, _ := cmdName.Output()
			processInfo = fmt.Sprintf("PID %s (%s)", pid, strings.TrimSpace(string(processName)))

			logger.Debug("Port listening",
				zap.Int("port", p.port),
				zap.String("service", p.service),
				zap.String("process", processInfo))
		} else {
			processInfo = "unknown process"
			logger.Warn("Port listening but could not identify process",
				zap.Int("port", p.port))
		}

		listening = append(listening, fmt.Sprintf("%d (%s)", p.port, p.service))
		allDetails = append(allDetails, fmt.Sprintf("  ✓ Port %d (%s): %s", p.port, p.service, processInfo))
	}

	// Always show all details
	detailsText := strings.Join(allDetails, "\n")

	if len(notListening) > 0 {
		logger.Debug("Port status check failed",
			zap.Strings("not_listening", notListening),
			zap.Strings("listening", listening))

		// Don't suggest systemctl unless we know services exist
		// That will be checked by CheckSystemdServicesWithResult
		return metis.CheckResult{
			Name:     "Port Status",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("%d ports not listening", len(notListening)),
			Remediation: []string{
				"Check if services are installed: systemctl list-units 'metis*' 'temporal*'",
				"If services exist but stopped: see 'Systemd Services' check for start commands",
				"If services don't exist: run 'eos create metis' or 'eos repair metis'",
			},
			Details: detailsText,
		}
	}

	logger.Debug("All ports listening", zap.Strings("ports", listening))

	return metis.CheckResult{
		Name:     "Port Status",
		Category: "Infrastructure",
		Passed:   true,
		Details:  detailsText,
	}
}

// CheckTemporalServerHealthDeepWithResult performs comprehensive health checks on Temporal server.
func CheckTemporalServerHealthDeepWithResult(rc *eos_io.RuntimeContext, config *metis.MetisConfig) metis.CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	if config == nil {
		return metis.CheckResult{
			Name:     "Temporal Server Health",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("config not loaded"),
			Remediation: []string{
				"Fix configuration first: eos create metis",
			},
		}
	}

	hostPort := config.Temporal.HostPort
	if hostPort == "" {
		hostPort = "localhost:7233"
	}

	var healthDetails []string

	// Step 1: Check if gRPC port is listening
	conn, err := net.DialTimeout("tcp", hostPort, 2*time.Second)
	if err != nil {
		logger.Error("Temporal gRPC port not listening",
			zap.String("hostPort", hostPort),
			zap.Error(err))

		// Check systemd status
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "temporal")
		statusOut, _ := statusCmd.Output()
		systemdStatus := strings.TrimSpace(string(statusOut))

		remediation := []string{
			"Check if systemd service exists: systemctl list-unit-files temporal.service",
		}

		if systemdStatus == "inactive" || systemdStatus == "failed" {
			remediation = append(remediation,
				"Service exists but not running: sudo systemctl start temporal",
				"Check logs: sudo journalctl -u temporal -n 50")
		} else if systemdStatus == "" {
			remediation = append(remediation,
				"Service not installed: eos create metis or eos repair metis",
				"Or start manually: temporal server start-dev")
		}

		remediation = append(remediation,
			"Check if port is in use by another process: lsof -i :7233")

		return metis.CheckResult{
			Name:        "Temporal Server Health",
			Category:    "Infrastructure",
			Passed:      false,
			Error:       fmt.Errorf("port %s not listening", hostPort),
			Remediation: remediation,
			Details:     fmt.Sprintf("systemd status: %s", systemdStatus),
		}
	}
	conn.Close()
	logger.Debug("Temporal gRPC port listening", zap.String("hostPort", hostPort))
	healthDetails = append(healthDetails, fmt.Sprintf("✓ gRPC port %s listening", hostPort))

	// Step 2: Check HTTP health endpoint (usually port 8233 for UI)
	httpPort := strings.Replace(hostPort, "7233", "8233", 1)
	healthURL := fmt.Sprintf("http://%s/", httpPort)

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		logger.Warn("Could not create health check request", zap.Error(err))
		healthDetails = append(healthDetails, "⚠ Could not check UI endpoint")
	} else {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logger.Warn("Temporal UI not reachable", zap.String("url", healthURL), zap.Error(err))
			healthDetails = append(healthDetails, fmt.Sprintf("✗ UI not reachable at %s", httpPort))
		} else {
			resp.Body.Close()
			logger.Debug("Temporal UI reachable", zap.String("url", healthURL), zap.Int("status", resp.StatusCode))
			healthDetails = append(healthDetails, fmt.Sprintf("✓ UI reachable at %s", httpPort))
		}
	}

	// Step 3: Try CLI health check
	cmd := exec.CommandContext(rc.Ctx, "temporal", "operator", "namespace", "list", "--address", hostPort)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn("Temporal CLI health check failed",
			zap.String("output", string(output)),
			zap.Error(err))
		healthDetails = append(healthDetails, "✗ CLI health check failed")

		return metis.CheckResult{
			Name:     "Temporal Server Health",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("server responding but CLI commands failing: %s", string(output)),
			Remediation: []string{
				"Server is running but not responding correctly",
				"Check server logs: sudo journalctl -u temporal -n 100",
				"Try restarting: sudo systemctl restart temporal",
				"Verify namespace configuration in config.yaml",
			},
			Details: strings.Join(healthDetails, "\n"),
		}
	}

	logger.Debug("Temporal CLI health check passed", zap.String("output", string(output)))
	healthDetails = append(healthDetails, "✓ CLI health check passed")

	return metis.CheckResult{
		Name:     "Temporal Server Health",
		Category: "Infrastructure",
		Passed:   true,
		Details:  strings.Join(healthDetails, "\n"),
	}
}

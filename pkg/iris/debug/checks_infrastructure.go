// pkg/iris/debug/checks_infrastructure.go
package debug

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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckProjectStructure verifies that all required Iris project files and directories exist
func CheckProjectStructure(rc *eos_io.RuntimeContext, projectDir string, verbose bool) CheckResult {
	err := checkProjectStructure(rc, projectDir, verbose)
	result := CheckResult{
		Name:     "Project Structure",
		Category: "Infrastructure",
		Passed:   err == nil,
		Error:    err,
	}

	if err != nil {
		result.Remediation = []string{
			"Install Iris using: eos create iris",
			"Or clone from repository: git clone <iris-repo> /opt/iris",
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

// CheckTemporalCLI verifies that the Temporal CLI is installed and executable
func CheckTemporalCLI(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	temporalPath, err := exec.LookPath("temporal")
	if err != nil {
		return CheckResult{
			Name:     "Temporal CLI",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("temporal CLI not found in PATH"),
			Remediation: []string{
				"Install Temporal CLI: curl -sSf https://temporal.download/cli.sh | sh",
				"Or run: eos repair iris --auto-yes",
				"Verify installation: temporal --version",
			},
		}
	}

	// Verify it's executable
	cmd := exec.CommandContext(rc.Ctx, temporalPath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return CheckResult{
			Name:     "Temporal CLI",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("temporal binary found but not executable: %w", err),
			Remediation: []string{
				"Fix permissions: sudo chmod 755 " + temporalPath,
				"Or reinstall: eos repair iris --auto-yes",
			},
		}
	}

	logger.Debug("Temporal CLI check passed", zap.String("path", temporalPath), zap.String("version", string(output)))

	return CheckResult{
		Name:     "Temporal CLI",
		Category: "Infrastructure",
		Passed:   true,
		Details:  fmt.Sprintf("Found at %s", temporalPath),
	}
}

// CheckBinaryAccessibility verifies that the Temporal binary is accessible to non-root users
func CheckBinaryAccessibility(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		logger.Warn("Could not determine current user", zap.Error(err))
	}

	// Check if temporal is in PATH and accessible
	temporalPath, err := exec.LookPath("temporal")
	if err != nil {
		return CheckResult{
			Name:     "Binary Accessibility",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("temporal not in PATH"),
			Remediation: []string{
				"Run: eos repair iris --auto-yes",
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
			return CheckResult{
				Name:     "Binary Accessibility",
				Category: "Infrastructure",
				Passed:   false,
				Error:    fmt.Errorf("temporal binary not accessible to non-root users: %s", string(output)),
				Remediation: []string{
					"Binary might be in /root/ directory which non-root users can't access",
					"Run: eos repair iris --auto-yes",
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
		return CheckResult{
			Name:     "Binary Accessibility",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("temporal binary not executable: %w", err),
			Remediation: []string{
				"Fix permissions: sudo chmod 755 " + temporalPath,
			},
		}
	}

	return CheckResult{
		Name:     "Binary Accessibility",
		Category: "Infrastructure",
		Passed:   true,
		Details:  fmt.Sprintf("Temporal binary accessible at %s", temporalPath),
	}
}

// CheckPortStatus verifies that required ports (Temporal gRPC, UI, Webhook) are listening
func CheckPortStatus(rc *eos_io.RuntimeContext, config *IrisConfig) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Determine webhook port from config, default to 8080
	webhookPort := 8080
	if config != nil && config.Webhook.Port > 0 {
		webhookPort = config.Webhook.Port
	}

	ports := []struct {
		port    int
		service string
	}{
		{7233, "Temporal gRPC"},
		{8233, "Temporal UI"},
		{webhookPort, "Iris Webhook"},
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
		_ = conn.Close()

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
		// That will be checked by CheckSystemdServices
		return CheckResult{
			Name:     "Port Status",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("%d ports not listening", len(notListening)),
			Remediation: []string{
				"Check if services are installed: systemctl list-units 'iris*' 'temporal*'",
				"If services exist but stopped: see 'Systemd Services' check for start commands",
				"If services don't exist: run 'eos create iris' or 'eos repair iris'",
			},
			Details: detailsText,
		}
	}

	logger.Debug("All ports listening", zap.Strings("ports", listening))

	// Add note about configured webhook port if different from default
	if config != nil && config.Webhook.Port > 0 && config.Webhook.Port != 8080 {
		detailsText += fmt.Sprintf("\n  ℹ Webhook port %d from config.yaml", config.Webhook.Port)
	}

	return CheckResult{
		Name:     "Port Status",
		Category: "Infrastructure",
		Passed:   true,
		Details:  detailsText,
	}
}

// CheckTemporalServerHealth performs a deep health check of the Temporal server
func CheckTemporalServerHealth(rc *eos_io.RuntimeContext, config *IrisConfig) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	if config == nil {
		return CheckResult{
			Name:     "Temporal Server Health",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("config not loaded"),
			Remediation: []string{
				"Fix configuration first: eos create iris",
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

		switch systemdStatus {
		case "inactive", "failed":
			remediation = append(remediation,
				"Service exists but not running: sudo systemctl start temporal",
				"Check logs: sudo journalctl -u temporal -n 50")
		case "":
			remediation = append(remediation,
				"Service not installed: eos create iris or eos repair iris",
				"Or start manually: temporal server start-dev")
		}

		remediation = append(remediation,
			"Check if port is in use by another process: lsof -i :7233")

		return CheckResult{
			Name:        "Temporal Server Health",
			Category:    "Infrastructure",
			Passed:      false,
			Error:       fmt.Errorf("port %s not listening", hostPort),
			Remediation: remediation,
			Details:     fmt.Sprintf("systemd status: %s", systemdStatus),
		}
	}
	_ = conn.Close()
	logger.Debug("Temporal gRPC port listening", zap.String("hostPort", hostPort))
	healthDetails = append(healthDetails, fmt.Sprintf("  ✓ gRPC port %s: listening", hostPort))

	// Step 2: Check Temporal UI HTTP endpoint
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	uiHost := strings.Replace(hostPort, ":7233", ":8233", 1)
	healthURL := fmt.Sprintf("http://%s/", uiHost)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		logger.Warn("Could not create HTTP request for UI", zap.Error(err))
		healthDetails = append(healthDetails, "  ⚠ UI endpoint: could not test")
	} else {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logger.Warn("Temporal UI not accessible", zap.Error(err))
			healthDetails = append(healthDetails, fmt.Sprintf("  ⚠ UI endpoint %s: not accessible", healthURL))
		} else {
			defer func() { _ = resp.Body.Close() }()
			logger.Debug("Temporal UI accessible", zap.Int("status", resp.StatusCode))
			healthDetails = append(healthDetails, fmt.Sprintf("  ✓ UI endpoint %s: accessible (HTTP %d)", healthURL, resp.StatusCode))
		}
	}

	// Step 3: API health check via HTTP API (preferred over CLI)
	// Temporal exposes health endpoint at gRPC port via HTTP/1.1
	apiHealthURL := fmt.Sprintf("http://%s/health", hostPort)
	apiReq, err := http.NewRequestWithContext(ctx, "GET", apiHealthURL, nil)
	if err == nil {
		client := &http.Client{Timeout: 3 * time.Second}
		apiResp, err := client.Do(apiReq)
		if err == nil {
			defer func() { _ = apiResp.Body.Close() }()
			if apiResp.StatusCode == http.StatusOK {
				logger.Debug("Temporal API health check passed", zap.Int("status", apiResp.StatusCode))
				healthDetails = append(healthDetails, "  ✓ API health endpoint: OK")
			} else {
				logger.Warn("Temporal API health check returned non-200", zap.Int("status", apiResp.StatusCode))
				healthDetails = append(healthDetails, fmt.Sprintf("  ⚠ API health endpoint: HTTP %d", apiResp.StatusCode))
			}
		} else {
			logger.Debug("API health endpoint not available, trying CLI", zap.Error(err))
			healthDetails = append(healthDetails, "  ⚠ API health endpoint: not available")
		}
	}

	// Step 4: Fallback to CLI health check (if API not available)
	cmd := exec.CommandContext(rc.Ctx, "temporal", "operator", "cluster", "health")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Temporal health check failed",
			zap.String("output", string(output)),
			zap.Error(err))

		// Check journalctl for recent errors
		journalCmd := exec.CommandContext(rc.Ctx, "journalctl", "-u", "temporal", "-n", "10", "--no-pager")
		journalOut, _ := journalCmd.Output()

		var logErrors []string
		if len(journalOut) > 0 {
			lines := strings.Split(string(journalOut), "\n")
			for _, line := range lines {
				if strings.Contains(line, "error") || strings.Contains(line, "Error") || strings.Contains(line, "ERROR") {
					logErrors = append(logErrors, line)
					logger.Warn("Error in temporal logs", zap.String("line", line))
				}
			}
		}

		detailsText := strings.Join(healthDetails, "\n")
		if len(logErrors) > 0 {
			detailsText += "\n\nRecent errors in logs:\n" + strings.Join(logErrors, "\n")
		}

		return CheckResult{
			Name:     "Temporal Server Health",
			Category: "Infrastructure",
			Passed:   false,
			Error:    fmt.Errorf("server listening but health check failed: %s", string(output)),
			Remediation: []string{
				"Server might be starting up - wait 30 seconds and retry",
				"Check logs: sudo journalctl -u temporal -n 50",
				"Restart server: sudo systemctl restart temporal",
				"Check for port conflicts: lsof -i :7233",
				"Verify process is healthy: ps aux | grep temporal",
			},
			Details: detailsText,
		}
	}

	logger.Debug("Temporal server health check passed", zap.String("output", string(output)))
	healthDetails = append(healthDetails, "  ✓ CLI health check: passed")

	return CheckResult{
		Name:     "Temporal Server Health",
		Category: "Infrastructure",
		Passed:   true,
		Details:  strings.Join(healthDetails, "\n"),
	}
}

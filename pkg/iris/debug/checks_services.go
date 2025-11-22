// pkg/iris/debug/checks_services.go
package debug

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckWorkerProcessHealth verifies that the Iris worker process is running and healthy
func CheckWorkerProcessHealth(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if worker is running
	cmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", "iris.*worker")
	output, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Name:     "Worker Process Health",
			Category: "Services",
			Passed:   false,
			Error:    fmt.Errorf("worker process not running"),
			Remediation: []string{
				"Start worker: sudo systemctl start iris-worker",
				"Or manually: cd /opt/iris/worker && go run main.go",
				"Check logs: sudo journalctl -u iris-worker -n 50",
				"Ensure Temporal server is running first",
			},
		}
	}

	pids := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pids) == 0 || pids[0] == "" {
		return CheckResult{
			Name:     "Worker Process Health",
			Category: "Services",
			Passed:   false,
			Error:    fmt.Errorf("worker process not found"),
			Remediation: []string{
				"Start worker: sudo systemctl start iris-worker",
				"Check logs: sudo journalctl -u iris-worker -n 50",
			},
		}
	}

	pid := pids[0]
	logger.Debug("Worker process found", zap.String("pid", pid))

	// Check how long it's been running (basic health check)
	cmdPs := exec.CommandContext(rc.Ctx, "ps", "-p", pid, "-o", "etime=")
	uptime, err := cmdPs.Output()
	if err != nil {
		logger.Warn("Could not get process uptime", zap.Error(err))
	}

	details := fmt.Sprintf("Worker running (PID %s)", pid)
	if len(uptime) > 0 {
		details += fmt.Sprintf(", uptime: %s", strings.TrimSpace(string(uptime)))
	}

	return CheckResult{
		Name:     "Worker Process Health",
		Category: "Services",
		Passed:   true,
		Details:  details,
	}
}

// CheckWebhookServerHealth verifies that the Iris webhook server is running and responding
func CheckWebhookServerHealth(rc *eos_io.RuntimeContext, config *IrisConfig) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if webhook is running
	cmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", "iris.*webhook")
	output, err := cmd.Output()
	if err != nil {
		return CheckResult{
			Name:     "Webhook Server Health",
			Category: "Services",
			Passed:   false,
			Error:    fmt.Errorf("webhook process not running"),
			Remediation: []string{
				"Start webhook: sudo systemctl start iris-webhook",
				"Or manually: cd /opt/iris/webhook && go run main.go",
				"Check logs: sudo journalctl -u iris-webhook -n 50",
			},
		}
	}

	pids := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pids) == 0 || pids[0] == "" {
		return CheckResult{
			Name:     "Webhook Server Health",
			Category: "Services",
			Passed:   false,
			Error:    fmt.Errorf("webhook process not found"),
			Remediation: []string{
				"Start webhook: sudo systemctl start iris-webhook",
			},
		}
	}

	pid := pids[0]
	logger.Debug("Webhook process found", zap.String("pid", pid))

	// Try to hit the health endpoint
	webhookPort := 8080
	if config != nil && config.Webhook.Port > 0 {
		webhookPort = config.Webhook.Port
	}

	healthURL := fmt.Sprintf("http://localhost:%d/health", webhookPort)
	ctx, cancel := context.WithTimeout(rc.Ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err == nil {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return CheckResult{
				Name:     "Webhook Server Health",
				Category: "Services",
				Passed:   false,
				Error:    fmt.Errorf("webhook process running (PID %s) but health check failed: %w", pid, err),
				Remediation: []string{
					"Check logs: sudo journalctl -u iris-webhook -n 50",
					"Restart webhook: sudo systemctl restart iris-webhook",
					"Verify port is correct in config.yaml",
				},
			}
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return CheckResult{
				Name:     "Webhook Server Health",
				Category: "Services",
				Passed:   false,
				Error:    fmt.Errorf("webhook health check returned status %d", resp.StatusCode),
				Remediation: []string{
					"Check logs: sudo journalctl -u iris-webhook -n 50",
					"Restart webhook: sudo systemctl restart iris-webhook",
				},
			}
		}
	}

	details := fmt.Sprintf("Webhook running (PID %s), health check passed", pid)

	return CheckResult{
		Name:     "Webhook Server Health",
		Category: "Services",
		Passed:   true,
		Details:  details,
	}
}

// CheckSystemdServices verifies that Iris systemd services are installed and running
func CheckSystemdServices(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	services := []string{"temporal", "iris-worker", "iris-webhook"}

	var missing []string
	var inactive []string
	var failed []string
	var active []string
	var allDetails []string

	for _, svc := range services {
		// Check if unit file exists
		checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "list-unit-files", svc+".service")
		checkOut, err := checkCmd.Output()

		if err != nil || !strings.Contains(string(checkOut), svc) {
			missing = append(missing, svc)
			allDetails = append(allDetails, fmt.Sprintf("  ✗ %s: unit file not found", svc))
			logger.Debug("Systemd unit not found", zap.String("service", svc))
			continue
		}

		// Check service status
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", svc)
		output, _ := statusCmd.Output()
		status := strings.TrimSpace(string(output))

		logger.Debug("Systemd service status",
			zap.String("service", svc),
			zap.String("status", status))

		switch status {
		case "active":
			active = append(active, svc)
			allDetails = append(allDetails, fmt.Sprintf("  ✓ %s: active", svc))

			// Get additional details with systemctl show
			showCmd := exec.CommandContext(rc.Ctx, "systemctl", "show", svc, "-p", "MainPID,ActiveEnterTimestamp")
			showOut, _ := showCmd.Output()
			logger.Debug("Service details", zap.String("service", svc), zap.String("details", string(showOut)))

		case "inactive":
			inactive = append(inactive, svc)
			allDetails = append(allDetails, fmt.Sprintf("  ⚠ %s: inactive (stopped)", svc))

		case "failed":
			failed = append(failed, svc)
			allDetails = append(allDetails, fmt.Sprintf("  ✗ %s: failed", svc))

			// Get failure reason from journalctl
			journalCmd := exec.CommandContext(rc.Ctx, "journalctl", "-u", svc, "-n", "5", "--no-pager")
			journalOut, _ := journalCmd.Output()
			if len(journalOut) > 0 {
				logger.Warn("Service failed, recent logs",
					zap.String("service", svc),
					zap.String("logs", string(journalOut)))
			}

		default:
			// activating, deactivating, etc
			inactive = append(inactive, svc)
			allDetails = append(allDetails, fmt.Sprintf("  ⚠ %s: %s", svc, status))
		}
	}

	detailsText := strings.Join(allDetails, "\n")

	// Handle missing services (not installed)
	if len(missing) > 0 {
		logger.Warn("Systemd services not installed", zap.Strings("missing", missing))
		return CheckResult{
			Name:     "Systemd Services",
			Category: "Services",
			Passed:   false,
			Error:    fmt.Errorf("service units not installed: %s", strings.Join(missing, ", ")),
			Remediation: []string{
				"Install services: eos create iris",
				"Or manually install: eos repair iris --auto-yes",
				"Services should be installed to: /etc/systemd/system/",
			},
			Details: detailsText,
		}
	}

	// Handle inactive/failed services
	if len(inactive) > 0 || len(failed) > 0 {
		var problemServices []string
		problemServices = append(problemServices, inactive...)
		problemServices = append(problemServices, failed...)

		logger.Warn("Systemd services not running",
			zap.Strings("inactive", inactive),
			zap.Strings("failed", failed))

		remediation := []string{
			fmt.Sprintf("Start services: sudo systemctl start %s", strings.Join(problemServices, " ")),
		}

		// Add service-specific remediation
		for _, svc := range failed {
			remediation = append(remediation,
				fmt.Sprintf("Check %s logs: sudo journalctl -u %s -n 50", svc, svc))
		}

		remediation = append(remediation,
			"Check status: sudo systemctl status "+strings.Join(problemServices, " "))

		return CheckResult{
			Name:        "Systemd Services",
			Category:    "Services",
			Passed:      false,
			Error:       fmt.Errorf("%d services not active", len(problemServices)),
			Remediation: remediation,
			Details:     detailsText,
		}
	}

	// All services active
	logger.Debug("All systemd services active", zap.Strings("services", active))

	return CheckResult{
		Name:     "Systemd Services",
		Category: "Services",
		Passed:   true,
		Details:  detailsText,
	}
}

// CheckRecentWorkflows verifies that Temporal workflows can be listed (tests CLI availability)
func CheckRecentWorkflows(rc *eos_io.RuntimeContext, config *IrisConfig) CheckResult {
	err := listRecentWorkflows(rc, config)
	result := CheckResult{
		Name:     "Temporal CLI",
		Category: "Infrastructure",
		Passed:   err == nil,
		Error:    err,
	}

	if err != nil {
		// Run diagnostics to find where Temporal might be
		diagnostics := FindTemporalBinary(rc)

		remediation := []string{
			"Install Temporal CLI: brew install temporal (macOS)",
			"Or download from: https://docs.temporal.io/cli",
			"Or install via script: curl -sSf https://temporal.download/cli.sh | sh",
		}

		if diagnostics != "" {
			remediation = append(remediation, "", "Diagnostics found:", diagnostics)
		} else {
			remediation = append(remediation, "", "No existing Temporal installation found on system")
		}

		remediation = append(remediation,
			"After installing, verify: temporal --version",
			"Ensure Temporal server is running",
			"View workflows in UI: http://localhost:8233",
		)

		result.Remediation = remediation
	} else {
		result.Details = "Temporal CLI available and workflow history accessible"
	}

	return result
}

func listRecentWorkflows(rc *eos_io.RuntimeContext, config *IrisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Use temporal CLI if available
	if _, err := exec.LookPath("temporal"); err != nil {
		return fmt.Errorf("temporal CLI not available")
	}

	listCmd := exec.CommandContext(rc.Ctx, "temporal", "workflow", "list",
		"--address", config.Temporal.HostPort,
		"--namespace", config.Temporal.Namespace,
		"--limit", "5")
	if output, err := listCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to list workflows: %s", string(output))
	}

	return nil
}

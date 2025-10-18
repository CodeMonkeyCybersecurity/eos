package wazuh

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/iris"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/network"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Exported flag variables for CLI binding
var (
	// Webhook diagnostics flags
	WebhookOut   bool
	IrisIP       string
	IrisPort     int
	SSHKey       string
	AutoStart    bool
	TemporalDB   string
	TemporalIP   string
	TemporalPort int

	// Component diagnostics flags
	Component string
	LogLines  int
	Verbose   bool
	Fix       bool
)

type wazuhCheckResult struct {
	name        string
	category    string
	passed      bool
	warning     bool // true for non-critical warnings
	error       error
	remediation []string
	details     string
}

// RunDiagnostics is the main entry point that dispatches to the appropriate diagnostic mode
func RunDiagnostics(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	if WebhookOut {
		// Webhook integration diagnostics mode
		return runWazuh(rc, cmd, args)
	}

	// Component diagnostics mode (default)
	return runWazuhDebug(rc, cmd, args)
}

func runWazuh(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !WebhookOut {
		logger.Error("No diagnostic mode specified")
		return fmt.Errorf("no diagnostic mode specified, use --webhook-out")
	}

	logger.Info("Starting Wazuh webhook diagnostics",
		zap.String("iris_ip", IrisIP),
		zap.Int("iris_port", IrisPort),
		zap.Bool("verbose", Verbose))

	results := RunWebhookOutDiagnostics(rc)
	DisplayWazuhResults(results)

	// Return nil for informational diagnostics
	return nil
}

func RunWebhookOutDiagnostics(rc *eos_io.RuntimeContext) []wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Running webhook-out diagnostics")

	var results []wazuhCheckResult

	// 1. Network Connectivity
	results = append(results, CheckNetworkConnectivity(rc)...)

	// 2. Iris Service Health
	irisConfig := iris.IrisConfig{
		IrisIP:       IrisIP,
		IrisPort:     IrisPort,
		SSHKey:       SSHKey,
		TemporalIP:   TemporalIP,
		TemporalPort: TemporalPort,
		TemporalDB:   TemporalDB,
		AutoStart:    AutoStart,
	}
	irisHealthResults := iris.CheckIrisServiceHealth(rc, irisConfig)
	for _, ir := range irisHealthResults {
		results = append(results, convertIrisCheckResult(ir))
	}

	// 3. Wazuh Integration Configuration
	results = append(results, CheckWazuhIntegrationConfig(rc)...)

	// 4. Python Dependencies
	results = append(results, CheckPythonDependencies(rc)...)

	// 5. Test Webhook
	results = append(results, SendTestWebhook(rc)...)

	// 6. Log Analysis
	results = append(results, AnalyzeLogs(rc)...)

	// 7. Remote Iris Checks (if SSH key provided)
	if SSHKey != "" {
		irisResults := iris.CheckRemoteIris(rc, irisConfig)
		for _, ir := range irisResults {
			results = append(results, convertIrisCheckResult(ir))
		}
	}

	return results
}

// convertIrisCheckResult converts iris.CheckResult to wazuhCheckResult
func convertIrisCheckResult(ir iris.CheckResult) wazuhCheckResult {
	return wazuhCheckResult{
		name:        ir.Name,
		category:    ir.Category,
		passed:      ir.Passed,
		warning:     ir.Warning,
		error:       ir.Error,
		remediation: ir.Remediation,
		details:     ir.Details,
	}
}

// convertCheckResult converts network.CheckResult to wazuhCheckResult
func convertCheckResult(nr network.CheckResult) wazuhCheckResult {
	return wazuhCheckResult{
		name:        nr.Name,
		category:    nr.Category,
		passed:      nr.Passed,
		warning:     nr.Warning,
		error:       nr.Error,
		remediation: nr.Remediation,
		details:     nr.Details,
	}
}

// Network Connectivity Checks
func CheckNetworkConnectivity(rc *eos_io.RuntimeContext) []wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking network connectivity", zap.String("target", IrisIP))

	var results []wazuhCheckResult

	// Ping check
	pingResult := network.CheckPing(rc, IrisIP, "Iris machine")
	results = append(results, convertCheckResult(pingResult))

	// TCP connection check
	tcpResult := network.CheckTCPConnection(rc, IrisIP, IrisPort, "Iris webhook")
	results = append(results, convertCheckResult(tcpResult))

	// Network latency
	latencyResult := network.CheckNetworkLatency(rc, IrisIP, IrisPort, "Iris webhook")
	results = append(results, convertCheckResult(latencyResult))

	// Firewall rules
	firewallResult := network.CheckFirewallRules(rc, IrisIP, IrisPort)
	results = append(results, convertCheckResult(firewallResult))

	return results
}

// Wazuh Integration Configuration Checks
func CheckWazuhIntegrationConfig(rc *eos_io.RuntimeContext) []wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Wazuh integration configuration")

	var results []wazuhCheckResult

	// .env file check
	envResult := CheckIntegrationEnvFile(rc)
	results = append(results, envResult)

	// Script permissions
	scriptResult := CheckIntegrationScripts(rc)
	results = append(results, scriptResult)

	// ossec.conf integration settings
	ossecResult := CheckOssecIntegrationConfig(rc)
	results = append(results, ossecResult)

	// Wazuh Manager service
	managerResult := CheckWazuhManagerService(rc)
	results = append(results, managerResult)

	return results
}

func CheckIntegrationEnvFile(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	envPath := "/var/ossec/integrations/.env"

	// Check existence
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		logger.Error(".env file not found", zap.String("path", envPath))
		return wazuhCheckResult{
			name:     "Integration .env File",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf(".env file not found at %s", envPath),
			remediation: []string{
				"Create .env file: sudo nano " + envPath,
				"Add required variables:",
				fmt.Sprintf("  HOOK_URL=http://%s:%d/webhooks/wazuh_alert", IrisIP, IrisPort),
				"  API_KEY=<your-api-key>",
				"Set permissions: sudo chmod 640 " + envPath,
				"Set ownership: sudo chown root:ossec " + envPath,
			},
		}
	}

	// Read and validate HOOK_URL
	file, err := os.Open(envPath)
	if err != nil {
		logger.Error("Cannot read .env file", zap.Error(err))
		return wazuhCheckResult{
			name:     "Integration .env File",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("cannot read .env file: %w", err),
			remediation: []string{
				"Check file permissions: ls -la " + envPath,
				"Should be readable by ossec user",
			},
		}
	}
	defer func() { _ = file.Close() }()

	var hookURL string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "HOOK_URL=") {
			hookURL = strings.TrimPrefix(line, "HOOK_URL=")
			break
		}
	}

	if hookURL == "" {
		return wazuhCheckResult{
			name:     "Integration .env File",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("HOOK_URL not found in .env file"),
			remediation: []string{
				"Add HOOK_URL to .env file: sudo nano " + envPath,
				fmt.Sprintf("  HOOK_URL=http://%s:%d/webhooks/wazuh_alert", IrisIP, IrisPort),
			},
		}
	}

	// Validate HOOK_URL points to correct IP
	expectedURL := fmt.Sprintf("http://%s:%d", IrisIP, IrisPort)
	if !strings.Contains(hookURL, expectedURL) {
		logger.Warn("HOOK_URL does not match expected Iris address",
			zap.String("found", hookURL),
			zap.String("expected", expectedURL))
		return wazuhCheckResult{
			name:     "Integration .env File",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("HOOK_URL points to wrong address: %s", hookURL),
			remediation: []string{
				fmt.Sprintf("Update HOOK_URL in %s to: http://%s:%d/webhooks/wazuh_alert",
					envPath, IrisIP, IrisPort),
			},
			details: fmt.Sprintf("Current: %s\nExpected: %s/webhooks/wazuh_alert", hookURL, expectedURL),
		}
	}

	logger.Debug(".env file validated", zap.String("hook_url", hookURL))
	return wazuhCheckResult{
		name:     "Integration .env File",
		category: "Wazuh Configuration",
		passed:   true,
		details:  fmt.Sprintf("HOOK_URL correctly configured: %s", hookURL),
	}
}

func CheckIntegrationScripts(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	scriptsToCheck := []string{
		"/var/ossec/integrations/custom-iris",
		"/var/ossec/integrations/custom-iris.py",
	}

	var missingScripts []string
	var notExecutable []string

	for _, script := range scriptsToCheck {
		info, err := os.Stat(script)
		if os.IsNotExist(err) {
			missingScripts = append(missingScripts, script)
			logger.Warn("Integration script not found", zap.String("script", script))
			continue
		}

		// Check if executable
		if info.Mode()&0111 == 0 {
			notExecutable = append(notExecutable, script)
			logger.Warn("Integration script not executable", zap.String("script", script))
		}
	}

	if len(missingScripts) > 0 {
		return wazuhCheckResult{
			name:     "Integration Scripts",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("missing scripts: %s", strings.Join(missingScripts, ", ")),
			remediation: []string{
				"Create missing integration scripts in /var/ossec/integrations/",
				"Ensure scripts are executable: sudo chmod 750 /var/ossec/integrations/custom-iris*",
				"Set ownership: sudo chown root:ossec /var/ossec/integrations/custom-iris*",
			},
		}
	}

	if len(notExecutable) > 0 {
		return wazuhCheckResult{
			name:     "Integration Scripts",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("scripts not executable: %s", strings.Join(notExecutable, ", ")),
			remediation: []string{
				"Make scripts executable:",
				"  sudo chmod 750 " + strings.Join(notExecutable, " "),
			},
		}
	}

	logger.Debug("Integration scripts validated")
	return wazuhCheckResult{
		name:     "Integration Scripts",
		category: "Wazuh Configuration",
		passed:   true,
		details:  "All integration scripts exist and are executable",
	}
}

func CheckOssecIntegrationConfig(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ossecConfPath := "/var/ossec/etc/ossec.conf"

	// Read ossec.conf
	data, err := os.ReadFile(ossecConfPath)
	if err != nil {
		logger.Error("Cannot read ossec.conf", zap.Error(err))
		return wazuhCheckResult{
			name:     "Ossec Integration Config",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("cannot read ossec.conf: %w", err),
			remediation: []string{
				"Check file exists: ls -la " + ossecConfPath,
				"Verify permissions allow reading",
			},
		}
	}

	content := string(data)

	// Check for custom-iris integration
	if !strings.Contains(content, "custom-iris") {
		return wazuhCheckResult{
			name:     "Ossec Integration Config",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("custom-iris integration not found in ossec.conf"),
			remediation: []string{
				"Add integration block to " + ossecConfPath,
				"<integration>",
				"  <name>custom-iris</name>",
				"  <level>8</level>",
				"  <alert_format>json</alert_format>",
				"</integration>",
				"Restart Wazuh: sudo systemctl restart wazuh-manager",
			},
		}
	}

	// Check for hardcoded hook_url or api_key
	var warnings []string
	if strings.Contains(content, "<hook_url>") {
		warnings = append(warnings, "Found hardcoded <hook_url> - should be in .env file")
	}
	if strings.Contains(content, "<api_key>") {
		warnings = append(warnings, "Found hardcoded <api_key> - should be in .env file")
	}

	// Extract alert level
	var alertLevel string
	lines := strings.Split(content, "\n")
	inIrisBlock := false
	for _, line := range lines {
		if strings.Contains(line, "<name>custom-iris</name>") {
			inIrisBlock = true
		}
		if inIrisBlock && strings.Contains(line, "<level>") {
			alertLevel = strings.TrimSpace(line)
			alertLevel = strings.TrimPrefix(alertLevel, "<level>")
			alertLevel = strings.TrimSuffix(alertLevel, "</level>")
			break
		}
		if inIrisBlock && strings.Contains(line, "</integration>") {
			break
		}
	}

	details := fmt.Sprintf("Integration configured with alert level: %s", alertLevel)
	if len(warnings) > 0 {
		details += "\nWarnings:\n  " + strings.Join(warnings, "\n  ")
	}

	if len(warnings) > 0 {
		return wazuhCheckResult{
			name:     "Ossec Integration Config",
			category: "Wazuh Configuration",
			passed:   false,
			warning:  true,
			error:    fmt.Errorf("configuration issues found"),
			details:  details,
			remediation: []string{
				"Remove hardcoded credentials from ossec.conf",
				"Move HOOK_URL and API_KEY to /var/ossec/integrations/.env",
				"Restart Wazuh after changes: sudo systemctl restart wazuh-manager",
			},
		}
	}

	logger.Debug("Ossec integration config validated", zap.String("alert_level", alertLevel))
	return wazuhCheckResult{
		name:     "Ossec Integration Config",
		category: "Wazuh Configuration",
		passed:   true,
		details:  details,
	}
}

func CheckWazuhManagerService(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "wazuh-manager")
	output, err := cmd.Output()

	status := strings.TrimSpace(string(output))

	if err != nil || status != "active" {
		logger.Error("Wazuh Manager not active", zap.String("status", status))
		return wazuhCheckResult{
			name:     "Wazuh Manager Service",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("wazuh-manager service is %s", status),
			remediation: []string{
				"Start Wazuh Manager: sudo systemctl start wazuh-manager",
				"Check status: sudo systemctl status wazuh-manager",
				"Check logs: sudo journalctl -u wazuh-manager -n 50",
			},
		}
	}

	logger.Debug("Wazuh Manager service active")
	return wazuhCheckResult{
		name:     "Wazuh Manager Service",
		category: "Wazuh Configuration",
		passed:   true,
		details:  "Wazuh Manager is running",
	}
}

// Python Dependencies Checks
func CheckPythonDependencies(rc *eos_io.RuntimeContext) []wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Python dependencies")

	var results []wazuhCheckResult

	pythonPath := "/var/ossec/framework/python/bin/python3"

	// Check requests module
	requestsResult := CheckPythonModule(rc, pythonPath, "requests")
	results = append(results, requestsResult)

	// Check dotenv module
	dotenvResult := CheckPythonModule(rc, pythonPath, "dotenv")
	results = append(results, dotenvResult)

	return results
}

func CheckPythonModule(rc *eos_io.RuntimeContext, pythonPath, module string) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonPath, "-c", fmt.Sprintf("import %s", module))
	err := cmd.Run()

	if err != nil {
		logger.Error("Python module not found", zap.String("module", module), zap.Error(err))
		return wazuhCheckResult{
			name:     fmt.Sprintf("Python Module: %s", module),
			category: "Python Dependencies",
			passed:   false,
			error:    fmt.Errorf("module %s not installed", module),
			remediation: []string{
				fmt.Sprintf("Install module: %s -m pip install %s", pythonPath, module),
				"Or if pip not available: sudo apt install python3-" + module,
			},
		}
	}

	logger.Debug("Python module available", zap.String("module", module))
	return wazuhCheckResult{
		name:     fmt.Sprintf("Python Module: %s", module),
		category: "Python Dependencies",
		passed:   true,
		details:  fmt.Sprintf("Module %s is installed", module),
	}
}

// Test Webhook
func SendTestWebhook(rc *eos_io.RuntimeContext) []wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Sending test webhook")

	var results []wazuhCheckResult

	// Create test alert payload
	testAlert := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"rule": map[string]interface{}{
			"level":       10,
			"description": "TEST: Wazuh webhook diagnostic",
			"id":          "99999",
		},
		"agent": map[string]interface{}{
			"id":   "000",
			"name": "wazuh-manager",
			"ip":   "192.168.122.66",
		},
		"manager": map[string]interface{}{
			"name": "wazuh-manager",
		},
		"id":      fmt.Sprintf("test-%d", time.Now().Unix()),
		"decoder": map[string]interface{}{"name": "test"},
		"data": map[string]interface{}{
			"test":    true,
			"message": "Diagnostic test from eos debug wazuh --webhook-out",
		},
	}

	alertJSON, err := json.MarshalIndent(testAlert, "", "  ")
	if err != nil {
		results = append(results, wazuhCheckResult{
			name:     "Test Alert Creation",
			category: "Test Webhook",
			passed:   false,
			error:    fmt.Errorf("failed to create test alert: %w", err),
		})
		return results
	}

	// Write to temp file
	tmpFile := filepath.Join(os.TempDir(), "test_alert.json")
	if err := os.WriteFile(tmpFile, alertJSON, 0640); err != nil {
		results = append(results, wazuhCheckResult{
			name:     "Test Alert Creation",
			category: "Test Webhook",
			passed:   false,
			error:    fmt.Errorf("failed to write test alert: %w", err),
		})
		return results
	}

	logger.Debug("Test alert created", zap.String("path", tmpFile))
	results = append(results, wazuhCheckResult{
		name:     "Test Alert Creation",
		category: "Test Webhook",
		passed:   true,
		details:  fmt.Sprintf("Test alert created at %s", tmpFile),
	})

	// Execute integration script
	scriptPath := "/var/ossec/integrations/custom-iris"
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, scriptPath, tmpFile, "debug")
	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Integration script failed", zap.Error(err), zap.String("output", string(output)))
		results = append(results, wazuhCheckResult{
			name:     "Integration Script Execution",
			category: "Test Webhook",
			passed:   false,
			error:    fmt.Errorf("script failed: %w", err),
			details:  string(output),
			remediation: []string{
				"Check script permissions: ls -la " + scriptPath,
				"Check .env file configuration",
				"Review script output above for specific errors",
				"Test manually: sudo " + scriptPath + " " + tmpFile + " debug",
			},
		})
		return results
	}

	logger.Debug("Integration script executed successfully", zap.String("output", string(output)))
	results = append(results, wazuhCheckResult{
		name:     "Integration Script Execution",
		category: "Test Webhook",
		passed:   true,
		details:  "Script executed successfully (exit 0)",
	})

	// Verify HTTP response
	if strings.Contains(string(output), "200") || strings.Contains(string(output), "HTTP 200") {
		results = append(results, wazuhCheckResult{
			name:     "Webhook Response",
			category: "Test Webhook",
			passed:   true,
			details:  "Received HTTP 200 response from Iris",
		})
	} else {
		results = append(results, wazuhCheckResult{
			name:     "Webhook Response",
			category: "Test Webhook",
			passed:   false,
			warning:  true,
			error:    fmt.Errorf("could not confirm HTTP 200 response"),
			details:  "Script executed but response unclear - check logs",
		})
	}

	return results
}

// Log Analysis
func AnalyzeLogs(rc *eos_io.RuntimeContext) []wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Analyzing integration logs")

	var results []wazuhCheckResult

	// Integration logs
	intLogResult := AnalyzeIntegrationLog(rc)
	results = append(results, intLogResult)

	// Sent payload logs
	payloadLogResult := AnalyzeSentPayloadLog(rc)
	results = append(results, payloadLogResult)

	return results
}

func AnalyzeIntegrationLog(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	logPath := "/var/ossec/logs/integrations.log"

	// Check if file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return wazuhCheckResult{
			name:     "Integration Logs",
			category: "Logs",
			passed:   true,
			warning:  true,
			details:  "No integration log file found (no integrations run yet)",
		}
	}

	// Read last 10 lines
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tail", "-n", "10", logPath)
	output, err := cmd.Output()

	if err != nil {
		logger.Warn("Could not read integration logs", zap.Error(err))
		return wazuhCheckResult{
			name:     "Integration Logs",
			category: "Logs",
			passed:   false,
			warning:  true,
			error:    fmt.Errorf("could not read logs: %w", err),
		}
	}

	lines := strings.Split(string(output), "\n")
	var recentLines []string
	for i := len(lines) - 1; i >= 0 && len(recentLines) < 5; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			recentLines = append([]string{lines[i]}, recentLines...)
		}
	}

	details := "Recent integration log entries:\n  " + strings.Join(recentLines, "\n  ")

	// Check for errors
	for _, line := range recentLines {
		if strings.Contains(strings.ToLower(line), "error") ||
			strings.Contains(strings.ToLower(line), "failed") {
			return wazuhCheckResult{
				name:     "Integration Logs",
				category: "Logs",
				passed:   false,
				warning:  true,
				error:    fmt.Errorf("errors found in recent logs"),
				details:  details,
				remediation: []string{
					"Review full logs: sudo tail -f " + logPath,
					"Look for specific error messages",
					"Check network connectivity to Iris",
				},
			}
		}
	}

	logger.Debug("Integration logs analyzed", zap.Int("lines", len(recentLines)))
	return wazuhCheckResult{
		name:     "Integration Logs",
		category: "Logs",
		passed:   true,
		details:  details,
	}
}

func AnalyzeSentPayloadLog(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	logPath := "/var/ossec/logs/sent_payload.log"

	// Check if file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return wazuhCheckResult{
			name:     "Sent Payload Logs",
			category: "Logs",
			passed:   true,
			warning:  true,
			details:  "No sent payload log (no alerts sent yet)",
		}
	}

	// Read last entry (last 20 lines to capture full JSON)
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tail", "-n", "20", logPath)
	output, err := cmd.Output()

	if err != nil {
		logger.Warn("Could not read sent payload logs", zap.Error(err))
		return wazuhCheckResult{
			name:     "Sent Payload Logs",
			category: "Logs",
			passed:   false,
			warning:  true,
			error:    fmt.Errorf("could not read logs: %w", err),
		}
	}

	// Extract last timestamp
	lines := strings.Split(string(output), "\n")
	var lastTimestamp string
	for _, line := range lines {
		if strings.Contains(line, "T") && strings.Contains(line, "Z") {
			// Looks like a timestamp line
			parts := strings.SplitN(line, " ", 2)
			if len(parts) > 0 {
				lastTimestamp = parts[0]
			}
		}
	}

	details := fmt.Sprintf("Last payload sent: %s", lastTimestamp)
	if lastTimestamp == "" {
		details = "No recent payloads found in log"
	}

	logger.Debug("Sent payload logs analyzed")
	return wazuhCheckResult{
		name:     "Sent Payload Logs",
		category: "Logs",
		passed:   true,
		details:  details,
	}
}

func testSSHConnection(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	// Try SSH with key
	cmd := exec.CommandContext(ctx, "ssh",
		"-i", SSHKey,
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=3",
		fmt.Sprintf("ubuntu@%s", IrisIP),
		"echo", "connected")

	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("SSH connection failed", zap.Error(err), zap.String("output", string(output)))
		return wazuhCheckResult{
			name:     "SSH Connectivity",
			category: "Remote Checks",
			passed:   false,
			error:    fmt.Errorf("cannot SSH to %s: %w", IrisIP, err),
			remediation: []string{
				"Verify SSH key is correct: " + SSHKey,
				"Check SSH is enabled on Iris machine",
				"Test manually: ssh -i " + SSHKey + " ubuntu@" + IrisIP,
				"Verify SSH port 22 is open",
			},
			details: string(output),
		}
	}

	logger.Debug("SSH connection successful")
	return wazuhCheckResult{
		name:     "SSH Connectivity",
		category: "Remote Checks",
		passed:   true,
		details:  fmt.Sprintf("Successfully connected to ubuntu@%s", IrisIP),
	}
}

func checkRemotePortStatus(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh",
		"-i", SSHKey,
		"-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("ubuntu@%s", IrisIP),
		"sudo", "ss", "-tulpn", "|", "grep", fmt.Sprint(IrisPort))

	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Remote port check failed", zap.Error(err))
		return wazuhCheckResult{
			name:     "Remote Port Status",
			category: "Remote Checks",
			passed:   false,
			error:    fmt.Errorf("port %d not listening on Iris", IrisPort),
			remediation: []string{
				"Start webhook service on Iris: sudo systemctl start iris-webhook",
				"Check what's using the port: sudo ss -tulpn | grep " + fmt.Sprint(IrisPort),
			},
			details: string(output),
		}
	}

	logger.Debug("Remote port check successful", zap.String("output", string(output)))
	return wazuhCheckResult{
		name:     "Remote Port Status",
		category: "Remote Checks",
		passed:   true,
		details:  fmt.Sprintf("Port %d is listening on Iris:\n  %s", IrisPort, string(output)),
	}
}

func checkRemoteServiceStatus(rc *eos_io.RuntimeContext) wazuhCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh",
		"-i", SSHKey,
		"-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("ubuntu@%s", IrisIP),
		"systemctl", "status", "iris-webhook", "iris-worker", "--no-pager")

	output, err := cmd.CombinedOutput()

	// systemctl status returns non-zero if any service is not active
	// We still want to show the output
	details := string(output)

	if err != nil {
		logger.Warn("Remote service check shows issues", zap.String("output", details))
		return wazuhCheckResult{
			name:     "Remote Service Status",
			category: "Remote Checks",
			passed:   false,
			error:    fmt.Errorf("one or more services not active"),
			details:  details,
			remediation: []string{
				"Start services on Iris:",
				"  sudo systemctl start iris-webhook iris-worker",
				"Check logs:",
				"  sudo journalctl -u iris-webhook -n 50",
				"  sudo journalctl -u iris-worker -n 50",
			},
		}
	}

	logger.Debug("Remote services active")
	return wazuhCheckResult{
		name:     "Remote Service Status",
		category: "Remote Checks",
		passed:   true,
		details:  "All Iris services are active",
	}
}

type WazuhComponent string

func displayDetectedComponents(components map[WazuhComponent]*ComponentInfo) {
	fmt.Println("\n Detected Wazuh Components:")
	fmt.Println(strings.Repeat("=", 60))

	for _, info := range components {
		if !info.Detected {
			continue
		}

		status := " Stopped"
		if info.Running {
			status = " Running"
		}

		fmt.Printf("  • %-15s %s\n", string(info.Name), status)
	}
	fmt.Println()
}

// Display Results
func DisplayWazuhResults(results []wazuhCheckResult) {
	// Count by status
	passed := 0
	failed := 0
	warnings := 0

	categoryMap := make(map[string][]wazuhCheckResult)
	for _, r := range results {
		if r.passed && !r.warning {
			passed++
		} else if r.warning {
			warnings++
		} else {
			failed++
		}
		categoryMap[r.category] = append(categoryMap[r.category], r)
	}

	total := passed + failed + warnings

	// Header
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           WAZUH WEBHOOK DIAGNOSTIC REPORT                     ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Summary
	status := "HEALTHY"
	if failed > 0 {
		status = "ISSUES DETECTED"
	} else if warnings > 0 {
		status = "WARNINGS"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Passed: %d/%d checks\n", passed, total)
	if warnings > 0 {
		fmt.Printf("Warnings: %d\n", warnings)
	}
	if failed > 0 {
		fmt.Printf("Failed: %d checks\n", failed)
	}
	fmt.Println()

	// Group by category
	categories := []string{"Network", "Iris Service", "Wazuh Configuration", "Python Dependencies", "Test Webhook", "Logs", "Remote Checks"}

	for _, category := range categories {
		checks := categoryMap[category]
		if len(checks) == 0 {
			continue
		}

		fmt.Printf("┌─ %s\n", category)
		for _, check := range checks {
			symbol := "✓"
			if !check.passed {
				symbol = "✗"
			} else if check.warning {
				symbol = "⚠"
			}

			fmt.Printf("│  %s %s\n", symbol, check.name)

			// Show details for Verbose or failed/warning checks
			if (Verbose || !check.passed || check.warning) && check.details != "" {
				detailLines := strings.Split(check.details, "\n")
				for _, line := range detailLines {
					if line != "" {
						fmt.Printf("│    %s\n", line)
					}
				}
			}
		}
		fmt.Println("│")
	}

	// Show failures with remediation
	if failed > 0 {
		fmt.Println()
		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                   ISSUES & REMEDIATION                         ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Println()

		issueNum := 1
		for _, r := range results {
			if !r.passed && !r.warning {
				fmt.Printf("Issue %d: %s\n", issueNum, r.name)
				fmt.Printf("Problem: %v\n", r.error)
				fmt.Println()

				if len(r.remediation) > 0 {
					fmt.Println("Solutions:")
					for _, remedy := range r.remediation {
						fmt.Printf("  • %s\n", remedy)
					}
					fmt.Println()
				}
				issueNum++
			}
		}
	}

	// Show warnings
	if warnings > 0 {
		fmt.Println()
		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                          WARNINGS                              ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Println()

		for _, r := range results {
			if r.warning {
				fmt.Printf("⚠ %s\n", r.name)
				if r.error != nil {
					fmt.Printf("  %v\n", r.error)
				}
				if r.details != "" {
					fmt.Printf("  %s\n", r.details)
				}
				if len(r.remediation) > 0 {
					fmt.Println("  Suggestions:")
					for _, remedy := range r.remediation {
						fmt.Printf("    • %s\n", remedy)
					}
				}
				fmt.Println()
			}
		}
	}

	// Summary and next steps
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                          SUMMARY                               ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	if failed == 0 && warnings == 0 {
		fmt.Println("✓ Webhook integration is correctly configured")
		fmt.Println("✓ Network connectivity is good")
		fmt.Println("✓ All checks passed")
		fmt.Println()
		fmt.Println("Next Steps:")
		fmt.Println("  • Generate a real Wazuh alert (level ≥ configured threshold)")
		fmt.Println("  • Monitor logs: sudo tail -f /var/ossec/logs/integrations.log")
		fmt.Printf("  • Check Temporal UI: http://%s:8233\n", IrisIP)
	} else {
		fmt.Println("Issues detected - follow remediation steps above")
		fmt.Println()
		fmt.Println("After fixing issues:")
		fmt.Println("  1. Run this diagnostic again: eos debug wazuh --webhook-out")
		fmt.Println("  2. Monitor integration logs: sudo tail -f /var/ossec/logs/integrations.log")
		fmt.Printf("  3. Check Temporal UI: http://%s:8233\n", IrisIP)
	}
	fmt.Println()
}

func displayWazuhResults(results []DiagnosticResult) {
	if len(results) == 0 {
		return
	}

	fmt.Println("\n Diagnostic Results:")
	fmt.Println(strings.Repeat("=", 60))

	currentComponent := WazuhComponent("")

	for _, result := range results {
		if result.Component != currentComponent {
			currentComponent = result.Component
			fmt.Printf("\n[%s]\n", strings.ToUpper(string(currentComponent)))
		}

		icon := ""
		if !result.Passed {
			if result.Warning {
				icon = " "
			} else {
				icon = ""
			}
		}

		fmt.Printf("%s %s (%s)\n", icon, result.CheckName, result.Category)

		if result.Details != "" {
			fmt.Printf("   %s\n", result.Details)
		}

		if result.Error != nil {
			fmt.Printf("   Error: %s\n", result.Error)
		}

		if len(result.Remediation) > 0 {
			fmt.Println("   Remediation:")
			for _, rem := range result.Remediation {
				fmt.Printf("     • %s\n", rem)
			}
		}
	}

	passed := 0
	failed := 0
	warnings := 0

	for _, r := range results {
		if r.Passed {
			passed++
		} else if r.Warning {
			warnings++
		} else {
			failed++
		}
	}

	fmt.Printf("\n Summary: %d passed, %d failed, %d warnings\n\n", passed, failed, warnings)
}

func applyAutomaticFixes(rc *eos_io.RuntimeContext, results []DiagnosticResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Attempting automatic fixes")

	fmt.Println("\n🔧 Attempting Automatic Fixes:")
	fmt.Println(strings.Repeat("=", 60))

	for _, result := range results {
		if result.Passed || len(result.Remediation) == 0 {
			continue
		}

		// Only auto-fix simple service start issues
		if result.CheckName == "Service Status" && strings.Contains(result.Error.Error(), "not running") {
			serviceName := ""
			for _, rem := range result.Remediation {
				if strings.Contains(rem, "systemctl start") {
					parts := strings.Fields(rem)
					if len(parts) >= 3 {
						serviceName = parts[len(parts)-1]
						break
					}
				}
			}

			if serviceName != "" {
				fmt.Printf("  Starting %s...\n", serviceName)
				ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
				cmd := exec.CommandContext(ctx, "sudo", "systemctl", "start", serviceName)
				err := cmd.Run()
				cancel()

				if err != nil {
					fmt.Printf("     Failed to start %s: %v\n", serviceName, err)
				} else {
					fmt.Printf("     Successfully started %s\n", serviceName)
				}
			}
		}
	}

	fmt.Println()
}

const (
	ComponentAgent     WazuhComponent = "agent"
	ComponentManager   WazuhComponent = "manager"
	ComponentIndexer   WazuhComponent = "indexer"
	ComponentDashboard WazuhComponent = "dashboard"
	ComponentServer    WazuhComponent = "server"
)

type ComponentInfo struct {
	Name        WazuhComponent
	ServiceName string
	Detected    bool
	Running     bool
	ConfigPaths []string
	LogPaths    []string
	Ports       []int
	DataDirs    []string
}

type DiagnosticResult struct {
	Component   WazuhComponent
	CheckName   string
	Category    string
	Passed      bool
	Warning     bool
	Error       error
	Details     string
	Remediation []string
}

func runWazuhDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Wazuh diagnostics",
		zap.String("component_filter", Component),
		zap.Int("log_lines", LogLines))

	components := detectWazuhComponents(rc)

	if len(components) == 0 {
		fmt.Println("\n No Wazuh components detected on this system")
		fmt.Println("\nTo install Wazuh components:")
		fmt.Println("  • Agent:     eos create wazuh-agent")
		fmt.Println("  • Manager:   eos create wazuh")
		return nil
	}

	if Component != "" {
		filtered := make(map[WazuhComponent]*ComponentInfo)
		comp := WazuhComponent(Component)
		if info, exists := components[comp]; exists {
			filtered[comp] = info
			components = filtered
		} else {
			return fmt.Errorf("component '%s' not found on this system", Component)
		}
	}

	displayDetectedComponents(components)

	var allResults []DiagnosticResult
	for _, info := range components {
		if !info.Detected {
			continue
		}

		results := diagnoseComponent(rc, info)
		allResults = append(allResults, results...)
	}

	displayWazuhResults(allResults)

	if Fix {
		applyAutomaticFixes(rc, allResults)
	}

	return nil
}

func detectWazuhComponents(rc *eos_io.RuntimeContext) map[WazuhComponent]*ComponentInfo {
	components := map[WazuhComponent]*ComponentInfo{
		ComponentAgent: {
			Name:        ComponentAgent,
			ServiceName: "wazuh-agent",
			ConfigPaths: []string{"/var/ossec/etc/ossec.conf"},
			LogPaths:    []string{"/var/ossec/logs/ossec.log"},
			DataDirs:    []string{"/var/ossec"},
		},
		ComponentManager: {
			Name:        ComponentManager,
			ServiceName: "wazuh-manager",
			ConfigPaths: []string{"/var/ossec/etc/ossec.conf"},
			LogPaths:    []string{"/var/ossec/logs/ossec.log", "/var/ossec/logs/api.log"},
			Ports:       []int{1514, 1515, 55000},
			DataDirs:    []string{"/var/ossec"},
		},
		ComponentIndexer: {
			Name:        ComponentIndexer,
			ServiceName: "wazuh-indexer",
			ConfigPaths: []string{"/etc/wazuh-indexer/opensearch.yml"},
			LogPaths:    []string{"/var/log/wazuh-indexer/wazuh-indexer.log"},
			Ports:       []int{9200, 9300},
			DataDirs:    []string{"/var/lib/wazuh-indexer"},
		},
		ComponentDashboard: {
			Name:        ComponentDashboard,
			ServiceName: "wazuh-dashboard",
			ConfigPaths: []string{"/etc/wazuh-dashboard/opensearch_dashboards.yml"},
			LogPaths:    []string{"/var/log/wazuh-dashboard/wazuh-dashboard.log"},
			Ports:       []int{443, 5601},
			DataDirs:    []string{"/var/lib/wazuh-dashboard"},
		},
	}

	for _, info := range components {
		ctx, cancel := context.WithTimeout(rc.Ctx, 2*time.Second)
		cmd := exec.CommandContext(ctx, "systemctl", "list-unit-files", info.ServiceName+".service")
		output, err := cmd.Output()
		cancel()

		if err == nil && strings.Contains(string(output), info.ServiceName) {
			info.Detected = true

			ctx2, cancel2 := context.WithTimeout(rc.Ctx, 2*time.Second)
			statusCmd := exec.CommandContext(ctx2, "systemctl", "is-active", info.ServiceName)
			statusOutput, _ := statusCmd.Output()
			cancel2()

			info.Running = strings.TrimSpace(string(statusOutput)) == "active"
		}
	}

	return components
}

func diagnoseComponent(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	results = append(results, checkServiceStatus(info))
	results = append(results, checkConfigFiles(rc, info)...)
	results = append(results, analyzeComponentLogs(rc, info)...)

	if len(info.Ports) > 0 {
		results = append(results, checkPorts(rc, info)...)
	}

	results = append(results, checkProcessResources(rc, info))

	switch info.Name {
	case ComponentAgent:
		results = append(results, DiagnoseAgent(rc, info)...)
	case ComponentManager:
		results = append(results, DiagnoseManager(rc, info)...)
	case ComponentIndexer:
		results = append(results, DiagnoseIndexer(rc, info)...)
	case ComponentDashboard:
		results = append(results, DiagnoseDashboard(rc, info)...)
	}

	return results
}

func checkServiceStatus(info *ComponentInfo) DiagnosticResult {
	if !info.Running {
		return DiagnosticResult{
			Component: info.Name,
			CheckName: "Service Status",
			Category:  "System",
			Passed:    false,
			Error:     fmt.Errorf("service %s is not running", info.ServiceName),
			Remediation: []string{
				fmt.Sprintf("Start service: sudo systemctl start %s", info.ServiceName),
				fmt.Sprintf("Check logs: sudo journalctl -u %s -n 50", info.ServiceName),
			},
		}
	}

	return DiagnosticResult{
		Component: info.Name,
		CheckName: "Service Status",
		Category:  "System",
		Passed:    true,
		Details:   fmt.Sprintf("Service %s is active and running", info.ServiceName),
	}
}

func checkConfigFiles(_ *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	for _, configPath := range info.ConfigPaths {
		fileInfo, err := os.Stat(configPath)

		if os.IsNotExist(err) {
			results = append(results, DiagnosticResult{
				Component: info.Name,
				CheckName: fmt.Sprintf("Config: %s", filepath.Base(configPath)),
				Category:  "Configuration",
				Passed:    false,
				Error:     fmt.Errorf("config file not found: %s", configPath),
			})
			continue
		}

		details := fmt.Sprintf("Size: %d bytes, Perms: %s", fileInfo.Size(), fileInfo.Mode().Perm())

		results = append(results, DiagnosticResult{
			Component: info.Name,
			CheckName: fmt.Sprintf("Config: %s", filepath.Base(configPath)),
			Category:  "Configuration",
			Passed:    true,
			Details:   details,
		})
	}

	return results
}

func analyzeComponentLogs(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	for _, logPath := range info.LogPaths {
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			continue
		}

		ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
		cmd := exec.CommandContext(ctx, "tail", "-n", fmt.Sprint(LogLines), logPath)
		output, err := cmd.Output()
		cancel()

		if err != nil {
			continue
		}

		logContent := string(output)
		var errors []string
		lines := strings.Split(logContent, "\n")

		for _, line := range lines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "error") || strings.Contains(lineLower, "fatal") {
				errors = append(errors, line)
			}
		}

		details := fmt.Sprintf("Last %d lines from %s", LogLines, filepath.Base(logPath))
		if len(errors) > 0 {
			details += fmt.Sprintf("\n\nFound %d error(s) - showing first 3:", len(errors))
			for i, e := range errors {
				if i < 3 {
					details += "\n  • " + e
				}
			}
		}

		if Verbose {
			details += "\n\nRecent logs:\n" + logContent
		}

		results = append(results, DiagnosticResult{
			Component: info.Name,
			CheckName: fmt.Sprintf("Logs: %s", filepath.Base(logPath)),
			Category:  "Logs",
			Passed:    len(errors) == 0,
			Details:   details,
		})
	}

	return results
}

func checkPorts(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ss", "-tlnp")
	output, err := cmd.Output()

	if err != nil {
		return results
	}

	portsOutput := string(output)

	for _, port := range info.Ports {
		portStr := fmt.Sprintf(":%d", port)
		listening := strings.Contains(portsOutput, portStr)

		results = append(results, DiagnosticResult{
			Component: info.Name,
			CheckName: fmt.Sprintf("Port %d", port),
			Category:  "Network",
			Passed:    listening,
			Error: func() error {
				if !listening {
					return fmt.Errorf("port %d not listening", port)
				}
				return nil
			}(),
			Details: func() string {
				if listening {
					return fmt.Sprintf("Port %d is listening", port)
				}
				return ""
			}(),
		})
	}

	return results
}

func checkProcessResources(rc *eos_io.RuntimeContext, info *ComponentInfo) DiagnosticResult {
	if !info.Running {
		return DiagnosticResult{
			Component: info.Name,
			CheckName: "Process Resources",
			Category:  "System",
			Passed:    false,
		}
	}

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ps", "aux")
	output, err := cmd.Output()

	if err != nil {
		return DiagnosticResult{
			Component: info.Name,
			CheckName: "Process Resources",
			Category:  "System",
			Passed:    true,
			Warning:   true,
		}
	}

	var processLines []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, info.ServiceName) {
			processLines = append(processLines, line)
		}
	}

	details := fmt.Sprintf("Found %d process(es)", len(processLines))
	if Verbose && len(processLines) > 0 {
		details += "\n" + strings.Join(processLines, "\n")
	}

	return DiagnosticResult{
		Component: info.Name,
		CheckName: "Process Resources",
		Category:  "System",
		Passed:    len(processLines) > 0,
		Details:   details,
	}
}

// DiagnoseAgent performs agent-specific diagnostics
func DiagnoseAgent(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	// Check agent registration
	clientKeysPath := "/var/ossec/etc/client.keys"
	if data, err := os.ReadFile(clientKeysPath); err == nil {
		if len(data) == 0 {
			results = append(results, DiagnosticResult{
				Component: info.Name,
				CheckName: "Agent Registration",
				Category:  "Configuration",
				Passed:    false,
				Error:     fmt.Errorf("agent not registered"),
				Remediation: []string{
					"Register agent: sudo /var/ossec/bin/agent-auth -m <manager-ip>",
				},
			})
		} else {
			results = append(results, DiagnosticResult{
				Component: info.Name,
				CheckName: "Agent Registration",
				Category:  "Configuration",
				Passed:    true,
				Details:   "Agent is registered",
			})
		}
	}

	// Comprehensive connectivity diagnostics
	results = append(results, diagnoseAgentConnectivity(rc)...)

	return results
}

// diagnoseAgentConnectivity performs comprehensive agent connectivity diagnostics
func diagnoseAgentConnectivity(rc *eos_io.RuntimeContext) []DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	var results []DiagnosticResult

	// Extract server configuration from ossec.conf
	serverAddr, serverPort := extractAgentServerConfig(rc)
	if serverAddr == "" {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Server Configuration",
			Category:  "Connectivity",
			Passed:    false,
			Error:     fmt.Errorf("could not extract server address from configuration"),
		})
		return results
	}

	// 1. DNS Resolution Check
	results = append(results, CheckDNSResolution(rc, serverAddr)...)

	// 2. Network Interface Check
	results = append(results, CheckNetworkInterfaces(rc)...)

	// 3. IPv4 Connectivity Test
	ipv4Addrs := ResolveIPv4(rc, serverAddr)
	if len(ipv4Addrs) > 0 {
		results = append(results, CheckIPv4Connectivity(rc, ipv4Addrs[0], serverPort)...)
	}

	// 4. IPv6 Connectivity Test
	ipv6Addrs := ResolveIPv6(rc, serverAddr)
	if len(ipv6Addrs) > 0 {
		results = append(results, CheckIPv6Connectivity(rc, ipv6Addrs[0], serverPort)...)
	}

	// 5. Firewall Check
	results = append(results, CheckFirewallRules(rc, serverAddr, serverPort)...)

	// 6. Self-Connection Detection (is this host the manager?)
	if len(ipv4Addrs) > 0 {
		results = append(results, CheckSelfConnection(rc, serverAddr, ipv4Addrs[0])...)
	}

	// 7. Recent Agent Errors
	results = append(results, CheckAgentErrors(rc)...)

	logger.Debug("Agent connectivity diagnostics completed",
		zap.String("server", serverAddr),
		zap.String("port", serverPort),
		zap.Int("checks_performed", len(results)))

	return results
}

// extractAgentServerConfig extracts server address and port from ossec.conf
func extractAgentServerConfig(rc *eos_io.RuntimeContext) (string, string) {
	configPath := "/var/ossec/etc/ossec.conf"
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", ""
	}

	content := string(data)

	// Extract address
	addressStart := strings.Index(content, "<address>")
	addressEnd := strings.Index(content, "</address>")
	serverAddr := ""
	if addressStart != -1 && addressEnd != -1 && addressEnd > addressStart {
		serverAddr = strings.TrimSpace(content[addressStart+9 : addressEnd])
	}

	// Extract port
	portStart := strings.Index(content, "<port>")
	portEnd := strings.Index(content, "</port>")
	serverPort := "1514" // default
	if portStart != -1 && portEnd != -1 && portEnd > portStart {
		serverPort = strings.TrimSpace(content[portStart+6 : portEnd])
	}

	return serverAddr, serverPort
}

// CheckFirewallRules checks firewall rules for connectivity
func CheckFirewallRules(rc *eos_io.RuntimeContext, serverAddr string, serverPort string) []DiagnosticResult {
	// TODO: Implement firewall rule checking
	return []DiagnosticResult{{
		Component: ComponentAgent,
		CheckName: "Firewall Rules",
		Category:  "Connectivity",
		Passed:    true,
		Details:   fmt.Sprintf("Firewall check for %s:%s - TODO: Implement", serverAddr, serverPort),
	}}
}

// checkDNSResolution checks DNS resolution for the server
func CheckDNSResolution(rc *eos_io.RuntimeContext, serverAddr string) []DiagnosticResult {
	var results []DiagnosticResult

	// Check IPv4 resolution
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "dig", "+short", "A", serverAddr)
	output, err := cmd.Output()
	cancel()

	ipv4Addrs := strings.Split(strings.TrimSpace(string(output)), "\n")
	if err == nil && len(ipv4Addrs) > 0 && ipv4Addrs[0] != "" {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "DNS IPv4 Resolution",
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Resolved to: %s", strings.Join(ipv4Addrs, ", ")),
		})
	} else {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "DNS IPv4 Resolution",
			Category:  "Connectivity",
			Passed:    false,
			Error:     fmt.Errorf("no IPv4 addresses resolved"),
			Remediation: []string{
				fmt.Sprintf("Verify DNS: dig +short A %s", serverAddr),
				"Check /etc/resolv.conf for correct nameservers",
			},
		})
	}

	// Check IPv6 resolution
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd2 := exec.CommandContext(ctx2, "dig", "+short", "AAAA", serverAddr)
	output2, err2 := cmd2.Output()
	cancel2()

	ipv6Addrs := strings.Split(strings.TrimSpace(string(output2)), "\n")
	if err2 == nil && len(ipv6Addrs) > 0 && ipv6Addrs[0] != "" {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "DNS IPv6 Resolution",
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Resolved to: %s", strings.Join(ipv6Addrs, ", ")),
		})
	}

	return results
}

// resolveIPv4 returns IPv4 addresses for the given hostname
func ResolveIPv4(rc *eos_io.RuntimeContext, serverAddr string) []string {
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", "A", serverAddr)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	addrs := strings.Split(strings.TrimSpace(string(output)), "\n")
	var validAddrs []string
	for _, addr := range addrs {
		if addr != "" {
			validAddrs = append(validAddrs, addr)
		}
	}
	return validAddrs
}

// resolveIPv6 returns IPv6 addresses for the given hostname
func ResolveIPv6(rc *eos_io.RuntimeContext, serverAddr string) []string {
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", "AAAA", serverAddr)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	addrs := strings.Split(strings.TrimSpace(string(output)), "\n")
	var validAddrs []string
	for _, addr := range addrs {
		if addr != "" {
			validAddrs = append(validAddrs, addr)
		}
	}
	return validAddrs
}

// checkIPv4Connectivity tests IPv4 connectivity to the server
func CheckIPv4Connectivity(rc *eos_io.RuntimeContext, ipv4Addr, port string) []DiagnosticResult {
	var results []DiagnosticResult

	// Ping test
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "ping", "-c", "3", "-W", "2", ipv4Addr)
	err := cmd.Run()
	cancel()

	if err == nil {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "IPv4 Ping Test",
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Successfully pinged %s", ipv4Addr),
		})
	} else {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "IPv4 Ping Test",
			Category:  "Connectivity",
			Passed:    false,
			Warning:   true,
			Error:     fmt.Errorf("ping failed to %s", ipv4Addr),
			Remediation: []string{
				"Check network connectivity",
				"Verify firewall allows ICMP",
			},
		})
	}

	// TCP port connectivity test
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd2 := exec.CommandContext(ctx2, "nc", "-zv", "-w", "5", ipv4Addr, port)
	output2, err2 := cmd2.CombinedOutput()
	cancel2()

	if err2 == nil || strings.Contains(string(output2), "succeeded") {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: fmt.Sprintf("IPv4 Port %s Connectivity", port),
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Port %s is reachable on %s", port, ipv4Addr),
		})
	} else {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: fmt.Sprintf("IPv4 Port %s Connectivity", port),
			Category:  "Connectivity",
			Passed:    false,
			Error:     fmt.Errorf("cannot connect to port %s on %s", port, ipv4Addr),
			Details:   string(output2),
			Remediation: []string{
				fmt.Sprintf("Verify Wazuh manager is listening on port %s", port),
				"Check firewall rules: sudo ufw status",
				fmt.Sprintf("Test manually: nc -zv %s %s", ipv4Addr, port),
			},
		})
	}

	return results
}

// checkIPv6Connectivity tests IPv6 connectivity to the server
func CheckIPv6Connectivity(rc *eos_io.RuntimeContext, ipv6Addr, port string) []DiagnosticResult {
	var results []DiagnosticResult

	// Ping test
	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd := exec.CommandContext(ctx, "ping6", "-c", "3", "-W", "2", ipv6Addr)
	err := cmd.Run()
	cancel()

	if err == nil {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "IPv6 Ping Test",
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Successfully pinged %s", ipv6Addr),
		})
	} else {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "IPv6 Ping Test",
			Category:  "Connectivity",
			Passed:    false,
			Warning:   true,
			Details:   fmt.Sprintf("IPv6 ping failed (may not be configured): %s", ipv6Addr),
		})
	}

	// TCP port connectivity test
	ctx2, cancel2 := context.WithTimeout(rc.Ctx, 10*time.Second)
	cmd2 := exec.CommandContext(ctx2, "nc", "-6", "-zv", "-w", "5", ipv6Addr, port)
	output2, err2 := cmd2.CombinedOutput()
	cancel2()

	if err2 == nil || strings.Contains(string(output2), "succeeded") {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: fmt.Sprintf("IPv6 Port %s Connectivity", port),
			Category:  "Connectivity",
			Passed:    true,
			Details:   fmt.Sprintf("Port %s is reachable on %s", port, ipv6Addr),
		})
	}

	return results
}

// checkNetworkInterfaces checks available network interfaces
func CheckNetworkInterfaces(rc *eos_io.RuntimeContext) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "ip", "-brief", "addr", "show")
	output, err := cmd.Output()
	cancel()

	if err == nil {
		details := "Network interfaces:\n" + string(output)

		// Check for default route
		ctx2, cancel2 := context.WithTimeout(rc.Ctx, 5*time.Second)
		routeCmd := exec.CommandContext(ctx2, "ip", "route", "show")
		routeOutput, routeErr := routeCmd.Output()
		cancel2()

		hasDefaultRoute := false
		if routeErr == nil {
			hasDefaultRoute = strings.Contains(string(routeOutput), "default")
			details += "\n\nDefault route: "
			if hasDefaultRoute {
				details += "configured"
			} else {
				details += "NOT configured"
			}
		}

		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Network Interfaces",
			Category:  "Connectivity",
			Passed:    hasDefaultRoute,
			Warning:   !hasDefaultRoute,
			Details:   details,
			Remediation: func() []string {
				if !hasDefaultRoute {
					return []string{"No default route configured - check network settings"}
				}
				return nil
			}(),
		})
	}

	return results
}

// checkAgentFirewallRules checks firewall configuration for agent connectivity
func CheckAgentFirewallRules(rc *eos_io.RuntimeContext) []DiagnosticResult {
	var results []DiagnosticResult

	// Check UFW
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "ufw", "status", "verbose")
	output, err := cmd.Output()
	cancel()

	if err == nil {
		isActive := strings.Contains(string(output), "Status: active")
		details := "UFW Status:\n" + string(output)

		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Firewall Status (UFW)",
			Category:  "Connectivity",
			Passed:    true,
			Warning:   isActive, // Active firewall might block connections
			Details:   details,
			Remediation: func() []string {
				if isActive {
					return []string{
						"UFW is active - ensure outbound connections to Wazuh manager are allowed",
						"Allow outbound: sudo ufw allow out to <manager-ip> port 1514 proto tcp",
					}
				}
				return nil
			}(),
		})
	}

	return results
}

// checkSelfConnection detects if this host is trying to connect to itself
func CheckSelfConnection(rc *eos_io.RuntimeContext, serverAddr, serverIP string) []DiagnosticResult {
	var results []DiagnosticResult

	// Get current hostname
	hostname, err := os.Hostname()
	if err != nil {
		return results
	}

	// Get current host IPs
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "hostname", "-I")
	output, err := cmd.Output()
	cancel()

	if err != nil {
		return results
	}

	currentIPs := strings.Fields(string(output))
	isSelf := false

	for _, ip := range currentIPs {
		if ip == serverIP {
			isSelf = true
			break
		}
	}

	if isSelf {
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Self-Connection Detection",
			Category:  "Configuration",
			Passed:    false,
			Error:     fmt.Errorf("agent is configured to connect to itself"),
			Details: fmt.Sprintf(
				"WARNING: This host (%s) appears to BE %s!\n"+
					"Current IPs: %s\n"+
					"Server resolves to: %s\n"+
					"Agents should not be installed on the manager server.",
				hostname, serverAddr, strings.Join(currentIPs, ", "), serverIP),
			Remediation: []string{
				"Remove Wazuh agent from the manager server",
				"Install agent on a different host",
				"Or configure a separate manager if this should be an agent",
			},
		})
	}

	return results
}

// checkAgentErrors analyzes recent agent errors
func CheckAgentErrors(rc *eos_io.RuntimeContext) []DiagnosticResult {
	var results []DiagnosticResult

	logPath := "/var/ossec/logs/ossec.log"
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "grep", "ERROR", logPath)
	output, err := cmd.Output()
	cancel()

	if err != nil && len(output) == 0 {
		// No errors found - this is good
		results = append(results, DiagnosticResult{
			Component: ComponentAgent,
			CheckName: "Recent Agent Errors",
			Category:  "Logs",
			Passed:    true,
			Details:   "No recent ERROR entries in agent log",
		})
		return results
	}

	// Parse and categorize errors
	errorLines := strings.Split(string(output), "\n")
	var connectErrors, authErrors, configErrors, otherErrors []string

	for _, line := range errorLines {
		if line == "" {
			continue
		}
		lineLower := strings.ToLower(line)

		if strings.Contains(lineLower, "connect") || strings.Contains(lineLower, "connection") {
			connectErrors = append(connectErrors, line)
		} else if strings.Contains(lineLower, "auth") || strings.Contains(lineLower, "key") {
			authErrors = append(authErrors, line)
		} else if strings.Contains(lineLower, "config") {
			configErrors = append(configErrors, line)
		} else {
			otherErrors = append(otherErrors, line)
		}
	}

	details := fmt.Sprintf("Found %d error entries:\n", len(errorLines)-1)
	if len(connectErrors) > 0 {
		details += fmt.Sprintf("  • Connection errors: %d\n", len(connectErrors))
	}
	if len(authErrors) > 0 {
		details += fmt.Sprintf("  • Authentication errors: %d\n", len(authErrors))
	}
	if len(configErrors) > 0 {
		details += fmt.Sprintf("  • Configuration errors: %d\n", len(configErrors))
	}
	if len(otherErrors) > 0 {
		details += fmt.Sprintf("  • Other errors: %d\n", len(otherErrors))
	}

	// Show last 3 errors
	details += "\nMost recent errors:\n"
	recentErrors := errorLines
	if len(recentErrors) > 10 {
		recentErrors = recentErrors[len(recentErrors)-10:]
	}
	for i, line := range recentErrors {
		if line != "" && i < 3 {
			details += "  " + line + "\n"
		}
	}

	remediation := []string{}
	if len(connectErrors) > 0 {
		remediation = append(remediation, "Connection errors detected - check network connectivity to manager")
	}
	if len(authErrors) > 0 {
		remediation = append(remediation, "Authentication errors detected - verify agent registration")
	}
	if len(configErrors) > 0 {
		remediation = append(remediation, "Configuration errors detected - check /var/ossec/etc/ossec.conf")
	}
	remediation = append(remediation, "View full log: sudo tail -50 /var/ossec/logs/ossec.log")

	results = append(results, DiagnosticResult{
		Component:   ComponentAgent,
		CheckName:   "Recent Agent Errors",
		Category:    "Logs",
		Passed:      false,
		Details:     details,
		Remediation: remediation,
	})

	return results
}

func DiagnoseManager(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	cmd := exec.CommandContext(ctx, "curl", "-s", "-k", "https://localhost:55000/")
	output, err := cmd.Output()
	cancel()

	apiWorking := err == nil && strings.Contains(string(output), "Wazuh")

	results = append(results, DiagnosticResult{
		Component: info.Name,
		CheckName: "Wazuh API",
		Category:  "Service",
		Passed:    apiWorking,
		Details: func() string {
			if apiWorking {
				return "API is responding"
			}
			return "API not responding"
		}(),
	})

	return results
}

func DiagnoseIndexer(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "curl", "-s", "-k", "-u", "admin:admin",
		"https://localhost:9200/_cluster/health")
	output, err := cmd.Output()
	cancel()

	if err == nil {
		status := "unknown"
		if strings.Contains(string(output), `"green"`) {
			status = "green"
		} else if strings.Contains(string(output), `"yellow"`) {
			status = "yellow"
		} else if strings.Contains(string(output), `"red"`) {
			status = "red"
		}

		results = append(results, DiagnosticResult{
			Component: info.Name,
			CheckName: "Cluster Health",
			Category:  "Service",
			Passed:    status == "green" || status == "yellow",
			Warning:   status == "yellow",
			Details:   fmt.Sprintf("Cluster status: %s", status),
		})
	}

	return results
}

func DiagnoseDashboard(rc *eos_io.RuntimeContext, info *ComponentInfo) []DiagnosticResult {
	var results []DiagnosticResult

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	cmd := exec.CommandContext(ctx, "curl", "-s", "-k", "https://localhost:443/app/wazuh")
	err := cmd.Run()
	cancel()

	results = append(results, DiagnosticResult{
		Component: info.Name,
		CheckName: "Dashboard Access",
		Category:  "Service",
		Passed:    err == nil,
		Details: func() string {
			if err == nil {
				return "Dashboard is accessible"
			}
			return "Dashboard not accessible"
		}(),
	})

	return results
}

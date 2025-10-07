// cmd/debug/metis.go
package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var debugMetisCmd = &cobra.Command{
	Use:   "metis",
	Short: "Debug Metis installation and configuration",
	Long: `Comprehensive diagnostic tool for Metis security alert processing system.

Enhanced Phase 1 checks performed:

Infrastructure (6 checks):
  • Project structure and files
  • Temporal CLI availability
  • Binary accessibility (non-root user access)
  • Port status (7233, 8233, 8080)
  • Temporal server health (deep check with gRPC verification)

Configuration (3 checks):
  • Configuration file validity
  • Azure OpenAI configuration
  • SMTP configuration

Services (3 checks):
  • Worker process health (with uptime check)
  • Webhook server health (with HTTP health endpoint)
  • Recent workflows in Temporal

System (1 check):
  • Go module dependencies

Flags:
  --test      Send a test alert through the system
  --verbose   Show detailed diagnostic output`,
	RunE: eos.Wrap(runDebugMetis),
}

var (
	testAlert bool
	verbose   bool
)

func init() {
	debugMetisCmd.Flags().BoolVar(&testAlert, "test", false, "Send a test alert")
	debugMetisCmd.Flags().BoolVar(&verbose, "verbose", false, "Verbose output")
	debugCmd.AddCommand(debugMetisCmd)
}

type checkResult struct {
	name        string
	category    string
	passed      bool
	error       error
	remediation []string
	details     string
}

func runDebugMetis(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Starting Metis diagnostic checks")

	projectDir := "/opt/metis"
	results := []checkResult{}

	// Run all checks
	// Load configuration first (needed by other checks)
	config, configResult := checkConfigurationWithResult(rc, projectDir)

	// Infrastructure checks
	results = append(results, checkProjectStructureWithResult(rc, projectDir))
	results = append(results, checkTemporalCLIWithResult(rc))
	results = append(results, checkBinaryAccessibilityWithResult(rc)) // NEW: Phase 1
	results = append(results, checkPortStatusWithResult(rc))           // NEW: Phase 1
	results = append(results, checkTemporalServerHealthDeepWithResult(rc, config)) // NEW: Phase 1 (replaces old check)

	// Configuration checks
	results = append(results, configResult)
	results = append(results, checkAzureOpenAIWithResult(rc, config))
	results = append(results, checkSMTPConfigWithResult(rc, config))

	// Services checks
	results = append(results, checkSystemdServicesWithResult(rc))      // NEW: Check systemd units exist and status
	results = append(results, checkWorkerProcessHealthWithResult(rc))  // NEW: Phase 1 (enhanced)
	results = append(results, checkWebhookServerHealthWithResult(rc, config)) // NEW: Phase 1 (enhanced)
	results = append(results, checkRecentWorkflowsWithResult(rc, config))

	// System checks
	results = append(results, checkGoDependenciesWithResult(rc, projectDir))

	// Display results
	displayDiagnosticResults(results)

	// Test alert if requested
	if testAlert {
		fmt.Println("\n╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                      SENDING TEST ALERT                        ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Println()
		if err := sendTestAlert(rc, config); err != nil {
			fmt.Printf("✗ Test alert failed: %v\n", err)
			fmt.Println("\nRemediation:")
			fmt.Println("  • Ensure webhook server is running")
			fmt.Println("  • Check webhook logs for errors")
			fmt.Println("  • Verify Temporal server is accessible")
			return fmt.Errorf("test alert failed: %w", err)
		}
		fmt.Println("✓ Test alert sent successfully")
		fmt.Println()
		fmt.Println("Next Steps:")
		fmt.Println("  1. Check Temporal UI at http://localhost:8233")
		fmt.Println("  2. Verify workflow execution completed")
		fmt.Println("  3. Check email inbox for alert notification")
	}

	// Diagnostics are informational, not errors
	// Always return nil (exit 0) - the display shows what passed/failed
	// Only return error for actual system failures (can't connect, etc.)
	return nil
}

func displayDiagnosticResults(results []checkResult) {
	// Count passed/failed by category
	passed := 0
	failed := 0
	categoryMap := make(map[string][]checkResult)

	for _, r := range results {
		if r.passed {
			passed++
		} else {
			failed++
		}
		categoryMap[r.category] = append(categoryMap[r.category], r)
	}

	total := passed + failed

	// Header
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              METIS DIAGNOSTIC REPORT                           ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Summary
	status := "HEALTHY"
	if failed > 0 {
		status = "ISSUES DETECTED"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Passed: %d/%d checks\n", passed, total)
	if failed > 0 {
		fmt.Printf("Failed: %d checks\n", failed)
	}
	fmt.Println()

	// Group results by category
	categories := []string{"Infrastructure", "Configuration", "Services", "Dependencies"}

	for _, category := range categories {
		checks := categoryMap[category]
		if len(checks) == 0 {
			continue
		}

		fmt.Printf("┌─ %s\n", category)
		for _, check := range checks {
			if check.passed {
				fmt.Printf("│  ✓ %s\n", check.name)
				// Show details if verbose OR if details contain structured info
				if check.details != "" && (verbose || strings.Contains(check.details, "✓") || strings.Contains(check.details, "✗")) {
					// Indent multi-line details
					detailLines := strings.Split(check.details, "\n")
					for _, line := range detailLines {
						if line != "" {
							fmt.Printf("│    %s\n", line)
						}
					}
				}
			} else {
				fmt.Printf("│  ✗ %s\n", check.name)
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
			if !r.passed {
				fmt.Printf("Issue %d: %s\n", issueNum, r.name)
				fmt.Printf("Problem: %v\n", r.error)

				// Show details if available
				if r.details != "" {
					fmt.Println()
					fmt.Println("Details:")
					detailLines := strings.Split(r.details, "\n")
					for _, line := range detailLines {
						if line != "" {
							fmt.Printf("  %s\n", line)
						}
					}
				}

				fmt.Println()
				fmt.Println("Solutions:")
				for _, remedy := range r.remediation {
					fmt.Printf("  • %s\n", remedy)
				}
				fmt.Println()
				issueNum++
			}
		}

		// Next steps summary
		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                        NEXT STEPS                              ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("Recommended action order:")
		fmt.Println()

		step := 1
		// Infrastructure first
		for _, r := range results {
			if !r.passed && r.category == "Infrastructure" {
				fmt.Printf("%d. Fix: %s\n", step, r.name)
				step++
			}
		}
		// Then configuration
		for _, r := range results {
			if !r.passed && r.category == "Configuration" {
				fmt.Printf("%d. Fix: %s\n", step, r.name)
				step++
			}
		}
		// Then services
		for _, r := range results {
			if !r.passed && r.category == "Services" {
				fmt.Printf("%d. Fix: %s\n", step, r.name)
				step++
			}
		}
		// Finally dependencies
		for _, r := range results {
			if !r.passed && r.category == "Dependencies" {
				fmt.Printf("%d. Fix: %s\n", step, r.name)
				step++
			}
		}
		fmt.Println()
		fmt.Println("After fixing issues, run: eos debug metis")
		fmt.Println()
	} else {
		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                  ALL CHECKS PASSED                             ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("Metis is configured and operational.")
		fmt.Println()
		fmt.Println("To test the alert processing pipeline:")
		fmt.Println("  eos debug metis --test")
		fmt.Println()
		fmt.Println("To view Temporal workflows:")
		fmt.Println("  • Open http://localhost:8233")
		fmt.Println("  • Or use: temporal workflow list")
		fmt.Println()
	}
}

func checkProjectStructureWithResult(rc *eos_io.RuntimeContext, projectDir string) checkResult {
	err := checkProjectStructure(rc, projectDir)
	result := checkResult{
		name:     "Project Structure",
		category: "Infrastructure",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		result.remediation = []string{
			"Install Metis using: eos create metis",
			"Or clone from repository: git clone <metis-repo> /opt/metis",
			fmt.Sprintf("Ensure directory exists: sudo mkdir -p %s", projectDir),
			"Verify required subdirectories: worker/, webhook/",
		}
	} else {
		result.details = fmt.Sprintf("All required files present in %s", projectDir)
	}

	return result
}

func checkProjectStructure(rc *eos_io.RuntimeContext, projectDir string) error {
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

type MetisConfig struct {
	Temporal struct {
		HostPort  string `yaml:"host_port"`
		Namespace string `yaml:"namespace"`
		TaskQueue string `yaml:"task_queue"`
	} `yaml:"temporal"`
	AzureOpenAI struct {
		Endpoint       string `yaml:"endpoint"`
		APIKey         string `yaml:"api_key"`
		DeploymentName string `yaml:"deployment_name"`
		APIVersion     string `yaml:"api_version"`
	} `yaml:"azure_openai"`
	Email struct {
		SMTPHost string `yaml:"smtp_host"`
		SMTPPort int    `yaml:"smtp_port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		From     string `yaml:"from"`
		To       string `yaml:"to"`
	} `yaml:"email"`
	Webhook struct {
		Port int `yaml:"port"`
	} `yaml:"webhook"`
}

func checkConfigurationWithResult(rc *eos_io.RuntimeContext, projectDir string) (*MetisConfig, checkResult) {
	config, err := checkConfiguration(rc, projectDir)
	result := checkResult{
		name:     "Configuration File",
		category: "Configuration",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		configPath := filepath.Join(projectDir, "config.yaml")
		result.remediation = []string{
			fmt.Sprintf("Edit configuration file: sudo nano %s", configPath),
			"Verify YAML syntax is valid",
			"Ensure all required fields are set:",
			"  - temporal.host_port (e.g., localhost:7233)",
			"  - azure_openai.endpoint (Azure OpenAI endpoint URL)",
			"  - email.smtp_host (SMTP server address)",
			"Example config: https://github.com/.../config.example.yaml",
		}
	} else {
		result.details = "Configuration valid with all required fields"
	}

	return config, result
}

func checkConfiguration(rc *eos_io.RuntimeContext, projectDir string) (*MetisConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	configPath := filepath.Join(projectDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config MetisConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate required fields
	if config.Temporal.HostPort == "" {
		return nil, fmt.Errorf("temporal.host_port not configured")
	}
	if config.AzureOpenAI.Endpoint == "" || strings.Contains(config.AzureOpenAI.Endpoint, "YOUR-") {
		return nil, fmt.Errorf("azure_openai.endpoint not configured")
	}
	if config.Email.SMTPHost == "" {
		return nil, fmt.Errorf("email.smtp_host not configured")
	}

	if verbose {
		logger.Debug("Configuration loaded",
			zap.String("temporal_host", config.Temporal.HostPort),
			zap.String("openai_endpoint", config.AzureOpenAI.Endpoint),
			zap.String("smtp_host", config.Email.SMTPHost))
	}

	return &config, nil
}

func checkTemporalServerWithResult(rc *eos_io.RuntimeContext, config *MetisConfig) checkResult {
	err := checkTemporalServer(rc, config)
	result := checkResult{
		name:     "Temporal Server",
		category: "Infrastructure",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		result.remediation = []string{
			"Start Temporal dev server: temporal server start-dev",
			"Or use Docker: docker run -p 7233:7233 temporalio/auto-setup",
			"Verify server is listening: netstat -tlnp | grep 7233",
			"Check Temporal UI at http://localhost:8233",
			"Update config.yaml temporal.host_port if using different address",
		}
	} else {
		if config != nil {
			result.details = fmt.Sprintf("Connected to Temporal at %s", config.Temporal.HostPort)
		}
	}

	return result
}

func checkTemporalServer(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Try to connect to Temporal health endpoint
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	healthURL := fmt.Sprintf("http://%s/", strings.Replace(config.Temporal.HostPort, ":7233", ":7233", 1))
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("temporal server not reachable at %s: %w", config.Temporal.HostPort, err)
	}
	defer resp.Body.Close()

	return nil
}

// Phase 1 Enhanced Diagnostics

func checkTemporalCLIWithResult(rc *eos_io.RuntimeContext) checkResult {
	logger := otelzap.Ctx(rc.Ctx)

	temporalPath, err := exec.LookPath("temporal")
	if err != nil {
		return checkResult{
			name:     "Temporal CLI",
			category: "Infrastructure",
			passed:   false,
			error:    fmt.Errorf("temporal CLI not found in PATH"),
			remediation: []string{
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
		return checkResult{
			name:     "Temporal CLI",
			category: "Infrastructure",
			passed:   false,
			error:    fmt.Errorf("temporal binary found but not executable: %w", err),
			remediation: []string{
				"Fix permissions: sudo chmod 755 " + temporalPath,
				"Or reinstall: eos repair metis --auto-yes",
			},
		}
	}

	logger.Debug("Temporal CLI check passed", zap.String("path", temporalPath), zap.String("version", string(output)))

	return checkResult{
		name:     "Temporal CLI",
		category: "Infrastructure",
		passed:   true,
		details:  fmt.Sprintf("Found at %s", temporalPath),
	}
}

func checkBinaryAccessibilityWithResult(rc *eos_io.RuntimeContext) checkResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		logger.Warn("Could not determine current user", zap.Error(err))
	}

	// Check if temporal is in PATH and accessible
	temporalPath, err := exec.LookPath("temporal")
	if err != nil {
		return checkResult{
			name:     "Binary Accessibility",
			category: "Infrastructure",
			passed:   false,
			error:    fmt.Errorf("temporal not in PATH"),
			remediation: []string{
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
			return checkResult{
				name:     "Binary Accessibility",
				category: "Infrastructure",
				passed:   false,
				error:    fmt.Errorf("temporal binary not accessible to non-root users: %s", string(output)),
				remediation: []string{
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
		return checkResult{
			name:     "Binary Accessibility",
			category: "Infrastructure",
			passed:   false,
			error:    fmt.Errorf("temporal binary not executable: %w", err),
			remediation: []string{
				"Fix permissions: sudo chmod 755 " + temporalPath,
			},
		}
	}

	return checkResult{
		name:     "Binary Accessibility",
		category: "Infrastructure",
		passed:   true,
		details:  fmt.Sprintf("Temporal binary accessible at %s", temporalPath),
	}
}

func checkPortStatusWithResult(rc *eos_io.RuntimeContext) checkResult {
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
		// That will be checked by checkSystemdServicesWithResult
		return checkResult{
			name:     "Port Status",
			category: "Infrastructure",
			passed:   false,
			error:    fmt.Errorf("%d ports not listening", len(notListening)),
			remediation: []string{
				"Check if services are installed: systemctl list-units 'metis*' 'temporal*'",
				"If services exist but stopped: see 'Systemd Services' check for start commands",
				"If services don't exist: run 'eos create metis' or 'eos repair metis'",
			},
			details: detailsText,
		}
	}

	logger.Debug("All ports listening", zap.Strings("ports", listening))

	return checkResult{
		name:     "Port Status",
		category: "Infrastructure",
		passed:   true,
		details:  detailsText,
	}
}

func checkTemporalServerHealthDeepWithResult(rc *eos_io.RuntimeContext, config *MetisConfig) checkResult {
	logger := otelzap.Ctx(rc.Ctx)

	if config == nil {
		return checkResult{
			name:     "Temporal Server Health",
			category: "Infrastructure",
			passed:   false,
			error:    fmt.Errorf("config not loaded"),
			remediation: []string{
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

		return checkResult{
			name:     "Temporal Server Health",
			category: "Infrastructure",
			passed:   false,
			error:    fmt.Errorf("port %s not listening", hostPort),
			remediation: remediation,
			details:  fmt.Sprintf("systemd status: %s", systemdStatus),
		}
	}
	conn.Close()
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
			defer resp.Body.Close()
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
			defer apiResp.Body.Close()
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

		return checkResult{
			name:     "Temporal Server Health",
			category: "Infrastructure",
			passed:   false,
			error:    fmt.Errorf("server listening but health check failed: %s", string(output)),
			remediation: []string{
				"Server might be starting up - wait 30 seconds and retry",
				"Check logs: sudo journalctl -u temporal -n 50",
				"Restart server: sudo systemctl restart temporal",
				"Check for port conflicts: lsof -i :7233",
				"Verify process is healthy: ps aux | grep temporal",
			},
			details: detailsText,
		}
	}

	logger.Debug("Temporal server health check passed", zap.String("output", string(output)))
	healthDetails = append(healthDetails, "  ✓ CLI health check: passed")

	return checkResult{
		name:     "Temporal Server Health",
		category: "Infrastructure",
		passed:   true,
		details:  strings.Join(healthDetails, "\n"),
	}
}

func checkWorkerProcessHealthWithResult(rc *eos_io.RuntimeContext) checkResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if worker is running
	cmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", "metis.*worker")
	output, err := cmd.Output()
	if err != nil {
		return checkResult{
			name:     "Worker Process Health",
			category: "Services",
			passed:   false,
			error:    fmt.Errorf("worker process not running"),
			remediation: []string{
				"Start worker: sudo systemctl start metis-worker",
				"Or manually: cd /opt/metis/worker && go run main.go",
				"Check logs: sudo journalctl -u metis-worker -n 50",
				"Ensure Temporal server is running first",
			},
		}
	}

	pids := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pids) == 0 || pids[0] == "" {
		return checkResult{
			name:     "Worker Process Health",
			category: "Services",
			passed:   false,
			error:    fmt.Errorf("worker process not found"),
			remediation: []string{
				"Start worker: sudo systemctl start metis-worker",
				"Check logs: sudo journalctl -u metis-worker -n 50",
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

	return checkResult{
		name:     "Worker Process Health",
		category: "Services",
		passed:   true,
		details:  details,
	}
}

func checkWebhookServerHealthWithResult(rc *eos_io.RuntimeContext, config *MetisConfig) checkResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if webhook is running
	cmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", "metis.*webhook")
	output, err := cmd.Output()
	if err != nil {
		return checkResult{
			name:     "Webhook Server Health",
			category: "Services",
			passed:   false,
			error:    fmt.Errorf("webhook process not running"),
			remediation: []string{
				"Start webhook: sudo systemctl start metis-webhook",
				"Or manually: cd /opt/metis/webhook && go run main.go",
				"Check logs: sudo journalctl -u metis-webhook -n 50",
			},
		}
	}

	pids := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pids) == 0 || pids[0] == "" {
		return checkResult{
			name:     "Webhook Server Health",
			category: "Services",
			passed:   false,
			error:    fmt.Errorf("webhook process not found"),
			remediation: []string{
				"Start webhook: sudo systemctl start metis-webhook",
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
			return checkResult{
				name:     "Webhook Server Health",
				category: "Services",
				passed:   false,
				error:    fmt.Errorf("webhook process running (PID %s) but health check failed: %w", pid, err),
				remediation: []string{
					"Check logs: sudo journalctl -u metis-webhook -n 50",
					"Restart webhook: sudo systemctl restart metis-webhook",
					"Verify port is correct in config.yaml",
				},
			}
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return checkResult{
				name:     "Webhook Server Health",
				category: "Services",
				passed:   false,
				error:    fmt.Errorf("webhook health check returned status %d", resp.StatusCode),
				remediation: []string{
					"Check logs: sudo journalctl -u metis-webhook -n 50",
					"Restart webhook: sudo systemctl restart metis-webhook",
				},
			}
		}
	}

	details := fmt.Sprintf("Webhook running (PID %s), health check passed", pid)

	return checkResult{
		name:     "Webhook Server Health",
		category: "Services",
		passed:   true,
		details:  details,
	}
}

func checkSystemdServicesWithResult(rc *eos_io.RuntimeContext) checkResult {
	logger := otelzap.Ctx(rc.Ctx)

	services := []string{"temporal", "metis-worker", "metis-webhook"}

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
		output, err := statusCmd.Output()
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
		return checkResult{
			name:     "Systemd Services",
			category: "Services",
			passed:   false,
			error:    fmt.Errorf("service units not installed: %s", strings.Join(missing, ", ")),
			remediation: []string{
				"Install services: eos create metis",
				"Or manually install: eos repair metis --auto-yes",
				"Services should be installed to: /etc/systemd/system/",
			},
			details: detailsText,
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

		return checkResult{
			name:     "Systemd Services",
			category: "Services",
			passed:   false,
			error:    fmt.Errorf("%d services not active", len(problemServices)),
			remediation: remediation,
			details: detailsText,
		}
	}

	// All services active
	logger.Debug("All systemd services active", zap.Strings("services", active))

	return checkResult{
		name:     "Systemd Services",
		category: "Services",
		passed:   true,
		details:  detailsText,
	}
}

func checkWorkerProcessWithResult(rc *eos_io.RuntimeContext) checkResult {
	err := checkWorkerProcess(rc)
	result := checkResult{
		name:     "Worker Process",
		category: "Services",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		result.remediation = []string{
			"Start worker manually: cd /opt/metis/worker && go run main.go",
			"Or enable systemd service: sudo systemctl start metis-worker",
			"Check worker logs: journalctl -u metis-worker -f",
			"Verify Go is installed: go version",
			"Ensure Temporal server is running first",
		}
	} else {
		result.details = "Worker process active and polling task queue"
	}

	return result
}

func checkWorkerProcess(rc *eos_io.RuntimeContext) error {
	// Check if worker is running via systemd
	checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "metis-worker")
	if output, err := checkCmd.Output(); err == nil {
		status := strings.TrimSpace(string(output))
		if status == "active" {
			return nil
		}
	}

	// Check if running as standalone process
	psCmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", "worker/main.go")
	if err := psCmd.Run(); err == nil {
		return nil // Process found
	}

	return fmt.Errorf("worker process not running")
}

func checkWebhookServerWithResult(rc *eos_io.RuntimeContext, config *MetisConfig) checkResult {
	err := checkWebhookServer(rc, config)
	result := checkResult{
		name:     "Webhook Server",
		category: "Services",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		result.remediation = []string{
			"Start webhook manually: cd /opt/metis/webhook && go run main.go",
			"Or enable systemd service: sudo systemctl start metis-webhook",
			"Check webhook logs: journalctl -u metis-webhook -f",
			"Verify port is not in use: netstat -tlnp | grep <port>",
			"Test health endpoint: curl http://localhost:<port>/health",
		}
	} else {
		if config != nil {
			result.details = fmt.Sprintf("Webhook server responding on port %d", config.Webhook.Port)
		}
	}

	return result
}

func checkWebhookServer(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Check if webhook is running via systemd
	checkCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "metis-webhook")
	if output, err := checkCmd.Output(); err == nil {
		status := strings.TrimSpace(string(output))
		if status == "active" {
			// Also check HTTP endpoint
			return checkWebhookHTTP(rc, config)
		}
	}

	// Check if running as standalone process
	psCmd := exec.CommandContext(rc.Ctx, "pgrep", "-f", "webhook/main.go")
	if err := psCmd.Run(); err == nil {
		return checkWebhookHTTP(rc, config)
	}

	return fmt.Errorf("webhook server not running")
}

func checkWebhookHTTP(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	webhookURL := fmt.Sprintf("http://localhost:%d/health", config.Webhook.Port)
	req, err := http.NewRequestWithContext(ctx, "GET", webhookURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook health endpoint not responding: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func checkAzureOpenAIWithResult(rc *eos_io.RuntimeContext, config *MetisConfig) checkResult {
	err := checkAzureOpenAI(rc, config)
	result := checkResult{
		name:     "Azure OpenAI Configuration",
		category: "Configuration",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		result.remediation = []string{
			"Get Azure OpenAI credentials from Azure Portal",
			"Edit config.yaml and set azure_openai section:",
			"  endpoint: https://<resource>.openai.azure.com/",
			"  api_key: <your-api-key>",
			"  deployment_name: <your-deployment>",
			"  api_version: 2024-02-15-preview",
			"Docs: https://learn.microsoft.com/azure/ai-services/openai/",
		}
	} else {
		result.details = "Azure OpenAI credentials configured"
	}

	return result
}

func checkAzureOpenAI(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	// Basic validation
	if strings.Contains(config.AzureOpenAI.APIKey, "YOUR-") {
		return fmt.Errorf("azure_openai.api_key contains placeholder text")
	}
	if config.AzureOpenAI.DeploymentName == "" {
		return fmt.Errorf("azure_openai.deployment_name not set")
	}
	if !strings.HasPrefix(config.AzureOpenAI.Endpoint, "https://") {
		return fmt.Errorf("azure_openai.endpoint must start with https://")
	}

	return nil
}

func checkSMTPConfigWithResult(rc *eos_io.RuntimeContext, config *MetisConfig) checkResult {
	err := checkSMTPConfig(rc, config)
	result := checkResult{
		name:     "SMTP Configuration",
		category: "Configuration",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		result.remediation = []string{
			"Configure SMTP settings in config.yaml email section:",
			"  smtp_host: smtp.gmail.com (or your SMTP server)",
			"  smtp_port: 587 (or 465 for SSL)",
			"  username: your-email@example.com",
			"  password: <app-password>",
			"  from: metis@example.com",
			"  to: security-team@example.com",
			"For Gmail: use App Password, not account password",
		}
	} else {
		result.details = "SMTP configuration complete"
	}

	return result
}

func checkSMTPConfig(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	if config.Email.SMTPHost == "" {
		return fmt.Errorf("email.smtp_host not set")
	}
	if config.Email.SMTPPort == 0 {
		return fmt.Errorf("email.smtp_port not set")
	}
	if config.Email.From == "" {
		return fmt.Errorf("email.from not set")
	}
	if config.Email.To == "" {
		return fmt.Errorf("email.to not set")
	}

	return nil
}

func checkRecentWorkflowsWithResult(rc *eos_io.RuntimeContext, config *MetisConfig) checkResult {
	err := checkRecentWorkflows(rc, config)
	result := checkResult{
		name:     "Temporal CLI",
		category: "Infrastructure",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		// Run diagnostics to find where Temporal might be
		diagnostics := findTemporalBinary(rc)

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

		result.remediation = remediation
	} else {
		result.details = "Temporal CLI available and workflow history accessible"
	}

	return result
}

func findTemporalBinary(rc *eos_io.RuntimeContext) string {
	logger := otelzap.Ctx(rc.Ctx)
	var findings []string

	// Check common installation locations
	commonPaths := []string{
		"/usr/local/bin/temporal",
		"/usr/bin/temporal",
		os.ExpandEnv("$HOME/.local/bin/temporal"),
		os.ExpandEnv("$HOME/.temporalio/bin/temporal"), // Official installer location
		"/root/.temporalio/bin/temporal",               // Root user installation
		"/opt/temporal/temporal",
	}

	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			findings = append(findings, fmt.Sprintf("✓ Found at: %s", path))

			// Check if executable
			if info.Mode()&0111 == 0 {
				findings = append(findings, "  ✗ NOT EXECUTABLE")
				findings = append(findings, fmt.Sprintf("  Fix: sudo chmod +x %s", path))
			} else {
				// Binary is executable - check if it's in PATH
				pathEnv := os.Getenv("PATH")
				binaryDir := filepath.Dir(path)
				inPath := false

				for _, dir := range strings.Split(pathEnv, ":") {
					if dir == binaryDir {
						inPath = true
						break
					}
				}

				if !inPath {
					findings = append(findings, fmt.Sprintf("  ✗ NOT IN PATH (directory %s not in PATH)", binaryDir))
					findings = append(findings, "  This is why 'temporal' command is not found!")
					findings = append(findings, "")
					findings = append(findings, "  Quick Fix (works immediately): Create symlink")
					findings = append(findings, fmt.Sprintf("    sudo ln -s %s /usr/local/bin/temporal", path))
					findings = append(findings, "")
					findings = append(findings, "  Permanent Fix (survives reboots): Add to PATH")

					// Detect shell and provide appropriate config file
					shell := os.Getenv("SHELL")
					configFile := "~/.bashrc"
					if strings.Contains(shell, "zsh") {
						configFile = "~/.zshrc"
					}

					findings = append(findings, fmt.Sprintf("    echo 'export PATH=\"%s:$PATH\"' >> %s", binaryDir, configFile))
					findings = append(findings, fmt.Sprintf("    source %s", configFile))
					findings = append(findings, "")
					findings = append(findings, "  Alternative: Move binary to system location")
					findings = append(findings, fmt.Sprintf("    sudo mv %s /usr/local/bin/temporal", path))
				} else {
					findings = append(findings, "  ✓ Binary is in PATH and executable")
				}
			}

			logger.Debug("Found temporal binary", zap.String("path", path), zap.Uint32("mode", uint32(info.Mode())))
		}
	}

	// Search /tmp and /var/tmp for downloaded but not installed binaries
	tmpDirs := []string{"/tmp", "/var/tmp"}
	for _, tmpDir := range tmpDirs {
		findCmd := exec.CommandContext(rc.Ctx, "find", tmpDir, "-name", "*temporal*", "-type", "f", "-maxdepth", "2")
		if output, err := findCmd.Output(); err == nil && len(output) > 0 {
			tmpFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
			if len(tmpFiles) > 0 && tmpFiles[0] != "" {
				findings = append(findings, fmt.Sprintf("Temporary files found in %s:", tmpDir))
				for _, file := range tmpFiles {
					if file != "" {
						findings = append(findings, fmt.Sprintf("  %s", file))
					}
				}
				findings = append(findings, "  These may be incomplete downloads or extracted archives")
			}
		}
	}

	// Check system-wide search (only if nothing found yet and running as root)
	if len(findings) == 0 && os.Geteuid() == 0 {
		logger.Debug("Running limited system-wide search for temporal binary")
		// Search specific locations with timeout to avoid hanging
		ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
		defer cancel()

		// Search specific directories likely to contain binaries
		searchDirs := []string{"/usr", "/opt", "/root"}
		for _, searchDir := range searchDirs {
			findCmd := exec.CommandContext(ctx, "find", searchDir,
				"-maxdepth", "4", // Limit depth FIRST
				"-name", "temporal",
				"-type", "f",
				"-not", "-path", "*/.*",
				"-not", "-path", "*/go/pkg/*")

			if output, err := findCmd.Output(); err == nil && len(output) > 0 {
				systemFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
				if len(systemFiles) > 0 && systemFiles[0] != "" {
					findings = append(findings, fmt.Sprintf("System-wide search found in %s:", searchDir))
					for _, file := range systemFiles {
						if file != "" && !strings.Contains(file, "/go/pkg/") {
							findings = append(findings, fmt.Sprintf("  %s", file))
						}
					}
				}
			}
			if ctx.Err() != nil {
				logger.Debug("System search timed out", zap.String("dir", searchDir))
				break
			}
		}
	}

	// Check PATH environment variable
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		findings = append(findings, fmt.Sprintf("Current PATH: %s", pathEnv))
	}

	// Check EOS installation logs for Temporal installation attempts
	logPath := "/var/log/eos/eos.log"
	if _, err := os.Stat(logPath); err == nil {
		// Use simpler approach: grep then take last N lines
		grepCmd := exec.CommandContext(rc.Ctx, "sh", "-c",
			fmt.Sprintf("grep -i temporal %s 2>/dev/null | tail -10 || true", logPath))

		if output, err := grepCmd.Output(); err == nil && len(output) > 0 {
			logLines := strings.Split(strings.TrimSpace(string(output)), "\n")
			if len(logLines) > 0 && logLines[0] != "" {
				findings = append(findings, "", "Recent Temporal-related log entries:")
				for _, line := range logLines {
					if line != "" {
						// Truncate very long lines
						if len(line) > 120 {
							line = line[:117] + "..."
						}
						findings = append(findings, fmt.Sprintf("  %s", line))
					}
				}
			}
		}
	}

	if len(findings) == 0 {
		return ""
	}

	return strings.Join(findings, "\n  ")
}

func checkRecentWorkflows(rc *eos_io.RuntimeContext, config *MetisConfig) error {
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

func checkGoDependenciesWithResult(rc *eos_io.RuntimeContext, projectDir string) checkResult {
	err := checkGoDependencies(rc, projectDir)
	result := checkResult{
		name:     "Go Dependencies",
		category: "Dependencies",
		passed:   err == nil,
		error:    err,
	}

	if err != nil {
		result.remediation = []string{
			"Fix worker dependencies: cd /opt/metis/worker && go mod tidy",
			"Fix webhook dependencies: cd /opt/metis/webhook && go mod tidy",
			"Download modules: go mod download",
			"Verify Go installation: go version",
			"Check module cache: go clean -modcache",
			"If behind proxy, set GOPROXY environment variable",
		}
	} else {
		result.details = "Worker and webhook dependencies verified"
	}

	return result
}

func checkGoDependencies(rc *eos_io.RuntimeContext, projectDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check worker dependencies
	workerDir := filepath.Join(projectDir, "worker")
	if _, err := os.Stat(filepath.Join(workerDir, "go.mod")); os.IsNotExist(err) {
		return fmt.Errorf("worker/go.mod not found")
	}

	workerVerify := exec.CommandContext(rc.Ctx, "go", "mod", "verify")
	workerVerify.Dir = workerDir
	if output, err := workerVerify.CombinedOutput(); err != nil {
		logger.Debug("Worker go mod verify failed", zap.String("output", string(output)))
		return fmt.Errorf("worker dependencies invalid: %s", string(output))
	}

	// Check webhook dependencies
	webhookDir := filepath.Join(projectDir, "webhook")
	if _, err := os.Stat(filepath.Join(webhookDir, "go.mod")); os.IsNotExist(err) {
		return fmt.Errorf("webhook/go.mod not found")
	}

	webhookVerify := exec.CommandContext(rc.Ctx, "go", "mod", "verify")
	webhookVerify.Dir = webhookDir
	if output, err := webhookVerify.CombinedOutput(); err != nil {
		logger.Debug("Webhook go mod verify failed", zap.String("output", string(output)))
		return fmt.Errorf("webhook dependencies invalid: %s", string(output))
	}

	return nil
}

func sendTestAlert(rc *eos_io.RuntimeContext, config *MetisConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	testAlert := map[string]interface{}{
		"agent": map[string]string{
			"name": "test-server",
			"id":   "001",
		},
		"data": map[string]interface{}{
			"vulnerability": map[string]interface{}{
				"severity": "High",
				"package": map[string]string{
					"name": "test-package",
				},
				"title": "TEST: Metis diagnostic test alert",
			},
		},
	}

	alertJSON, err := json.Marshal(testAlert)
	if err != nil {
		return fmt.Errorf("failed to marshal test alert: %w", err)
	}

	webhookURL := fmt.Sprintf("http://localhost:%d/webhook", config.Webhook.Port)
	logger.Info("Sending test alert", zap.String("url", webhookURL))

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, strings.NewReader(string(alertJSON)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send test alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	logger.Info("Test alert sent successfully - check Temporal UI and email")
	return nil
}

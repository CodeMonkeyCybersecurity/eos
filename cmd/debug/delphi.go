// cmd/debug/delphi.go
package debug

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var delphiCmd = &cobra.Command{
	Use:   "delphi",
	Short: "Diagnose Delphi (Iris/Temporal) integration issues",
	Long: `Comprehensive diagnostic tool for Wazuh → Iris webhook integration.

Diagnostic checks performed with --webhook-out:

Network Connectivity (4 checks):
  • Ping Iris machine
  • TCP connection to webhook port
  • Network latency measurement
  • Firewall rule analysis

Iris Service Health (4 checks):
  • HTTP health endpoint verification
  • Temporal connection status
  • Systemd service status
  • Port listening status

Wazuh Integration Configuration (7 checks):
  • Integration .env file existence
  • HOOK_URL correctness
  • Script permissions
  • ossec.conf integration settings
  • Alert level threshold
  • Wazuh Manager service status
  • No hardcoded credentials

Python Dependencies (2 checks):
  • requests module availability
  • python-dotenv module availability

Test Webhook (3 checks):
  • Test alert payload creation
  • Integration script execution
  • Response validation

Log Analysis (2 checks):
  • Integration logs review
  • Sent payload logs review

Remote Checks (optional with --ssh-key):
  • Iris service status on remote machine
  • Port status verification
  • Temporal service logs

Flags:
  --webhook-out      Check outbound webhook from Wazuh to Iris
  --iris-ip         Iris machine IP address (default: 192.168.122.133)
  --iris-port       Iris webhook port (default: 9101)
  --ssh-key          SSH private key for remote checks (optional)
  --verbose          Show detailed output
  --auto-start       Automatically start Temporal server if not running (local only)
  --temporal-ip      IP address for Temporal server to bind to (default: 0.0.0.0)
  --temporal-port    Port for Temporal server to listen on (default: 7233)
  --temporal-db      Path to Temporal database file (default: /tmp/temporal.db)

Example:
  eos debug delphi --webhook-out
  eos debug delphi --webhook-out --iris-ip 192.168.122.133 --iris-port 9101
  eos debug delphi --webhook-out --ssh-key ~/.ssh/id_rsa --verbose
  eos debug delphi --webhook-out --auto-start --temporal-ip 0.0.0.0 --temporal-db /tmp/temporal.db`,
	RunE: eos.Wrap(runDelphi),
}

var (
	delphiWebhookOut   bool
	delphiIrisIP       string
	delphiIrisPort     int
	delphiSSHKey       string
	delphiVerbose      bool
	delphiAutoStart    bool
	delphiTemporalDB   string
	delphiTemporalIP   string
	delphiTemporalPort int
)

func init() {
	delphiCmd.Flags().BoolVar(&delphiWebhookOut, "webhook-out", false, "Check outbound webhook from Wazuh to Iris")
	delphiCmd.Flags().StringVar(&delphiIrisIP, "iris-ip", "192.168.122.133", "Iris machine IP address")
	delphiCmd.Flags().IntVar(&delphiIrisPort, "iris-port", 9101, "Iris webhook port")
	delphiCmd.Flags().StringVar(&delphiSSHKey, "ssh-key", "", "SSH private key for remote checks")
	delphiCmd.Flags().BoolVar(&delphiVerbose, "verbose", false, "Show detailed output")
	delphiCmd.Flags().BoolVar(&delphiAutoStart, "auto-start", false, "Automatically start Temporal server if not running")
	delphiCmd.Flags().StringVar(&delphiTemporalDB, "temporal-db", "/tmp/temporal.db", "Path to Temporal database file")
	delphiCmd.Flags().StringVar(&delphiTemporalIP, "temporal-ip", "0.0.0.0", "IP address for Temporal server to bind to")
	delphiCmd.Flags().IntVar(&delphiTemporalPort, "temporal-port", 7233, "Port for Temporal server to listen on")
	debugCmd.AddCommand(delphiCmd)
}

type delphiCheckResult struct {
	name        string
	category    string
	passed      bool
	warning     bool // true for non-critical warnings
	error       error
	remediation []string
	details     string
}

func runDelphi(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !delphiWebhookOut {
		logger.Error("No diagnostic mode specified")
		return fmt.Errorf("no diagnostic mode specified, use --webhook-out")
	}

	logger.Info("Starting Delphi webhook diagnostics",
		zap.String("iris_ip", delphiIrisIP),
		zap.Int("iris_port", delphiIrisPort),
		zap.Bool("delphiVerbose", delphiVerbose))

	results := runWebhookOutDiagnostics(rc)
	displayDelphiResults(results)

	// Return nil for informational diagnostics
	return nil
}

func runWebhookOutDiagnostics(rc *eos_io.RuntimeContext) []delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Running webhook-out diagnostics")

	var results []delphiCheckResult

	// 1. Network Connectivity
	results = append(results, checkNetworkConnectivity(rc)...)

	// 2. Iris Service Health
	results = append(results, checkIrisServiceHealth(rc)...)

	// 3. Wazuh Integration Configuration
	results = append(results, checkWazuhIntegrationConfig(rc)...)

	// 4. Python Dependencies
	results = append(results, checkPythonDependencies(rc)...)

	// 5. Test Webhook
	results = append(results, sendTestWebhook(rc)...)

	// 6. Log Analysis
	results = append(results, analyzeLogs(rc)...)

	// 7. Remote Iris Checks (if SSH key provided)
	if delphiSSHKey != "" {
		results = append(results, checkRemoteIris(rc)...)
	}

	return results
}

// Network Connectivity Checks
func checkNetworkConnectivity(rc *eos_io.RuntimeContext) []delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking network connectivity", zap.String("target", delphiIrisIP))

	var results []delphiCheckResult

	// Ping check
	pingResult := checkPing(rc)
	results = append(results, pingResult)

	// TCP connection check
	tcpResult := checkTCPConnection(rc)
	results = append(results, tcpResult)

	// Network latency
	latencyResult := checkNetworkLatency(rc)
	results = append(results, latencyResult)

	// Firewall rules
	firewallResult := checkFirewallRules(rc)
	results = append(results, firewallResult)

	return results
}

func checkPing(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "3", "-W", "1", delphiIrisIP)
	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Ping failed", zap.Error(err), zap.String("output", string(output)))
		return delphiCheckResult{
			name:     "Ping Connectivity",
			category: "Network",
			passed:   false,
			error:    fmt.Errorf("cannot ping %s: %w", delphiIrisIP, err),
			remediation: []string{
				fmt.Sprintf("Verify Iris machine (%s) is powered on and accessible", delphiIrisIP),
				"Check network connectivity: ip route get " + delphiIrisIP,
				"Verify IP address is correct",
				"Check if ICMP is blocked by firewall",
			},
			details: string(output),
		}
	}

	logger.Debug("Ping successful", zap.String("output", string(output)))
	return delphiCheckResult{
		name:     "Ping Connectivity",
		category: "Network",
		passed:   true,
		details:  fmt.Sprintf("Successfully pinged %s", delphiIrisIP),
	}
}

func checkTCPConnection(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	target := net.JoinHostPort(delphiIrisIP, fmt.Sprint(delphiIrisPort))
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)

	if err != nil {
		logger.Error("TCP connection failed", zap.Error(err), zap.String("target", target))
		return delphiCheckResult{
			name:     "TCP Port Connectivity",
			category: "Network",
			passed:   false,
			error:    fmt.Errorf("port %d not accessible: %w", delphiIrisPort, err),
			remediation: []string{
				fmt.Sprintf("Verify Iris webhook service is running on %s", delphiIrisIP),
				"Check if service is listening: sudo ss -tulpn | grep " + fmt.Sprint(delphiIrisPort),
				"Check firewall rules on both machines",
				"Verify port number is correct in configuration",
			},
		}
	}
	_ = conn.Close()

	logger.Debug("TCP connection successful", zap.String("target", target))
	return delphiCheckResult{
		name:     "TCP Port Connectivity",
		category: "Network",
		passed:   true,
		details:  fmt.Sprintf("Port %d is open and accepting connections", delphiIrisPort),
	}
}

func checkNetworkLatency(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Measure latency with multiple TCP connections
	var latencies []time.Duration
	target := net.JoinHostPort(delphiIrisIP, fmt.Sprint(delphiIrisPort))

	for i := 0; i < 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		latency := time.Since(start)

		if err != nil {
			logger.Warn("Latency check connection failed", zap.Int("attempt", i+1), zap.Error(err))
			continue
		}
		_ = conn.Close()
		latencies = append(latencies, latency)
	}

	if len(latencies) == 0 {
		return delphiCheckResult{
			name:     "Network Latency",
			category: "Network",
			passed:   false,
			error:    fmt.Errorf("could not measure latency"),
			remediation: []string{
				"Network appears unstable or port is not consistently accessible",
				"Check network congestion",
				"Verify Iris service is stable",
			},
		}
	}

	// Calculate average latency
	var total time.Duration
	for _, l := range latencies {
		total += l
	}
	avgLatency := total / time.Duration(len(latencies))

	logger.Debug("Network latency measured",
		zap.Duration("avg_latency", avgLatency),
		zap.Int("samples", len(latencies)))

	// Warn if latency is high
	warning := avgLatency > 100*time.Millisecond
	details := fmt.Sprintf("Average latency: %v (%d samples)", avgLatency, len(latencies))

	return delphiCheckResult{
		name:     "Network Latency",
		category: "Network",
		passed:   !warning,
		warning:  warning,
		error:    nil,
		details:  details,
		remediation: func() []string {
			if warning {
				return []string{
					fmt.Sprintf("Network latency is high (%v)", avgLatency),
					"Check network congestion",
					"Verify no routing issues",
				}
			}
			return nil
		}(),
	}
}

func checkFirewallRules(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// Check iptables/ufw for blocking rules
	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	var details []string

	// Check ufw status
	ufwCmd := exec.CommandContext(ctx, "sudo", "ufw", "status")
	ufwOutput, err := ufwCmd.CombinedOutput()
	if err == nil && strings.Contains(string(ufwOutput), "Status: active") {
		details = append(details, "UFW firewall is active")
		// Check for specific rule
		if !strings.Contains(string(ufwOutput), fmt.Sprint(delphiIrisPort)) {
			details = append(details, fmt.Sprintf("No explicit UFW rule for port %d", delphiIrisPort))
		}
	}

	// Check iptables
	iptablesCmd := exec.CommandContext(ctx, "sudo", "iptables", "-L", "-n")
	iptablesOutput, err := iptablesCmd.CombinedOutput()
	if err == nil {
		// Look for DROP or REJECT rules
		lines := strings.Split(string(iptablesOutput), "\n")
		for _, line := range lines {
			if (strings.Contains(line, "DROP") || strings.Contains(line, "REJECT")) &&
				strings.Contains(line, delphiIrisIP) {
				details = append(details, "Found potential blocking iptables rule: "+line)
			}
		}
	}

	logger.Debug("Firewall check completed", zap.Strings("details", details))

	if len(details) == 0 {
		return delphiCheckResult{
			name:     "Firewall Rules",
			category: "Network",
			passed:   true,
			warning:  true,
			details:  "No obvious firewall blocking rules detected (limited check)",
		}
	}

	return delphiCheckResult{
		name:     "Firewall Rules",
		category: "Network",
		passed:   true,
		warning:  true,
		details:  strings.Join(details, "\n  "),
		remediation: []string{
			"Review firewall rules manually if experiencing connectivity issues",
			"Check UFW: sudo ufw status delphiVerbose",
			"Check iptables: sudo iptables -L -n -v",
		},
	}
}

// Iris Service Health Checks
func checkIrisServiceHealth(rc *eos_io.RuntimeContext) []delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Iris service health")

	var results []delphiCheckResult

	// Check if we're running on the Iris machine itself
	isLocalIris := delphiIrisIP == "localhost" || delphiIrisIP == "127.0.0.1" || delphiIrisIP == "0.0.0.0"

	// If local and auto-start enabled, check and start Temporal server
	if isLocalIris && delphiAutoStart {
		temporalResult := checkAndStartTemporalServer(rc)
		results = append(results, temporalResult)
	}

	// HTTP health endpoint
	healthResult := checkIrisHealthEndpoint(rc)
	results = append(results, healthResult)

	// Port listening status (from this machine's perspective)
	portResult := checkIrisPortListening(rc)
	results = append(results, portResult)

	return results
}

// checkAndStartTemporalServer implements Assess → Intervene → Evaluate pattern
func checkAndStartTemporalServer(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if Temporal server is already running
	logger.Info("Assessing Temporal server status",
		zap.Int("port", delphiTemporalPort))

	target := fmt.Sprintf("localhost:%d", delphiTemporalPort)
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)

	if err == nil {
		// Server is already running
		_ = conn.Close()
		logger.Info("Temporal server already running", zap.String("target", target))
		return delphiCheckResult{
			name:     "Temporal Server Auto-Start",
			category: "Iris Service",
			passed:   true,
			details:  fmt.Sprintf("Temporal server already running on port %d", delphiTemporalPort),
		}
	}

	// INTERVENE: Start Temporal server
	logger.Info("Temporal server not running, starting in background",
		zap.String("ip", delphiTemporalIP),
		zap.Int("port", delphiTemporalPort),
		zap.String("db", delphiTemporalDB))

	// Check if temporal CLI is available
	temporalPath, err := exec.LookPath("temporal")
	if err != nil {
		logger.Error("Temporal CLI not found in PATH", zap.Error(err))
		return delphiCheckResult{
			name:     "Temporal Server Auto-Start",
			category: "Iris Service",
			passed:   false,
			error:    fmt.Errorf("temporal CLI not found: %w", err),
			remediation: []string{
				"Install Temporal CLI: curl -sSf https://temporal.download/cli.sh | sh",
				"Or run: eos create iris",
				"Verify installation: temporal --version",
			},
		}
	}

	// Start server in background
	cmd := exec.CommandContext(rc.Ctx, temporalPath, "server", "start-dev",
		"--ip", delphiTemporalIP,
		"--port", fmt.Sprint(delphiTemporalPort),
		"--db-filename", delphiTemporalDB)

	// Redirect output to log file
	logFile := "/tmp/temporal-server.log"
	logF, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		logger.Warn("Could not open log file for Temporal server", zap.Error(err))
	} else {
		cmd.Stdout = logF
		cmd.Stderr = logF
		defer func() { _ = logF.Close() }()
	}

	// Start the server
	if err := cmd.Start(); err != nil {
		logger.Error("Failed to start Temporal server", zap.Error(err))
		return delphiCheckResult{
			name:     "Temporal Server Auto-Start",
			category: "Iris Service",
			passed:   false,
			error:    fmt.Errorf("failed to start temporal server: %w", err),
			remediation: []string{
				"Check temporal CLI: temporal --version",
				"Try starting manually: temporal server start-dev --ip " + delphiTemporalIP + " --db-filename " + delphiTemporalDB,
				"Check logs: tail -f " + logFile,
			},
		}
	}

	logger.Info("Temporal server started in background",
		zap.Int("pid", cmd.Process.Pid),
		zap.String("log_file", logFile))

	// EVALUATE: Wait for server to start and verify it's listening
	logger.Info("Waiting for Temporal server to start listening")

	maxAttempts := 10
	waitInterval := 1 * time.Second

	for i := 0; i < maxAttempts; i++ {
		time.Sleep(waitInterval)

		testConn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err == nil {
			_ = testConn.Close()
			logger.Info("Temporal server is now listening",
				zap.String("target", target),
				zap.Int("attempt", i+1))

			return delphiCheckResult{
				name:     "Temporal Server Auto-Start",
				category: "Iris Service",
				passed:   true,
				details: fmt.Sprintf("Temporal server started successfully on %s:%d\n"+
					"  PID: %d\n"+
					"  Database: %s\n"+
					"  Logs: %s\n"+
					"  UI: http://localhost:8233",
					delphiTemporalIP, delphiTemporalPort, cmd.Process.Pid, delphiTemporalDB, logFile),
			}
		}

		logger.Debug("Temporal server not yet ready",
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxAttempts))
	}

	// Server started but not listening after timeout
	logger.Error("Temporal server started but not responding",
		zap.Int("pid", cmd.Process.Pid),
		zap.Duration("timeout", time.Duration(maxAttempts)*waitInterval))

	return delphiCheckResult{
		name:     "Temporal Server Auto-Start",
		category: "Iris Service",
		passed:   false,
		warning:  true,
		error:    fmt.Errorf("server started (PID %d) but not listening after %d seconds", cmd.Process.Pid, maxAttempts),
		details: fmt.Sprintf("Server may still be starting up. Check logs: tail -f %s\n"+
			"Process running: ps aux | grep %d", logFile, cmd.Process.Pid),
		remediation: []string{
			"Wait a bit longer and check: netstat -tlnp | grep " + fmt.Sprint(delphiTemporalPort),
			"Check server logs: tail -f " + logFile,
			"Verify process is running: ps aux | grep temporal",
			"Kill and retry: pkill -f 'temporal server' && eos debug delphi --webhook-out --auto-start",
		},
	}
}

func checkIrisHealthEndpoint(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	healthURL := fmt.Sprintf("http://%s:%d/health", delphiIrisIP, delphiIrisPort)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return delphiCheckResult{
			name:     "Iris Health Endpoint",
			category: "Iris Service",
			passed:   false,
			error:    fmt.Errorf("failed to create request: %w", err),
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Health endpoint check failed", zap.Error(err), zap.String("url", healthURL))
		return delphiCheckResult{
			name:     "Iris Health Endpoint",
			category: "Iris Service",
			passed:   false,
			error:    fmt.Errorf("health endpoint not responding: %w", err),
			remediation: []string{
				fmt.Sprintf("Verify Iris webhook service is running on %s", delphiIrisIP),
				"Check service status: sudo systemctl status iris-webhook",
				"Start service if stopped: sudo systemctl start iris-webhook",
				"Check service logs: sudo journalctl -u iris-webhook -n 50",
			},
		}
	}
	defer func() { _ = resp.Body.Close() }()

	// Try to parse response
	var healthResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err == nil {
		logger.Debug("Health endpoint response", zap.Any("response", healthResp))

		status, _ := healthResp["status"].(string)
		temporalConnected, _ := healthResp["temporal_connected"].(bool)

		details := fmt.Sprintf("Status: %s, Temporal connected: %v", status, temporalConnected)

		if status != "healthy" || !temporalConnected {
			return delphiCheckResult{
				name:     "Iris Health Endpoint",
				category: "Iris Service",
				passed:   false,
				error:    fmt.Errorf("service unhealthy or Temporal not connected"),
				details:  details,
				remediation: []string{
					"Check Temporal service: sudo systemctl status temporal",
					"Verify Temporal is accessible from Iris machine",
					"Review Iris configuration: cat /opt/iris/config.yaml",
				},
			}
		}

		return delphiCheckResult{
			name:     "Iris Health Endpoint",
			category: "Iris Service",
			passed:   true,
			details:  details,
		}
	}

	// Response code check if parsing failed
	if resp.StatusCode != http.StatusOK {
		return delphiCheckResult{
			name:     "Iris Health Endpoint",
			category: "Iris Service",
			passed:   false,
			error:    fmt.Errorf("health check returned HTTP %d", resp.StatusCode),
			remediation: []string{
				"Service is running but returned non-200 status",
				"Check service logs for errors",
			},
		}
	}

	return delphiCheckResult{
		name:     "Iris Health Endpoint",
		category: "Iris Service",
		passed:   true,
		details:  fmt.Sprintf("HTTP %d (response parsing failed, but service responding)", resp.StatusCode),
	}
}

func checkIrisPortListening(_ *eos_io.RuntimeContext) delphiCheckResult {
	// This is similar to TCP connectivity check but provides different context
	target := net.JoinHostPort(delphiIrisIP, fmt.Sprint(delphiIrisPort))
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)

	if err != nil {
		return delphiCheckResult{
			name:     "Port Listening Status",
			category: "Iris Service",
			passed:   false,
			error:    fmt.Errorf("port %d not listening", delphiIrisPort),
			remediation: []string{
				"Start Iris webhook service: sudo systemctl start iris-webhook",
				"Check what's using the port: sudo ss -tulpn | grep " + fmt.Sprint(delphiIrisPort),
			},
		}
	}
	_ = conn.Close()

	return delphiCheckResult{
		name:     "Port Listening Status",
		category: "Iris Service",
		passed:   true,
		details:  fmt.Sprintf("Port %d is listening", delphiIrisPort),
	}
}

// Wazuh Integration Configuration Checks
func checkWazuhIntegrationConfig(rc *eos_io.RuntimeContext) []delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Wazuh integration configuration")

	var results []delphiCheckResult

	// .env file check
	envResult := checkIntegrationEnvFile(rc)
	results = append(results, envResult)

	// Script permissions
	scriptResult := checkIntegrationScripts(rc)
	results = append(results, scriptResult)

	// ossec.conf integration settings
	ossecResult := checkOssecIntegrationConfig(rc)
	results = append(results, ossecResult)

	// Wazuh Manager service
	managerResult := checkWazuhManagerService(rc)
	results = append(results, managerResult)

	return results
}

func checkIntegrationEnvFile(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	envPath := "/var/ossec/integrations/.env"

	// Check existence
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		logger.Error(".env file not found", zap.String("path", envPath))
		return delphiCheckResult{
			name:     "Integration .env File",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf(".env file not found at %s", envPath),
			remediation: []string{
				"Create .env file: sudo nano " + envPath,
				"Add required variables:",
				fmt.Sprintf("  HOOK_URL=http://%s:%d/webhooks/wazuh_alert", delphiIrisIP, delphiIrisPort),
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
		return delphiCheckResult{
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
		return delphiCheckResult{
			name:     "Integration .env File",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("HOOK_URL not found in .env file"),
			remediation: []string{
				"Add HOOK_URL to .env file: sudo nano " + envPath,
				fmt.Sprintf("  HOOK_URL=http://%s:%d/webhooks/wazuh_alert", delphiIrisIP, delphiIrisPort),
			},
		}
	}

	// Validate HOOK_URL points to correct IP
	expectedURL := fmt.Sprintf("http://%s:%d", delphiIrisIP, delphiIrisPort)
	if !strings.Contains(hookURL, expectedURL) {
		logger.Warn("HOOK_URL does not match expected Iris address",
			zap.String("found", hookURL),
			zap.String("expected", expectedURL))
		return delphiCheckResult{
			name:     "Integration .env File",
			category: "Wazuh Configuration",
			passed:   false,
			error:    fmt.Errorf("HOOK_URL points to wrong address: %s", hookURL),
			remediation: []string{
				fmt.Sprintf("Update HOOK_URL in %s to: http://%s:%d/webhooks/wazuh_alert",
					envPath, delphiIrisIP, delphiIrisPort),
			},
			details: fmt.Sprintf("Current: %s\nExpected: %s/webhooks/wazuh_alert", hookURL, expectedURL),
		}
	}

	logger.Debug(".env file validated", zap.String("hook_url", hookURL))
	return delphiCheckResult{
		name:     "Integration .env File",
		category: "Wazuh Configuration",
		passed:   true,
		details:  fmt.Sprintf("HOOK_URL correctly configured: %s", hookURL),
	}
}

func checkIntegrationScripts(rc *eos_io.RuntimeContext) delphiCheckResult {
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
		return delphiCheckResult{
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
		return delphiCheckResult{
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
	return delphiCheckResult{
		name:     "Integration Scripts",
		category: "Wazuh Configuration",
		passed:   true,
		details:  "All integration scripts exist and are executable",
	}
}

func checkOssecIntegrationConfig(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ossecConfPath := "/var/ossec/etc/ossec.conf"

	// Read ossec.conf
	data, err := os.ReadFile(ossecConfPath)
	if err != nil {
		logger.Error("Cannot read ossec.conf", zap.Error(err))
		return delphiCheckResult{
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
		return delphiCheckResult{
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
		return delphiCheckResult{
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
	return delphiCheckResult{
		name:     "Ossec Integration Config",
		category: "Wazuh Configuration",
		passed:   true,
		details:  details,
	}
}

func checkWazuhManagerService(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "wazuh-manager")
	output, err := cmd.Output()

	status := strings.TrimSpace(string(output))

	if err != nil || status != "active" {
		logger.Error("Wazuh Manager not active", zap.String("status", status))
		return delphiCheckResult{
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
	return delphiCheckResult{
		name:     "Wazuh Manager Service",
		category: "Wazuh Configuration",
		passed:   true,
		details:  "Wazuh Manager is running",
	}
}

// Python Dependencies Checks
func checkPythonDependencies(rc *eos_io.RuntimeContext) []delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Python dependencies")

	var results []delphiCheckResult

	pythonPath := "/var/ossec/framework/python/bin/python3"

	// Check requests module
	requestsResult := checkPythonModule(rc, pythonPath, "requests")
	results = append(results, requestsResult)

	// Check dotenv module
	dotenvResult := checkPythonModule(rc, pythonPath, "dotenv")
	results = append(results, dotenvResult)

	return results
}

func checkPythonModule(rc *eos_io.RuntimeContext, pythonPath, module string) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonPath, "-c", fmt.Sprintf("import %s", module))
	err := cmd.Run()

	if err != nil {
		logger.Error("Python module not found", zap.String("module", module), zap.Error(err))
		return delphiCheckResult{
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
	return delphiCheckResult{
		name:     fmt.Sprintf("Python Module: %s", module),
		category: "Python Dependencies",
		passed:   true,
		details:  fmt.Sprintf("Module %s is installed", module),
	}
}

// Test Webhook
func sendTestWebhook(rc *eos_io.RuntimeContext) []delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Sending test webhook")

	var results []delphiCheckResult

	// Create test alert payload
	testAlert := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"rule": map[string]interface{}{
			"level":       10,
			"description": "TEST: Delphi webhook diagnostic",
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
			"message": "Diagnostic test from eos debug delphi --webhook-out",
		},
	}

	alertJSON, err := json.MarshalIndent(testAlert, "", "  ")
	if err != nil {
		results = append(results, delphiCheckResult{
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
		results = append(results, delphiCheckResult{
			name:     "Test Alert Creation",
			category: "Test Webhook",
			passed:   false,
			error:    fmt.Errorf("failed to write test alert: %w", err),
		})
		return results
	}

	logger.Debug("Test alert created", zap.String("path", tmpFile))
	results = append(results, delphiCheckResult{
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
		results = append(results, delphiCheckResult{
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
	results = append(results, delphiCheckResult{
		name:     "Integration Script Execution",
		category: "Test Webhook",
		passed:   true,
		details:  "Script executed successfully (exit 0)",
	})

	// Verify HTTP response
	if strings.Contains(string(output), "200") || strings.Contains(string(output), "HTTP 200") {
		results = append(results, delphiCheckResult{
			name:     "Webhook Response",
			category: "Test Webhook",
			passed:   true,
			details:  "Received HTTP 200 response from Iris",
		})
	} else {
		results = append(results, delphiCheckResult{
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
func analyzeLogs(rc *eos_io.RuntimeContext) []delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Analyzing integration logs")

	var results []delphiCheckResult

	// Integration logs
	intLogResult := analyzeIntegrationLog(rc)
	results = append(results, intLogResult)

	// Sent payload logs
	payloadLogResult := analyzeSentPayloadLog(rc)
	results = append(results, payloadLogResult)

	return results
}

func analyzeIntegrationLog(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	logPath := "/var/ossec/logs/integrations.log"

	// Check if file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return delphiCheckResult{
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
		return delphiCheckResult{
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
			return delphiCheckResult{
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
	return delphiCheckResult{
		name:     "Integration Logs",
		category: "Logs",
		passed:   true,
		details:  details,
	}
}

func analyzeSentPayloadLog(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	logPath := "/var/ossec/logs/sent_payload.log"

	// Check if file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return delphiCheckResult{
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
		return delphiCheckResult{
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
	return delphiCheckResult{
		name:     "Sent Payload Logs",
		category: "Logs",
		passed:   true,
		details:  details,
	}
}

// Remote Iris Checks
func checkRemoteIris(rc *eos_io.RuntimeContext) []delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking remote Iris machine", zap.String("ssh_key", delphiSSHKey))

	var results []delphiCheckResult

	// Test SSH connectivity first
	sshConnResult := testSSHConnection(rc)
	results = append(results, sshConnResult)

	if !sshConnResult.passed {
		// Cannot proceed with remote checks
		return results
	}

	// Check remote port status
	remotePortResult := checkRemotePortStatus(rc)
	results = append(results, remotePortResult)

	// Check remote service status
	remoteServiceResult := checkRemoteServiceStatus(rc)
	results = append(results, remoteServiceResult)

	return results
}

func testSSHConnection(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	// Try SSH with key
	cmd := exec.CommandContext(ctx, "ssh",
		"-i", delphiSSHKey,
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=3",
		fmt.Sprintf("ubuntu@%s", delphiIrisIP),
		"echo", "connected")

	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("SSH connection failed", zap.Error(err), zap.String("output", string(output)))
		return delphiCheckResult{
			name:     "SSH Connectivity",
			category: "Remote Checks",
			passed:   false,
			error:    fmt.Errorf("cannot SSH to %s: %w", delphiIrisIP, err),
			remediation: []string{
				"Verify SSH key is correct: " + delphiSSHKey,
				"Check SSH is enabled on Iris machine",
				"Test manually: ssh -i " + delphiSSHKey + " ubuntu@" + delphiIrisIP,
				"Verify SSH port 22 is open",
			},
			details: string(output),
		}
	}

	logger.Debug("SSH connection successful")
	return delphiCheckResult{
		name:     "SSH Connectivity",
		category: "Remote Checks",
		passed:   true,
		details:  fmt.Sprintf("Successfully connected to ubuntu@%s", delphiIrisIP),
	}
}

func checkRemotePortStatus(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh",
		"-i", delphiSSHKey,
		"-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("ubuntu@%s", delphiIrisIP),
		"sudo", "ss", "-tulpn", "|", "grep", fmt.Sprint(delphiIrisPort))

	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Remote port check failed", zap.Error(err))
		return delphiCheckResult{
			name:     "Remote Port Status",
			category: "Remote Checks",
			passed:   false,
			error:    fmt.Errorf("port %d not listening on Iris", delphiIrisPort),
			remediation: []string{
				"Start webhook service on Iris: sudo systemctl start iris-webhook",
				"Check what's using the port: sudo ss -tulpn | grep " + fmt.Sprint(delphiIrisPort),
			},
			details: string(output),
		}
	}

	logger.Debug("Remote port check successful", zap.String("output", string(output)))
	return delphiCheckResult{
		name:     "Remote Port Status",
		category: "Remote Checks",
		passed:   true,
		details:  fmt.Sprintf("Port %d is listening on Iris:\n  %s", delphiIrisPort, string(output)),
	}
}

func checkRemoteServiceStatus(rc *eos_io.RuntimeContext) delphiCheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh",
		"-i", delphiSSHKey,
		"-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("ubuntu@%s", delphiIrisIP),
		"systemctl", "status", "iris-webhook", "iris-worker", "--no-pager")

	output, err := cmd.CombinedOutput()

	// systemctl status returns non-zero if any service is not active
	// We still want to show the output
	details := string(output)

	if err != nil {
		logger.Warn("Remote service check shows issues", zap.String("output", details))
		return delphiCheckResult{
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
	return delphiCheckResult{
		name:     "Remote Service Status",
		category: "Remote Checks",
		passed:   true,
		details:  "All Iris services are active",
	}
}

// Display Results
func displayDelphiResults(results []delphiCheckResult) {
	// Count by status
	passed := 0
	failed := 0
	warnings := 0

	categoryMap := make(map[string][]delphiCheckResult)
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
	fmt.Println("║           DELPHI WEBHOOK DIAGNOSTIC REPORT                     ║")
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

			// Show details for delphiVerbose or failed/warning checks
			if (delphiVerbose || !check.passed || check.warning) && check.details != "" {
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
		fmt.Printf("  • Check Temporal UI: http://%s:8233\n", delphiIrisIP)
	} else {
		fmt.Println("Issues detected - follow remediation steps above")
		fmt.Println()
		fmt.Println("After fixing issues:")
		fmt.Println("  1. Run this diagnostic again: eos debug delphi --webhook-out")
		fmt.Println("  2. Monitor integration logs: sudo tail -f /var/ossec/logs/integrations.log")
		fmt.Printf("  3. Check Temporal UI: http://%s:8233\n", delphiIrisIP)
	}
	fmt.Println()
}

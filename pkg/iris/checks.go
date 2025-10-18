package iris

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckResult represents a diagnostic check result
type CheckResult struct {
	Name        string
	Category    string
	Passed      bool
	Warning     bool
	Error       error
	Remediation []string
	Details     string
}

// IrisConfig holds configuration for Iris checks
type IrisConfig struct {
	IrisIP       string
	IrisPort     int
	SSHKey       string
	TemporalIP   string
	TemporalPort int
	TemporalDB   string
	AutoStart    bool
}

// CheckRemoteIris performs remote checks on Iris machine
func CheckRemoteIris(rc *eos_io.RuntimeContext, config IrisConfig) []CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking remote Iris machine", zap.String("ssh_key", config.SSHKey))

	var results []CheckResult

	// Test SSH connectivity first
	sshConnResult := TestSSHConnection(rc, config)
	results = append(results, sshConnResult)

	if !sshConnResult.Passed {
		// Cannot proceed with remote checks
		return results
	}

	// Check remote port status
	remotePortResult := CheckRemotePortStatus(rc, config)
	results = append(results, remotePortResult)

	// Check remote service status
	remoteServiceResult := CheckRemoteServiceStatus(rc, config)
	results = append(results, remoteServiceResult)

	return results
}

// CheckIrisServiceHealth checks Iris service health
func CheckIrisServiceHealth(rc *eos_io.RuntimeContext, config IrisConfig) []CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Iris service health")

	var results []CheckResult

	// Check if we're running on the Iris machine itself
	isLocalIris := config.IrisIP == "localhost" || config.IrisIP == "127.0.0.1" || config.IrisIP == "0.0.0.0"

	// If local and auto-start enabled, check and start Temporal server
	if isLocalIris && config.AutoStart {
		temporalResult := CheckAndStartTemporalServer(rc, config)
		results = append(results, temporalResult)
	}

	// HTTP health endpoint
	healthResult := CheckIrisHealthEndpoint(rc, config)
	results = append(results, healthResult)

	// Port listening status (from this machine's perspective)
	portResult := CheckIrisPortListening(rc, config)
	results = append(results, portResult)

	return results
}

// CheckAndStartTemporalServer implements Assess → Intervene → Evaluate pattern
func CheckAndStartTemporalServer(rc *eos_io.RuntimeContext, config IrisConfig) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if Temporal server is already running
	logger.Info("Assessing Temporal server status",
		zap.Int("port", config.TemporalPort))

	target := fmt.Sprintf("localhost:%d", config.TemporalPort)
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)

	if err == nil {
		// Server is already running
		_ = conn.Close()
		logger.Info("Temporal server already running", zap.String("target", target))
		return CheckResult{
			Name:     "Temporal Server Auto-Start",
			Category: "Iris Service",
			Passed:   true,
			Details:  fmt.Sprintf("Temporal server already running on port %d", config.TemporalPort),
		}
	}

	// INTERVENE: Start Temporal server
	logger.Info("Temporal server not running, starting in background",
		zap.String("ip", config.TemporalIP),
		zap.Int("port", config.TemporalPort),
		zap.String("db", config.TemporalDB))

	// Check if temporal CLI is available
	temporalPath, err := exec.LookPath("temporal")
	if err != nil {
		logger.Error("Temporal CLI not found in PATH", zap.Error(err))
		return CheckResult{
			Name:     "Temporal Server Auto-Start",
			Category: "Iris Service",
			Passed:   false,
			Error:    fmt.Errorf("temporal CLI not found: %w", err),
			Remediation: []string{
				"Install Temporal CLI: curl -sSf https://temporal.download/cli.sh | sh",
				"Or run: eos create iris",
				"Verify installation: temporal --version",
			},
		}
	}

	// Start server in background
	cmd := exec.CommandContext(rc.Ctx, temporalPath, "server", "start-dev",
		"--ip", config.TemporalIP,
		"--port", fmt.Sprint(config.TemporalPort),
		"--db-filename", config.TemporalDB)

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
		return CheckResult{
			Name:     "Temporal Server Auto-Start",
			Category: "Iris Service",
			Passed:   false,
			Error:    fmt.Errorf("failed to start temporal server: %w", err),
			Remediation: []string{
				"Check temporal CLI: temporal --version",
				"Try starting manually: temporal server start-dev --ip " + config.TemporalIP + " --db-filename " + config.TemporalDB,
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

			return CheckResult{
				Name:     "Temporal Server Auto-Start",
				Category: "Iris Service",
				Passed:   true,
				Details: fmt.Sprintf("Temporal server started successfully on %s:%d\n"+
					"  PID: %d\n"+
					"  Database: %s\n"+
					"  Logs: %s\n"+
					"  UI: http://localhost:8233",
					config.TemporalIP, config.TemporalPort, cmd.Process.Pid, config.TemporalDB, logFile),
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

	return CheckResult{
		Name:     "Temporal Server Auto-Start",
		Category: "Iris Service",
		Passed:   false,
		Warning:  true,
		Error:    fmt.Errorf("server started (PID %d) but not listening after %d seconds", cmd.Process.Pid, maxAttempts),
		Details: fmt.Sprintf("Server may still be starting up. Check logs: tail -f %s\n"+
			"Process running: ps aux | grep %d", logFile, cmd.Process.Pid),
		Remediation: []string{
			"Wait a bit longer and check: netstat -tlnp | grep " + fmt.Sprint(config.TemporalPort),
			"Check server logs: tail -f " + logFile,
			"Verify process is running: ps aux | grep temporal",
			"Kill and retry: pkill -f 'temporal server' && eos debug wazuh --webhook-out --auto-start",
		},
	}
}

func CheckIrisHealthEndpoint(rc *eos_io.RuntimeContext, config IrisConfig) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	healthURL := fmt.Sprintf("http://%s:%d/health", config.IrisIP, config.IrisPort)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return CheckResult{
			Name:     "Iris Health Endpoint",
			Category: "Iris Service",
			Passed:   false,
			Error:    fmt.Errorf("failed to create request: %w", err),
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Health endpoint check failed", zap.Error(err), zap.String("url", healthURL))
		return CheckResult{
			Name:     "Iris Health Endpoint",
			Category: "Iris Service",
			Passed:   false,
			Error:    fmt.Errorf("health endpoint not responding: %w", err),
			Remediation: []string{
				fmt.Sprintf("Verify Iris webhook service is running on %s", config.IrisIP),
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
			return CheckResult{
				Name:     "Iris Health Endpoint",
				Category: "Iris Service",
				Passed:   false,
				Error:    fmt.Errorf("service unhealthy or Temporal not connected"),
				Details:  details,
				Remediation: []string{
					"Check Temporal service: sudo systemctl status temporal",
					"Verify Temporal is accessible from Iris machine",
					"Review Iris configuration: cat /opt/iris/config.yaml",
				},
			}
		}

		return CheckResult{
			Name:     "Iris Health Endpoint",
			Category: "Iris Service",
			Passed:   true,
			Details:  details,
		}
	}

	// Response code check if parsing failed
	if resp.StatusCode != http.StatusOK {
		return CheckResult{
			Name:     "Iris Health Endpoint",
			Category: "Iris Service",
			Passed:   false,
			Error:    fmt.Errorf("health check returned HTTP %d", resp.StatusCode),
			Remediation: []string{
				"Service is running but returned non-200 status",
				"Check service logs for errors",
			},
		}
	}

	return CheckResult{
		Name:     "Iris Health Endpoint",
		Category: "Iris Service",
		Passed:   true,
		Details:  fmt.Sprintf("HTTP %d (response parsing failed, but service responding)", resp.StatusCode),
	}
}

func CheckIrisPortListening(_ *eos_io.RuntimeContext, config IrisConfig) CheckResult {
	// This is similar to TCP connectivity check but provides different context
	target := net.JoinHostPort(config.IrisIP, fmt.Sprint(config.IrisPort))
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)

	if err != nil {
		return CheckResult{
			Name:     "Port Listening Status",
			Category: "Iris Service",
			Passed:   false,
			Error:    fmt.Errorf("port %d not listening", config.IrisPort),
			Remediation: []string{
				"Start Iris webhook service: sudo systemctl start iris-webhook",
				"Check what's using the port: sudo ss -tulpn | grep " + fmt.Sprint(config.IrisPort),
			},
		}
	}
	_ = conn.Close()

	return CheckResult{
		Name:     "Port Listening Status",
		Category: "Iris Service",
		Passed:   true,
		Details:  fmt.Sprintf("Port %d is listening", config.IrisPort),
	}
}

// TestSSHConnection tests SSH connectivity to remote Iris machine
func TestSSHConnection(rc *eos_io.RuntimeContext, config IrisConfig) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	// Try SSH with key
	cmd := exec.CommandContext(ctx, "ssh",
		"-i", config.SSHKey,
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=3",
		fmt.Sprintf("ubuntu@%s", config.IrisIP),
		"echo", "connected")

	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("SSH connection failed", zap.Error(err), zap.String("output", string(output)))
		return CheckResult{
			Name:     "SSH Connectivity",
			Category: "Remote Checks",
			Passed:   false,
			Error:    fmt.Errorf("cannot SSH to %s: %w", config.IrisIP, err),
			Remediation: []string{
				"Verify SSH key is correct: " + config.SSHKey,
				"Check SSH is enabled on Iris machine",
				"Test manually: ssh -i " + config.SSHKey + " ubuntu@" + config.IrisIP,
				"Verify SSH port 22 is open",
			},
			Details: string(output),
		}
	}

	logger.Debug("SSH connection successful")
	return CheckResult{
		Name:     "SSH Connectivity",
		Category: "Remote Checks",
		Passed:   true,
		Details:  fmt.Sprintf("Successfully connected to ubuntu@%s", config.IrisIP),
	}
}

// CheckRemotePortStatus checks if the Iris port is listening on the remote machine
func CheckRemotePortStatus(rc *eos_io.RuntimeContext, config IrisConfig) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh",
		"-i", config.SSHKey,
		"-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("ubuntu@%s", config.IrisIP),
		"sudo", "ss", "-tulpn", "|", "grep", fmt.Sprint(config.IrisPort))

	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Remote port check failed", zap.Error(err))
		return CheckResult{
			Name:     "Remote Port Status",
			Category: "Remote Checks",
			Passed:   false,
			Error:    fmt.Errorf("port %d not listening on Iris", config.IrisPort),
			Remediation: []string{
				"Start webhook service on Iris: sudo systemctl start iris-webhook",
				"Check what's using the port: sudo ss -tulpn | grep " + fmt.Sprint(config.IrisPort),
			},
			Details: string(output),
		}
	}

	logger.Debug("Remote port check successful", zap.String("output", string(output)))
	return CheckResult{
		Name:     "Remote Port Status",
		Category: "Remote Checks",
		Passed:   true,
		Details:  fmt.Sprintf("Port %d is listening on Iris:\n  %s", config.IrisPort, string(output)),
	}
}

// CheckRemoteServiceStatus checks the status of Iris services on the remote machine
func CheckRemoteServiceStatus(rc *eos_io.RuntimeContext, config IrisConfig) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)

	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh",
		"-i", config.SSHKey,
		"-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("ubuntu@%s", config.IrisIP),
		"systemctl", "status", "iris-webhook", "iris-worker", "--no-pager")

	output, err := cmd.CombinedOutput()

	// systemctl status returns non-zero if any service is not active
	// We still want to show the output
	details := string(output)

	if err != nil {
		logger.Warn("Remote service check shows issues", zap.String("output", details))
		return CheckResult{
			Name:     "Remote Service Status",
			Category: "Remote Checks",
			Passed:   false,
			Warning:  true,
			Error:    fmt.Errorf("one or more Iris services not running properly"),
			Details:  details,
			Remediation: []string{
				"Check individual service status on Iris machine",
				"Start services: sudo systemctl start iris-webhook iris-worker",
				"Check logs: sudo journalctl -u iris-webhook -u iris-worker -n 50",
			},
		}
	}

	logger.Debug("Remote service check successful")
	return CheckResult{
		Name:     "Remote Service Status",
		Category: "Remote Checks",
		Passed:   true,
		Details:  "All Iris services are running:\n" + details,
	}
}

//go:build linux

// pkg/kvm/guest_exec.go
// Execute commands inside VMs via QEMU guest agent

package kvm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

// GuestExecResult represents the result of a guest-exec command
type GuestExecResult struct {
	PID      int           `json:"pid"`
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	Exited   bool          `json:"exited"`
}

// GuestExecConfig configures guest-exec command execution
type GuestExecConfig struct {
	Command        string        // Command to execute (full path)
	Args           []string      // Command arguments
	Timeout        time.Duration // Overall timeout (default 30min)
	PollInterval   time.Duration // Status polling interval (default 2s)
	CaptureOutput  bool          // Capture stdout/stderr (default true)
	WorkingDir     string        // Working directory (optional)
	Environment    []string      // Environment variables (optional)
}

// DefaultGuestExecConfig returns default configuration
func DefaultGuestExecConfig() *GuestExecConfig {
	return &GuestExecConfig{
		Timeout:       30 * time.Minute,
		PollInterval:  2 * time.Second,
		CaptureOutput: true,
	}
}

// GuestExecCommand executes a command inside a VM via guest-exec
// Follows Assess → Intervene → Evaluate pattern
func GuestExecCommand(rc *eos_io.RuntimeContext, vmName string, cfg *GuestExecConfig) (*GuestExecResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	if cfg == nil {
		cfg = DefaultGuestExecConfig()
	}

	logger.Info("Executing guest command",
		zap.String("vm", vmName),
		zap.String("command", cfg.Command),
		zap.Strings("args", cfg.Args),
		zap.Duration("timeout", cfg.Timeout))

	// ASSESS: Verify prerequisites
	conn, domain, err := assessGuestExec(rc, vmName)
	if err != nil {
		return nil, fmt.Errorf("guest-exec assessment failed: %w", err)
	}
	defer func() { _, _ = conn.Close() }()
	defer domain.Free()

	// INTERVENE: Execute command
	result, err := interveneGuestExec(rc, domain, cfg)
	if err != nil {
		return nil, fmt.Errorf("guest-exec execution failed: %w", err)
	}

	// EVALUATE: Wait for completion and capture output
	if err := evaluateGuestExec(rc, domain, result, cfg); err != nil {
		return nil, fmt.Errorf("guest-exec evaluation failed: %w", err)
	}

	result.Duration = time.Since(startTime)

	logger.Info("Guest command completed",
		zap.String("vm", vmName),
		zap.Int("exit_code", result.ExitCode),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// GuestExecScript executes a multi-line shell script via guest-exec
func GuestExecScript(rc *eos_io.RuntimeContext, vmName string, script string, timeout time.Duration) (*GuestExecResult, error) {
	cfg := DefaultGuestExecConfig()
	cfg.Command = "/bin/bash"
	cfg.Args = []string{"-c", script}
	cfg.Timeout = timeout

	return GuestExecCommand(rc, vmName, cfg)
}

// assessGuestExec verifies VM is ready for guest-exec
func assessGuestExec(rc *eos_io.RuntimeContext, vmName string) (*libvirt.Connect, *libvirt.Domain, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Connect to libvirt
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}

	// Get domain
	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("VM not found: %w", err)
	}

	// Check VM is running
	state, _, err := domain.GetState()
	if err != nil {
		domain.Free()
		conn.Close()
		return nil, nil, fmt.Errorf("failed to get VM state: %w", err)
	}

	if state != libvirt.DOMAIN_RUNNING {
		domain.Free()
		conn.Close()
		return nil, nil, fmt.Errorf("VM is not running (state: %s)", stateToString(state))
	}

	// Check guest agent is responsive
	if !checkGuestAgent(domain) {
		domain.Free()
		conn.Close()
		return nil, nil, fmt.Errorf("guest agent not responsive - ensure qemu-guest-agent is installed and running")
	}

	// Test guest-exec is enabled
	status := testGuestExec(domain)
	if status == "DISABLED" {
		domain.Free()
		conn.Close()
		return nil, nil, fmt.Errorf("guest-exec is disabled - run 'eos update kvm %s --enable-guest-exec' first", vmName)
	}
	if status == "ERROR" {
		logger.Warn("Guest-exec status unclear but proceeding",
			zap.String("vm", vmName))
	}

	logger.Debug("Guest-exec prerequisites verified",
		zap.String("vm", vmName),
		zap.String("guest_exec_status", status))

	return conn, domain, nil
}

// interveneGuestExec submits the command for execution
func interveneGuestExec(rc *eos_io.RuntimeContext, domain *libvirt.Domain, cfg *GuestExecConfig) (*GuestExecResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Build guest-exec command
	guestCmd := map[string]interface{}{
		"execute": "guest-exec",
		"arguments": map[string]interface{}{
			"path":           cfg.Command,
			"arg":            cfg.Args,
			"capture-output": cfg.CaptureOutput,
		},
	}

	// Add optional parameters
	if cfg.WorkingDir != "" {
		guestCmd["arguments"].(map[string]interface{})["cwd"] = cfg.WorkingDir
	}
	if len(cfg.Environment) > 0 {
		guestCmd["arguments"].(map[string]interface{})["env"] = cfg.Environment
	}

	cmdJSON, err := json.Marshal(guestCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal command: %w", err)
	}

	logger.Debug("Submitting guest-exec command",
		zap.String("command_json", string(cmdJSON)))

	// Execute via QEMU agent
	response, err := domain.QemuAgentCommand(
		string(cmdJSON),
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("guest-exec submission failed: %w", err)
	}

	// Parse response to get PID
	var execResponse struct {
		Return struct {
			PID int `json:"pid"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(response), &execResponse); err != nil {
		return nil, fmt.Errorf("failed to parse exec response: %w", err)
	}

	logger.Debug("Guest-exec command submitted",
		zap.Int("pid", execResponse.Return.PID))

	return &GuestExecResult{
		PID:    execResponse.Return.PID,
		Exited: false,
	}, nil
}

// evaluateGuestExec polls for command completion and captures output
func evaluateGuestExec(rc *eos_io.RuntimeContext, domain *libvirt.Domain, result *GuestExecResult, cfg *GuestExecConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	deadline := time.Now().Add(cfg.Timeout)

	logger.Debug("Waiting for guest-exec completion",
		zap.Int("pid", result.PID),
		zap.Duration("timeout", cfg.Timeout))

	// Poll for completion
	pollCount := 0
	for time.Now().Before(deadline) {
		pollCount++

		// Query command status
		statusCmd := fmt.Sprintf(`{"execute":"guest-exec-status","arguments":{"pid":%d}}`, result.PID)
		response, err := domain.QemuAgentCommand(
			statusCmd,
			libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
			0,
		)
		if err != nil {
			return fmt.Errorf("failed to query command status: %w", err)
		}

		// Parse status response
		var statusResponse struct {
			Return struct {
				Exited   bool   `json:"exited"`
				ExitCode int    `json:"exitcode"`
				OutData  string `json:"out-data"` // base64 encoded
				ErrData  string `json:"err-data"` // base64 encoded
			} `json:"return"`
		}

		if err := json.Unmarshal([]byte(response), &statusResponse); err != nil {
			return fmt.Errorf("failed to parse status response: %w", err)
		}

		// Log periodic progress
		if pollCount%30 == 0 { // Every ~60 seconds at 2s intervals
			logger.Debug("Command still running",
				zap.Int("pid", result.PID),
				zap.Int("poll_count", pollCount))
		}

		// Check if command completed
		if statusResponse.Return.Exited {
			result.Exited = true
			result.ExitCode = statusResponse.Return.ExitCode

			// Decode stdout/stderr if captured
			if cfg.CaptureOutput {
				if statusResponse.Return.OutData != "" {
					stdout, err := base64.StdEncoding.DecodeString(statusResponse.Return.OutData)
					if err != nil {
						logger.Warn("Failed to decode stdout", zap.Error(err))
					} else {
						result.Stdout = string(stdout)
					}
				}

				if statusResponse.Return.ErrData != "" {
					stderr, err := base64.StdEncoding.DecodeString(statusResponse.Return.ErrData)
					if err != nil {
						logger.Warn("Failed to decode stderr", zap.Error(err))
					} else {
						result.Stderr = string(stderr)
					}
				}
			}

			logger.Debug("Command completed",
				zap.Int("pid", result.PID),
				zap.Int("exit_code", result.ExitCode),
				zap.Int("stdout_bytes", len(result.Stdout)),
				zap.Int("stderr_bytes", len(result.Stderr)))

			return nil
		}

		// Sleep before next poll
		time.Sleep(cfg.PollInterval)
	}

	// Timeout exceeded
	return fmt.Errorf("command timeout exceeded (%s) - command may still be running (PID: %d)", cfg.Timeout, result.PID)
}

// pkg/unix/systemctl.go

package eos_unix

// TODO: MIGRATION IN PROGRESS
// This file has 3 fmt.Printf/Println violations that need to be replaced with structured logging.
// See systemctl_refactored.go for the migrated version that follows Eos standards:
// - All user output uses fmt.Fprint(os.Stderr, ...) to preserve stdout
// - All debug/info logging uses otelzap.Ctx(rc.Ctx)
// - Proper RuntimeContext usage throughout
// - Uses execute.Run where appropriate

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReloadDaemonAndEnable reloads systemd, then enables & starts the given unit.
// It returns an error if either step fails.
func ReloadDaemonAndEnable(ctx context.Context, unit string) error {
	// 1) reload systemd
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		otelzap.Ctx(ctx).Warn("systemd daemon-reload failed",
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("daemon-reload: %w", err)
	}

	// 2) enable & start the unit
	if out, err := exec.Command("systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
		otelzap.Ctx(ctx).Warn("failed to enable/start service",
			zap.String("unit", unit),
			zap.Error(err),
			zap.ByteString("output", out),
		)
		return fmt.Errorf("enable --now %s: %w", unit, err)
	}

	otelzap.Ctx(ctx).Info(" systemd unit enabled & started",
		zap.String("unit", unit),
	)
	return nil
}

func StartSystemdUnitWithRetry(ctx context.Context, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(ctx, "start", unit, retries, delaySeconds)
}

func StopSystemdUnitWithRetry(ctx context.Context, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(ctx, "stop", unit, retries, delaySeconds)
}

func RestartSystemdUnitWithRetry(ctx context.Context, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(ctx, "restart", unit, retries, delaySeconds)
}

func RunSystemctlWithRetry(ctx context.Context, action, unit string, retries, delaySeconds int) error {
	otelzap.Ctx(ctx).Info(" systemctl action initiated",
		zap.String("action", action),
		zap.String("unit", unit),
	)

	if !CanSudoSystemctl("status", unit) {
		if !CanInteractiveSudo() {
			return fmt.Errorf(" eos user missing sudo permissions; please add:\n    eos ALL=(ALL) NOPASSWD: /bin/systemctl")
		}
		otelzap.Ctx(ctx).Warn("NOPASSWD sudo missing. Attempting interactive sudo...")
		if err := PromptAndRunInteractiveSystemctl(action, unit); err != nil {
			return fmt.Errorf("interactive systemctl %s %s failed: %w", action, unit, err)
		}
		otelzap.Ctx(ctx).Info(" Interactive sudo succeeded; skipping retries")
		return nil
	}

	var lastErr error
	for i := 0; i < retries; i++ {
		cmd := exec.Command("systemctl", action, unit)
		out, err := cmd.CombinedOutput()

		if bytes.Contains(out, []byte("Authentication is required")) {
			otelzap.Ctx(ctx).Error(" Insufficient sudo privileges. Please add to sudoers...",
				zap.String("recommendation", "eos ALL=(ALL) NOPASSWD: /bin/systemctl"))
			return fmt.Errorf("sudo privileges missing; systemctl %s %s requires password", action, unit)
		}

		if err == nil {
			otelzap.Ctx(ctx).Info(fmt.Sprintf(" systemd unit %s succeeded", action),
				zap.String("unit", unit),
			)
			return nil
		}

		otelzap.Ctx(ctx).Warn(fmt.Sprintf("systemctl %s failed", action),
			zap.Int("attempt", i+1),
			zap.String("unit", unit),
			zap.Error(err),
			zap.ByteString("output", out),
		)
		lastErr = err
		time.Sleep(time.Duration(delaySeconds) * time.Second)
	}

	otelzap.Ctx(ctx).Error(fmt.Sprintf(" systemd unit %s failed after retries", action),
		zap.String("unit", unit),
		zap.Error(lastErr),
	)
	otelzap.Ctx(ctx).Info(" Run `systemctl status " + unit + " -l` or `journalctl -u " + unit + "` to investigate further")

	return fmt.Errorf("systemctl %s for unit %q failed: %w", action, unit, lastErr)
}

// CanSudoSystemctl checks if the current user can run sudo systemctl without a password.
// Uses a safe command that won't fail due to non-existent services.
func CanSudoSystemctl(action, unit string) bool {
	// Test with a safe systemctl command that always exists
	cmd := exec.Command("sudo", "-n", "systemctl", "--version")
	err := cmd.Run()
	if err != nil {
		fmt.Printf(" sudo -n systemctl --version failed: %v\n", err)
		return false
	}
	return true
}

func PromptAndRunInteractiveSystemctl(action, unit string) error {
	fmt.Printf("Privilege escalation required to run 'systemctl %s %s'\n", action, unit)
	fmt.Println("\nYou will be prompted for your password.")

	cmd := exec.Command("systemctl", action, unit)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// ServiceExists checks if a systemd service unit file exists
func ServiceExists(unit string) bool {
	cmd := exec.Command("systemctl", "cat", unit)
	err := cmd.Run()
	return err == nil
}

// CheckServiceStatus checks if a systemd service is active
func CheckServiceStatus(ctx context.Context, unit string) error {
	otelzap.Ctx(ctx).Debug("Checking service status", zap.String("unit", unit))

	cmd := exec.Command("systemctl", "is-active", unit)
	output, err := cmd.CombinedOutput()

	if err != nil {
		otelzap.Ctx(ctx).Debug("Service status check failed",
			zap.String("unit", unit),
			zap.Error(err),
			zap.ByteString("output", output))
		return fmt.Errorf("service %s is not active: %w", unit, err)
	}

	outputStr := string(bytes.TrimSpace(output))
	if outputStr != "active" {
		return fmt.Errorf("service %s is not active (status: %s)", unit, outputStr)
	}

	otelzap.Ctx(ctx).Debug("Service is active", zap.String("unit", unit))
	return nil
}

// RestartSystemdUnitWithVisibility performs a systemd restart with enhanced visibility
// It streams journalctl output and shows service state transitions in real-time
func RestartSystemdUnitWithVisibility(ctx context.Context, unit string, retries int, delaySeconds int) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("  Starting enhanced service restart",
		zap.String("unit", unit),
		zap.Int("max_retries", retries),
		zap.Int("retry_delay_seconds", delaySeconds))

	// Check if service exists first
	if !ServiceExists(unit) {
		return fmt.Errorf("service %s does not exist", unit)
	}

	// Get initial service state
	initialState, _ := getServiceState(unit)
	logger.Info("  Initial service state",
		zap.String("unit", unit),
		zap.String("state", initialState),
		zap.String("timestamp", time.Now().Format(time.RFC3339)))

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		if attempt > 0 {
			logger.Info("   Waiting before retry",
				zap.Int("attempt", attempt+1),
				zap.Int("delay_seconds", delaySeconds))
			time.Sleep(time.Duration(delaySeconds) * time.Second)
		}

		logger.Info("  Attempting service restart",
			zap.String("unit", unit),
			zap.Int("attempt", attempt+1),
			zap.Int("of", retries))

		// Start journalctl streaming in background
		journalCtx, journalCancel := context.WithCancel(ctx)
		journalDone := make(chan struct{})

		go func() {
			defer close(journalDone)
			streamJournalLogs(journalCtx, unit, logger)
		}()

		// Execute the restart with state monitoring
		restartStart := time.Now()
		err := executeRestartWithStateMonitoring(ctx, unit, logger)
		restartDuration := time.Since(restartStart)

		// Stop journal streaming
		journalCancel()
		<-journalDone

		if err == nil {
			// Verify service is active
			finalState, _ := getServiceState(unit)
			logger.Info("  Service restart completed successfully",
				zap.String("unit", unit),
				zap.String("initial_state", initialState),
				zap.String("final_state", finalState),
				zap.Duration("restart_duration", restartDuration))

			// Give service a moment to fully initialize
			time.Sleep(2 * time.Second)

			// Final health check - use appropriate check based on service type
			isOneshot, err := isOneshotService(unit)
			if err != nil {
				logger.Warn("Could not determine service type, using standard check",
					zap.String("unit", unit),
					zap.Error(err))
				isOneshot = false
			}

			var healthCheckErr error
			if isOneshot {
				// For oneshot services, check exit code rather than active state
				healthCheckErr = checkOneshotServiceHealth(ctx, unit)
				if healthCheckErr != nil {
					logger.Warn("   Oneshot service health check failed after restart",
						zap.String("unit", unit),
						zap.String("service_type", "oneshot"),
						zap.Error(healthCheckErr))
				} else {
					logger.Info("   Oneshot service completed successfully",
						zap.String("unit", unit),
						zap.String("service_type", "oneshot"))
				}
			} else {
				// For regular services, use the standard active state check
				healthCheckErr = CheckServiceStatus(ctx, unit)
				if healthCheckErr != nil {
					logger.Warn("   Service is not active after restart",
						zap.String("unit", unit),
						zap.String("service_type", "standard"),
						zap.Error(healthCheckErr))
				}
			}

			if healthCheckErr != nil {
				lastErr = healthCheckErr
				continue
			}

			return nil
		}

		logger.Error("  Service restart failed",
			zap.String("unit", unit),
			zap.Int("attempt", attempt+1),
			zap.Duration("restart_duration", restartDuration),
			zap.Error(err))
		lastErr = err
	}

	logger.Error("  Service restart failed after all retries",
		zap.String("unit", unit),
		zap.Int("total_attempts", retries),
		zap.Error(lastErr))

	// Show final diagnostic info
	showServiceDiagnostics(ctx, unit, logger)

	return fmt.Errorf("failed to restart %s after %d attempts: %w", unit, retries, lastErr)
}

// executeRestartWithStateMonitoring performs the restart while monitoring state changes
func executeRestartWithStateMonitoring(ctx context.Context, unit string, logger otelzap.LoggerWithCtx) error {
	// First, attempt graceful stop
	logger.Info("  Initiating graceful stop",
		zap.String("unit", unit),
		zap.String("phase", "stop"),
		zap.String("graceful_stop_explanation", "Sending SIGTERM to allow clean shutdown before SIGKILL"))

	stopStart := time.Now()

	// Get systemd's TimeoutStopSec for this unit
	timeoutStopSec := getUnitTimeoutStopSec(unit)
	logger.Info("   Service stop timeout configuration",
		zap.String("unit", unit),
		zap.String("timeout_stop_sec", timeoutStopSec),
		zap.String("explanation", "systemd will wait this long for graceful shutdown before SIGKILL"))

	// Monitor state during stop
	stopCmd := exec.Command("systemctl", "stop", unit)
	if err := stopCmd.Start(); err != nil {
		return fmt.Errorf("failed to initiate stop: %w", err)
	}

	// Monitor service state changes during stop
	go monitorServiceStateChanges(ctx, unit, logger, "stopping")

	if err := stopCmd.Wait(); err != nil {
		logger.Error(" Failed to stop service",
			zap.String("unit", unit),
			zap.Duration("stop_duration", time.Since(stopStart)),
			zap.Error(err))
		return fmt.Errorf("stop failed: %w", err)
	}

	stopDuration := time.Since(stopStart)
	logger.Info("  Service stopped",
		zap.String("unit", unit),
		zap.Duration("stop_duration", stopDuration))

	// Brief pause between stop and start
	time.Sleep(500 * time.Millisecond)

	// Start the service
	logger.Info("  Starting service",
		zap.String("unit", unit),
		zap.String("phase", "start"))

	startTime := time.Now()
	startCmd := exec.Command("systemctl", "start", unit)
	startOut, err := startCmd.CombinedOutput()
	startDuration := time.Since(startTime)

	if err != nil {
		logger.Error(" Failed to start service",
			zap.String("unit", unit),
			zap.Duration("start_duration", startDuration),
			zap.ByteString("output", startOut),
			zap.Error(err))
		return fmt.Errorf("start failed: %w", err)
	}

	logger.Info("  Service started",
		zap.String("unit", unit),
		zap.Duration("start_duration", startDuration),
		zap.Duration("total_restart_duration", time.Since(stopStart)))

	return nil
}

// streamJournalLogs streams journalctl output for a service
func streamJournalLogs(ctx context.Context, unit string, logger otelzap.LoggerWithCtx) {
	// Start journalctl with follow mode
	cmd := exec.CommandContext(ctx, "journalctl", "-u", unit, "-f", "--no-pager", "--since", "1 second ago")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Error(" Failed to create journalctl pipe",
			zap.String("unit", unit),
			zap.Error(err))
		return
	}

	if err := cmd.Start(); err != nil {
		logger.Error(" Failed to start journalctl",
			zap.String("unit", unit),
			zap.Error(err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		// Log each journal line with appropriate metadata
		logger.Info("  Service log",
			zap.String("unit", unit),
			zap.String("journal_line", line))
	}

	if err := cmd.Wait(); err != nil {
		logger.Debug("journalctl command exited",
			zap.String("unit", unit),
			zap.Error(err))
	}
}

// monitorServiceStateChanges monitors and logs service state transitions
func monitorServiceStateChanges(ctx context.Context, unit string, logger otelzap.LoggerWithCtx, expectedTransition string) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	lastState := ""
	transitionStart := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentState, _ := getServiceState(unit)
			if currentState != lastState {
				logger.Info("  Service state transition",
					zap.String("unit", unit),
					zap.String("from", lastState),
					zap.String("to", currentState),
					zap.Duration("after", time.Since(transitionStart)))
				lastState = currentState

				// Stop monitoring once we reach expected end state
				if expectedTransition == "stopping" && currentState == "inactive" {
					return
				} else if expectedTransition == "starting" && currentState == "active" {
					return
				}
			}

			// Timeout after 30 seconds
			if time.Since(transitionStart) > 30*time.Second {
				logger.Warn("   Service state transition timeout",
					zap.String("unit", unit),
					zap.String("expected_transition", expectedTransition),
					zap.String("current_state", currentState))
				return
			}
		}
	}
}

// getServiceState returns the current state of a systemd service
func getServiceState(unit string) (string, error) {
	cmd := exec.Command("systemctl", "show", unit, "--property=ActiveState", "--value")
	output, err := cmd.Output()
	if err != nil {
		return "unknown", err
	}
	return strings.TrimSpace(string(output)), nil
}

// getUnitTimeoutStopSec gets the TimeoutStopSec value for a unit
func getUnitTimeoutStopSec(unit string) string {
	cmd := exec.Command("systemctl", "show", unit, "--property=TimeoutStopUSec", "--value")
	output, err := cmd.Output()
	if err != nil {
		return "90s (default)"
	}

	// Convert microseconds to human-readable format
	valueStr := strings.TrimSpace(string(output))
	if valueStr == "infinity" {
		return "infinity"
	}

	// systemd returns microseconds, convert to seconds
	return valueStr
}

// showServiceDiagnostics displays diagnostic information for troubleshooting
func showServiceDiagnostics(ctx context.Context, unit string, logger otelzap.LoggerWithCtx) {
	logger.Info("  Service diagnostics",
		zap.String("unit", unit))

	// Get service status
	statusCmd := exec.Command("systemctl", "status", unit, "--no-pager", "-l")
	statusOut, _ := statusCmd.Output()
	if len(statusOut) > 0 {
		logger.Info("  Service status output",
			zap.String("unit", unit),
			zap.ByteString("status", statusOut))
	}

	// Get recent logs
	logsCmd := exec.Command("journalctl", "-u", unit, "--no-pager", "-n", "20")
	logsOut, _ := logsCmd.Output()
	if len(logsOut) > 0 {
		logger.Info("  Recent service logs",
			zap.String("unit", unit),
			zap.ByteString("logs", logsOut))
	}

	logger.Info("  Troubleshooting commands",
		zap.String("status_cmd", fmt.Sprintf("systemctl status %s -l", unit)),
		zap.String("logs_cmd", fmt.Sprintf("journalctl -u %s -f", unit)),
		zap.String("full_logs_cmd", fmt.Sprintf("journalctl -u %s --since '10 minutes ago'", unit)))
}

// isOneshotService checks if a systemd service is configured as Type=oneshot
func isOneshotService(serviceName string) (bool, error) {
	output, err := execute.Run(context.Background(), execute.Options{
		Command: "systemctl",
		Args:    []string{"show", serviceName, "--property=Type", "--value"},
		Capture: true,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check service type: %w", err)
	}

	serviceType := strings.TrimSpace(output)
	return serviceType == "oneshot", nil
}

// checkOneshotServiceHealth checks the health of a oneshot service by examining its exit status
func checkOneshotServiceHealth(ctx context.Context, serviceName string) error {
	// For oneshot services, we need to check:
	// 1. The service executed successfully (exit code 0)
	// 2. The service is in "inactive" state (which is normal for completed oneshot services)
	
	// Check the exit status of the last execution
	output, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"show", serviceName, "--property=ExecMainStatus", "--value"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to check service exit status: %w", err)
	}

	exitStatus := strings.TrimSpace(output)
	if exitStatus != "0" && exitStatus != "" {
		return fmt.Errorf("oneshot service exited with non-zero status: %s", exitStatus)
	}

	// Check that the service is in inactive state (normal for completed oneshot)
	output, err = execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
		Capture: true,
	})
	if err != nil {
		// For oneshot services, is-active returning an error is expected
		// Check if it's in "inactive" state specifically
		if strings.Contains(output, "inactive") {
			return nil // This is normal for completed oneshot services
		}
		return fmt.Errorf("oneshot service in unexpected state: %w", err)
	}

	state := strings.TrimSpace(output)
	if state == "inactive" {
		return nil // This is the expected state for completed oneshot services
	}

	return fmt.Errorf("oneshot service in unexpected active state: %s", state)
}

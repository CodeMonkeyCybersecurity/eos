// pkg/eos_unix/systemctl.go

package eos_unix

import (
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

// Package eos_unix provides systemctl operations with structured logging
// This implementation follows Eos standards:
// - All fmt.Printf/Println replaced with structured logging or stderr output
// - Using execute.Run instead of exec.Command where appropriate
// - Proper RuntimeContext usage throughout
// - Enhanced error handling

// ReloadDaemonAndEnable reloads systemd, then enables & starts the given unit.
// It returns an error if either step fails.
func ReloadDaemonAndEnable(ctx context.Context, unit string) error {
	logger := otelzap.Ctx(ctx)

	// ASSESS - Check if systemd is available
	logger.Info("Assessing systemd availability")
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found: %w", err)
	}

	// INTERVENE - Reload and enable
	logger.Info("Reloading systemd daemon")

	// 1) reload systemd
	if _, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: true,
	}); err != nil {
		logger.Warn("systemd daemon-reload failed",
			zap.Error(err))
		return fmt.Errorf("daemon-reload: %w", err)
	}

	// 2) enable & start the unit
	logger.Info("Enabling and starting systemd unit",
		zap.String("unit", unit))

	if _, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "--now", unit},
		Capture: true,
	}); err != nil {
		logger.Warn("failed to enable/start service",
			zap.String("unit", unit),
			zap.Error(err))
		return fmt.Errorf("enable --now %s: %w", unit, err)
	}

	// EVALUATE - Verify service is active
	logger.Info("Evaluating systemd unit status",
		zap.String("unit", unit))

	if err := CheckServiceStatus(ctx, unit); err != nil {
		logger.Error("Service is not active after enable",
			zap.String("unit", unit),
			zap.Error(err))
		return err
	}

	logger.Info("systemd unit enabled & started",
		zap.String("unit", unit))
	return nil
}

// CanSudoSystemctl checks if the current user can run sudo systemctl without a password.
// Uses a safe command that won't fail due to non-existent services.
func CanSudoSystemctl(ctx context.Context, action, unit string) bool {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Checking sudo systemctl permissions",
		zap.String("action", action),
		zap.String("unit", unit))

	// Test with a safe systemctl command that always exists
	_, err := execute.Run(ctx, execute.Options{
		Command: "sudo",
		Args:    []string{"-n", "systemctl", "--version"},
		Capture: true,
	})

	if err != nil {
		logger.Debug("sudo -n systemctl --version failed",
			zap.Error(err))
		return false
	}
	return true
}

// PromptAndRunInteractiveSystemctl prompts for sudo password and runs systemctl
func PromptAndRunInteractiveSystemctl(ctx context.Context, action, unit string) error {
	logger := otelzap.Ctx(ctx)

	// Log the prompt for audit trail
	logger.Info("terminal prompt: Privilege escalation required for systemctl")

	// Use stderr for user prompts to preserve stdout
	if _, err := fmt.Fprintf(os.Stderr, "Privilege escalation required to run 'systemctl %s %s'\n", action, unit); err != nil {
		return fmt.Errorf("failed to write prompt: %w", err)
	}

	logger.Info("terminal prompt: You will be prompted for your password")
	if _, err := fmt.Fprintln(os.Stderr, "\nYou will be prompted for your password."); err != nil {
		return fmt.Errorf("failed to write prompt: %w", err)
	}

	// Use exec.Command for interactive sudo (needs stdin/stdout)
	cmd := exec.Command("systemctl", action, unit)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		logger.Error("Interactive systemctl failed",
			zap.String("action", action),
			zap.String("unit", unit),
			zap.Error(err))
		return err
	}

	logger.Info("Interactive systemctl completed successfully",
		zap.String("action", action),
		zap.String("unit", unit))

	return nil
}

// RunSystemctlWithRetry runs systemctl with retries and enhanced logging
func RunSystemctlWithRetry(ctx context.Context, action, unit string, retries, delaySeconds int) error {
	logger := otelzap.Ctx(ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing systemctl operation requirements",
		zap.String("action", action),
		zap.String("unit", unit),
		zap.Int("max_retries", retries))

	if !CanSudoSystemctl(ctx, "status", unit) {
		if !CanInteractiveSudoWithContext(ctx) {
			return fmt.Errorf("eos user missing sudo permissions; please add:\n    eos ALL=(ALL) NOPASSWD: /bin/systemctl")
		}
		logger.Warn("NOPASSWD sudo missing. Attempting interactive sudo...")
		if err := PromptAndRunInteractiveSystemctl(ctx, action, unit); err != nil {
			return fmt.Errorf("interactive systemctl %s %s failed: %w", action, unit, err)
		}
		logger.Info("Interactive sudo succeeded; skipping retries")
		return nil
	}

	// INTERVENE - Execute with retries
	logger.Info("Executing systemctl action",
		zap.String("action", action),
		zap.String("unit", unit))

	var lastErr error
	for i := 0; i < retries; i++ {
		if i > 0 {
			logger.Info("Retrying systemctl command",
				zap.Int("attempt", i+1),
				zap.Int("delay_seconds", delaySeconds))
			time.Sleep(time.Duration(delaySeconds) * time.Second)
		}

		output, err := execute.Run(ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{action, unit},
			Capture: true,
		})

		if bytes.Contains([]byte(output), []byte("Authentication is required")) {
			logger.Error("Insufficient sudo privileges",
				zap.String("recommendation", "eos ALL=(ALL) NOPASSWD: /bin/systemctl"))
			return fmt.Errorf("sudo privileges missing; systemctl %s %s requires password", action, unit)
		}

		if err == nil {
			// EVALUATE - Verify success
			logger.Info("systemd unit action succeeded",
				zap.String("action", action),
				zap.String("unit", unit),
				zap.Int("attempt", i+1))
			return nil
		}

		logger.Warn("systemctl action failed",
			zap.String("action", action),
			zap.Int("attempt", i+1),
			zap.String("unit", unit),
			zap.Error(err),
			zap.String("output", output))
		lastErr = err
	}

	logger.Error("systemd unit action failed after retries",
		zap.String("action", action),
		zap.String("unit", unit),
		zap.Int("total_attempts", retries),
		zap.Error(lastErr))

	logger.Info("Run diagnostics commands for troubleshooting",
		zap.String("status_cmd", fmt.Sprintf("systemctl status %s -l", unit)),
		zap.String("journal_cmd", fmt.Sprintf("journalctl -u %s", unit)))

	return fmt.Errorf("systemctl %s for unit %q failed: %w", action, unit, lastErr)
}

// Helper functions for retry methods
func StartSystemdUnitWithRetry(ctx context.Context, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(ctx, "start", unit, retries, delaySeconds)
}

func StopSystemdUnitWithRetry(ctx context.Context, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(ctx, "stop", unit, retries, delaySeconds)
}

func RestartSystemdUnitWithRetry(ctx context.Context, unit string, retries int, delaySeconds int) error {
	return RunSystemctlWithRetry(ctx, "restart", unit, retries, delaySeconds)
}

// CanInteractiveSudoWithContext checks if interactive sudo is available
func CanInteractiveSudoWithContext(ctx context.Context) bool {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking if interactive sudo is available")

	// Check if we have a TTY
	if _, err := os.Stdin.Stat(); err != nil {
		logger.Debug("No TTY available for interactive sudo")
		return false
	}
	return true
}

// ServiceExists checks if a systemd service unit file exists
func ServiceExists(ctx context.Context, unit string) bool {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Checking if service exists",
		zap.String("unit", unit))

	_, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"cat", unit},
		Capture: true,
	})

	exists := err == nil
	logger.Debug("Service existence check result",
		zap.String("unit", unit),
		zap.Bool("exists", exists))

	return exists
}

// CheckServiceStatus checks if a systemd service is active
func CheckServiceStatus(ctx context.Context, unit string) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking service status", zap.String("unit", unit))

	output, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", unit},
		Capture: true,
	})

	if err != nil {
		logger.Debug("Service status check failed",
			zap.String("unit", unit),
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("service %s is not active: %w", unit, err)
	}

	outputStr := strings.TrimSpace(output)
	if outputStr != "active" {
		return fmt.Errorf("service %s is not active (status: %s)", unit, outputStr)
	}

	logger.Debug("Service is active", zap.String("unit", unit))
	return nil
}

// TODO: The RestartSystemdUnitWithVisibility function and its helpers would also need migration
// This is a complex function with extensive logging that should be carefully refactored

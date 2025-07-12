package pipeline

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetServiceWorkers returns the list of service workers that need to be deployed
// for the pipeline infrastructure. This follows the Assess → Intervene → Evaluate pattern.
func GetServiceWorkers() []shared.ServiceWorkerInfo {
	return []shared.ServiceWorkerInfo{
		{
			ServiceName: "delphi-webhook-listener.service",
			SourcePath:  "assets/service-workers/webhook-listener.py",
			TargetPath:  "/opt/delphi/service-workers/webhook-listener.py",
			BackupPath:  "/opt/delphi/service-workers/webhook-listener.py.bak",
		},
		{
			ServiceName: "delphi-webhook-processor.service",
			SourcePath:  "assets/service-workers/webhook-processor.py",
			TargetPath:  "/opt/delphi/service-workers/webhook-processor.py",
			BackupPath:  "/opt/delphi/service-workers/webhook-processor.py.bak",
		},
		{
			ServiceName: "delphi-alert-dispatcher.service",
			SourcePath:  "assets/service-workers/alert-dispatcher.py",
			TargetPath:  "/opt/delphi/service-workers/alert-dispatcher.py",
			BackupPath:  "/opt/delphi/service-workers/alert-dispatcher.py.bak",
		},
		{
			ServiceName: "delphi-prompt-manager.service",
			SourcePath:  "assets/service-workers/prompt-manager.py",
			TargetPath:  "/opt/delphi/service-workers/prompt-manager.py",
			BackupPath:  "/opt/delphi/service-workers/prompt-manager.py.bak",
		},
		{
			ServiceName: "delphi-prompt-ab-tester.service",
			SourcePath:  "assets/service-workers/prompt-ab-tester.py",
			TargetPath:  "/opt/delphi/service-workers/prompt-ab-tester.py",
			BackupPath:  "/opt/delphi/service-workers/prompt-ab-tester.py.bak",
		},
		{
			ServiceName: "delphi-ai-initializer.service",
			SourcePath:  "assets/service-workers/ai-pipeline-init.py",
			TargetPath:  "/opt/delphi/service-workers/ai-pipeline-init.py",
			BackupPath:  "/opt/delphi/service-workers/ai-pipeline-init.py.bak",
		},
	}
}

// UpdateServiceWorker handles the update of a single service worker following
// the Assess → Intervene → Evaluate pattern.
func UpdateServiceWorker(rc *eos_io.RuntimeContext, worker shared.ServiceWorkerInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Verify source file exists
	if _, err := os.Stat(worker.SourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source file not found: %s", worker.SourcePath)
	}

	logger.Info("📦 Updating service worker",
		zap.String("service", worker.ServiceName),
		zap.String("source", worker.SourcePath),
		zap.String("target", worker.TargetPath))

	// INTERVENE - Create backup of existing file
	if _, err := os.Stat(worker.TargetPath); err == nil {
		logger.Info("📋 Creating backup of existing worker",
			zap.String("backup", worker.BackupPath))

		if err := CopyFile(worker.TargetPath, worker.BackupPath); err != nil {
			return fmt.Errorf("failed to backup existing worker: %w", err)
		}
	}

	// Ensure target directory exists
	targetDir := "/opt/delphi/service-workers"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Copy new worker file
	if err := CopyFile(worker.SourcePath, worker.TargetPath); err != nil {
		// Attempt to restore backup on failure
		if _, backupErr := os.Stat(worker.BackupPath); backupErr == nil {
			logger.Warn("⚠️ Copy failed, attempting to restore backup",
				zap.Error(err))
			_ = CopyFile(worker.BackupPath, worker.TargetPath)
		}
		return fmt.Errorf("failed to copy worker file: %w", err)
	}

	// Set proper permissions (executable for Python scripts)
	if err := os.Chmod(worker.TargetPath, 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// EVALUATE - Restart service if it's running
	if err := RestartServiceIfRunning(rc.Ctx, worker.ServiceName); err != nil {
		logger.Warn("⚠️ Failed to restart service",
			zap.String("service", worker.ServiceName),
			zap.Error(err))
	}

	// For oneshot services (like ai-initializer), verify completion
	if worker.ServiceName == "delphi-ai-initializer.service" {
		logger.Info("⏳ Waiting for oneshot service to complete",
			zap.String("service", worker.ServiceName))

		if err := VerifyOneshotCompletion(rc.Ctx, worker.ServiceName); err != nil {
			logger.Warn("⚠️ Oneshot service may not have completed successfully",
				zap.String("service", worker.ServiceName),
				zap.Error(err))
		}
	}

	logger.Info(" Service worker deployment completed",
		zap.String("service", worker.ServiceName),
		zap.String("target", worker.TargetPath))

	return nil
}

// RestartServiceIfRunning restarts a systemd service if it's currently running
func RestartServiceIfRunning(ctx context.Context, serviceName string) error {
	// Check if service is active
	output, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
	})

	// If service is not active (exit code != 0), nothing to do
	if err != nil {
		return nil
	}

	// Service is active, restart it
	if output == "active\n" {
		_, err := execute.Run(ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"restart", serviceName},
		})
		return err
	}

	return nil
}

// VerifyOneshotCompletion verifies that a oneshot service has completed successfully
func VerifyOneshotCompletion(ctx context.Context, serviceName string) error {
	// For oneshot services, we expect them to be in "inactive" state after completion
	output, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
	})

	// For oneshot services, "inactive" is the expected state after successful completion
	if err != nil && output == "inactive\n" {
		// Check if the service result was successful
		result, _ := execute.Run(ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"show", serviceName, "--property=Result"},
		})

		if result == "Result=success\n" {
			return nil // Service completed successfully
		}
	}

	// Wait a bit and check again
	time.Sleep(2 * time.Second)

	// Final check of service result
	result, _ := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"show", serviceName, "--property=Result"},
	})

	if result != "Result=success\n" {
		return fmt.Errorf("oneshot service did not complete successfully: %s", result)
	}

	return nil
}

// CopyFile copies a file from source to destination
func CopyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, input, 0644)
	if err != nil {
		return err
	}

	return nil
}

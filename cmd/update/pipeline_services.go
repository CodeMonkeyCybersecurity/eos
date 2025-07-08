package update

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceWorkerInfo contains information about a service worker
type ServiceWorkerInfo struct {
	ServiceName string
	SourcePath  string
	TargetPath  string
	BackupPath  string
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// GetServiceWorkers returns information about all delphi service workers
func GetServiceWorkers(eosRoot string) []ServiceWorkerInfo {
	return []ServiceWorkerInfo{
		{
			ServiceName: "delphi-listener",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "delphi-listener.py"),
			TargetPath:  "/opt/stackstorm/packs/delphi/delphi-listener.py",
			BackupPath:  "/opt/stackstorm/packs/delphi/delphi-listener.py.bak",
		},
		{
			ServiceName: "delphi-agent-enricher",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "delphi-agent-enricher.py"),
			TargetPath:  "/opt/stackstorm/packs/delphi/delphi-agent-enricher.py",
			BackupPath:  "/opt/stackstorm/packs/delphi/delphi-agent-enricher.py.bak",
		},
		{
			ServiceName: "llm-worker",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "llm-worker.py"),
			TargetPath:  "/opt/stackstorm/packs/delphi/llm-worker.py",
			BackupPath:  "/opt/stackstorm/packs/delphi/llm-worker.py.bak",
		},
		{
			ServiceName: "email-structurer",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "email-structurer.py"),
			TargetPath:  "/usr/local/bin/email-structurer.py",
			BackupPath:  "/usr/local/bin/email-structurer.py.bak",
		},
		{
			ServiceName: "prompt-ab-tester",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "prompt-ab-tester.py"),
			TargetPath:  "/usr/local/bin/prompt-ab-tester.py",
			BackupPath:  "/usr/local/bin/prompt-ab-tester.py.bak",
		},
	}
}

var PipelineServicesCmd = &cobra.Command{
	Use:   "pipeline-services",
	Short: "Update Delphi pipeline services (Python workers)",
	Long: `Update Delphi pipeline services from source code to deployment.

This command synchronizes Python worker scripts from the source repository to their runtime locations,
creating backups and verifying deployment. It ensures all Delphi pipeline services are up-to-date.

Example:
  eos update pipeline-services`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Starting pipeline services update")

		// Get eos root directory
		eosRoot := "/opt/eos"
		if envRoot := os.Getenv("EOS_ROOT"); envRoot != "" {
			eosRoot = envRoot
		}
		logger.Info(" Eos root directory located", zap.String("root", eosRoot))

		// Verify source directory exists
		sourcePyDir := filepath.Join(eosRoot, "assets", "python_workers")
		if _, err := os.Stat(sourcePyDir); os.IsNotExist(err) {
			return fmt.Errorf("python workers source directory not found: %s", sourcePyDir)
		}

		logger.Info(" Source directory verified", zap.String("path", sourcePyDir))

		// Get service worker configurations
		workers := GetServiceWorkers(eosRoot)
		logger.Info(" Service workers identified", zap.Int("count", len(workers)))

		// Process each service worker
		successCount := 0
		for i, worker := range workers {
			logger.Info(" Processing service worker",
				zap.String("service", worker.ServiceName),
				zap.Int("progress", i+1),
				zap.Int("total", len(workers)))

			if err := updateServiceWorker(rc, worker); err != nil {
				logger.Error(" Failed to update service worker",
					zap.String("service", worker.ServiceName),
					zap.Error(err))
				return fmt.Errorf("failed to update %s: %w", worker.ServiceName, err)
			}

			successCount++
			logger.Info(" Service worker updated successfully",
				zap.String("service", worker.ServiceName))
		}

		logger.Info(" Pipeline services update completed",
			zap.Int("services_updated", successCount),
			zap.Int("total_services", len(workers)))

		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(PipelineServicesCmd)
}

// updateServiceWorker handles the update of a single service worker
func updateServiceWorker(rc *eos_io.RuntimeContext, worker ServiceWorkerInfo) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Verify source file exists
	if _, err := os.Stat(worker.SourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source file not found: %s", worker.SourcePath)
	}

	logger.Debug(" Source file verified", zap.String("path", worker.SourcePath))

	// Create target directory if it doesn't exist
	targetDir := filepath.Dir(worker.TargetPath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
	}

	// Create backup if target file exists
	if _, err := os.Stat(worker.TargetPath); err == nil {
		logger.Info(" Creating backup of existing file",
			zap.String("target", worker.TargetPath),
			zap.String("backup", worker.BackupPath))

		backupDir := filepath.Dir(worker.BackupPath)
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			return fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
		}

		if err := CopyFile(worker.TargetPath, worker.BackupPath); err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}

		logger.Info(" Backup created successfully", zap.String("backup", worker.BackupPath))
	}

	// Copy source to target
	logger.Info(" Copying source to target",
		zap.String("source", worker.SourcePath),
		zap.String("target", worker.TargetPath))

	if err := CopyFile(worker.SourcePath, worker.TargetPath); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// Set proper permissions (executable for Python scripts)
	if err := os.Chmod(worker.TargetPath, 0755); err != nil {
		logger.Warn(" Failed to set executable permissions", zap.Error(err))
	}

	// Restart the service if it's running
	if err := restartServiceIfRunning(rc.Ctx, worker.ServiceName); err != nil {
		logger.Warn(" Failed to restart service (may not be running)",
			zap.String("service", worker.ServiceName),
			zap.Error(err))
	}

	logger.Info(" Service worker deployment completed",
		zap.String("service", worker.ServiceName),
		zap.String("target", worker.TargetPath))

	return nil
}

// restartServiceIfRunning restarts a systemd service if it's currently running
func restartServiceIfRunning(ctx context.Context, serviceName string) error {
	// Check if service is active
	output, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
	})

	if err != nil {
		// Service is not active or doesn't exist
		return nil
	}

	state := strings.TrimSpace(output)
	if state == "active" {
		// Service is running, restart it
		_, err := execute.Run(ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"restart", serviceName},
		})
		return err
	}

	return nil
}

// verifyOneshotCompletion verifies that a oneshot service has completed successfully
func verifyOneshotCompletion(ctx context.Context, serviceName string) error {
	// For oneshot services, we expect them to be in "inactive" state after completion
	output, err := execute.Run(ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", serviceName},
	})

	if err != nil {
		// Check if it's inactive (expected for completed oneshot services)
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

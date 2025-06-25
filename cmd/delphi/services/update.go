package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
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

// GetServiceWorkers returns information about all delphi service workers
// This function needs the eosRoot to correctly determine source paths.
func GetServiceWorkers(eosRoot string) []ServiceWorkerInfo {
	timestamp := time.Now().Format("20060102_150405")

	return []ServiceWorkerInfo{
		{
			ServiceName: "delphi-listener",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "delphi-listener.py"),
			TargetPath:  "/opt/stackstorm/packs/delphi/delphi-listener.py",
			BackupPath:  fmt.Sprintf("/opt/stackstorm/packs/delphi/delphi-listener.py.%s.bak", timestamp),
		},
		{
			ServiceName: "delphi-agent-enricher",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "delphi-agent-enricher.py"),
			TargetPath:  "/opt/stackstorm/packs/delphi/delphi-agent-enricher.py",
			BackupPath:  fmt.Sprintf("/opt/stackstorm/packs/delphi/delphi-agent-enricher.py.%s.bak", timestamp),
		},
		{
			ServiceName: "delphi-emailer",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "delphi-emailer.py"),
			TargetPath:  "/opt/stackstorm/packs/delphi/delphi-emailer.py",
			BackupPath:  fmt.Sprintf("/opt/stackstorm/packs/delphi/delphi-emailer.py.%s.bak", timestamp),
		},
		{
			ServiceName: "llm-worker",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "llm-worker.py"),
			TargetPath:  "/opt/stackstorm/packs/delphi/llm-worker.py",
			BackupPath:  fmt.Sprintf("/opt/stackstorm/packs/delphi/llm-worker.py.%s.bak", timestamp),
		},
		{
			ServiceName: "prompt-ab-tester",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "prompt-ab-tester.py"),
			TargetPath:  "/usr/local/bin/prompt-ab-tester.py", // Note: This one goes to /usr/local/bin
			BackupPath:  fmt.Sprintf("/usr/local/bin/prompt-ab-tester.py.%s.bak", timestamp),
		},
		{
			ServiceName: "ab-test-analyzer",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "ab-test-analyzer.py"),
			TargetPath:  "/usr/local/bin/ab-test-analyzer.py", // Note: This one goes to /usr/local/bin
			BackupPath:  fmt.Sprintf("/usr/local/bin/ab-test-analyzer.py.%s.bak", timestamp),
		},
		{
			ServiceName: "alert-to-db",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "alert-to-db.py"),
			TargetPath:  "/opt/stackstorm/packs/delphi/alert-to-db.py",
			BackupPath:  fmt.Sprintf("/opt/stackstorm/packs/delphi/alert-to-db.py.%s.bak", timestamp),
		},
		{
			ServiceName: "email-structurer",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "email-structurer.py"),
			TargetPath:  "/usr/local/bin/email-structurer.py",
			BackupPath:  fmt.Sprintf("/usr/local/bin/email-structurer.py.%s.bak", timestamp),
		},
		{
			ServiceName: "email-formatter", // ADDED: New entry for email-formatter
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "email-formatter.py"),
			TargetPath:  "/usr/local/bin/email-formatter.py", // Assuming this is its target path
			BackupPath:  fmt.Sprintf("/usr/local/bin/email-formatter.py.%s.bak", timestamp),
		},
	}
}

// detectEosRoot attempts to find the EOS root directory.
// It checks the EOS_ROOT env var, then relative to the executable, then current working dir.
func detectEosRoot(logger otelzap.LoggerWithCtx) (string, error) {
	// 1. Check EOS_ROOT environment variable
	if eosRoot := os.Getenv("EOS_ROOT"); eosRoot != "" {
		logger.Debug("EOS_ROOT found from environment variable", zap.String("path", eosRoot))
		// Check if the provided EOS_ROOT actually contains the 'assets' directory
		if fileExists(filepath.Join(eosRoot, "assets")) {
			return eosRoot, nil
		}
		logger.Warn("EOS_ROOT environment variable set, but 'assets' directory not found inside it, trying auto-detection.", zap.String("path", eosRoot))
		// Continue to other detection methods if the set path doesn't look valid for assets
	}

	// 2. Try to deduce from executable path (e.g., if installed in /usr/local/bin)
	exePath, err := os.Executable()
	if err == nil {
		// Common installation locations for the executable and corresponding project root
		// This list assumes 'eos' binary is in /usr/local/bin and the project root
		// is typically in /opt/eos or /srv/eos.
		possibleRoots := []string{
			filepath.Join(filepath.Dir(exePath), "..", "..", "opt", "eos"), // e.g., /usr/local/bin/eos -> /opt/eos
			filepath.Join(filepath.Dir(exePath), "..", "..", "srv", "eos"), // e.g., /usr/local/bin/eos -> /srv/eos
			filepath.Join(filepath.Dir(exePath), "..", "eos"),              // e.g., /usr/local/bin/eos -> /usr/local/eos (less common)
			"/opt/eos", // Direct check for common /opt/eos
			"/srv/eos", // Direct check for common /srv/eos
		}
		for _, root := range possibleRoots {
			absRoot, _ := filepath.Abs(root)
			if fileExists(filepath.Join(absRoot, "assets")) {
				logger.Debug("EOS_ROOT auto-detected relative to executable", zap.String("path", absRoot))
				return absRoot, nil
			}
		}
	} else {
		logger.Warn("Failed to get executable path for EOS_ROOT auto-detection", zap.Error(err))
	}

	// 3. Try current working directory (only if it looks like the root)
	if pwd, err := os.Getwd(); err == nil {
		if fileExists(filepath.Join(pwd, "assets")) {
			logger.Debug("EOS_ROOT auto-detected from current working directory", zap.String("path", pwd))
			return pwd, nil
		}
	} else {
		logger.Warn("Failed to get current working directory for EOS_ROOT auto-detection", zap.Error(err))
	}

	return "", fmt.Errorf("EOS_ROOT environment variable not set and cannot auto-detect Eos directory. Please set EOS_ROOT to the path of your eos project (e.g., /opt/eos) or ensure 'eos' is installed in a standard location.")
}

// NewUpdateCmd creates the update command
func NewUpdateCmd() *cobra.Command {
	var (
		all         bool
		dryRun      bool
		skipBackup  bool
		skipRestart bool
	)

	cmd := &cobra.Command{
		Use:   "update [service-name]",
		Short: "Update Delphi service workers to latest version",
		Long: `Update one or more Delphi service worker Python scripts to the latest version.

This command:
1. Backs up existing service workers with timestamp (unless --skip-backup)
2. Deploys updated Python workers from assets/python_workers/
3. Restarts affected services (unless --skip-restart)
4. Verifies services are running properly

Available services:
- delphi-listener: Webhook listener for Wazuh alerts
- delphi-agent-enricher: Agent enrichment service
- delphi-emailer: Email notification service
- llm-worker: LLM processing service
- prompt-ab-tester: A/B testing worker for prompt optimization
- ab-test-analyzer: A/B test analysis worker
- alert-to-db: Database operations for alerts
- email-structurer: Email structuring service
- email-formatter: Email formatting service (Added)

Examples:
  eos delphi services update delphi-listener
  eos delphi services update --all
  eos delphi services update --all --dry-run
  eos delphi services update delphi-emailer --skip-backup --skip-restart`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			// Call detectEosRoot here as well to get an accurate list for autocompletion
			logger := otelzap.Ctx(cmd.Context()) // Use command context for logger
			eosRoot, err := detectEosRoot(logger)
			if err != nil {
				// Log the error but don't fail autocompletion
				logger.Error("Failed to detect EOS_ROOT for autocompletion", zap.Error(err))
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			workers := GetServiceWorkers(eosRoot)
			var services []string
			for _, w := range workers {
				services = append(services, w.ServiceName)
			}
			return services, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Starting Delphi services update",
				zap.Bool("all", all),
				zap.Bool("dry_run", dryRun),
				zap.Bool("skip_backup", skipBackup),
				zap.Bool("skip_restart", skipRestart))

			// Get EOS root directory using the new robust detection function
			eosRoot, err := detectEosRoot(logger)
			if err != nil {
				return err // Return the error if EOS_ROOT cannot be determined
			}

			// Get all service workers
			allWorkers := GetServiceWorkers(eosRoot)

			// Determine which workers to update
			var workersToUpdate []ServiceWorkerInfo
			if all {
				workersToUpdate = allWorkers
			} else if len(args) == 0 {
				return fmt.Errorf("specify a service name or use --all")
			} else {
				// Validate service name and find worker
				serviceName := args[0]
				found := false
				for _, worker := range allWorkers {
					if worker.ServiceName == serviceName {
						workersToUpdate = []ServiceWorkerInfo{worker}
						found = true
						break
					}
				}
				if !found {
					var availableServices []string
					for _, w := range allWorkers {
						availableServices = append(availableServices, w.ServiceName)
					}
					return fmt.Errorf("invalid service: %s. Valid services: %s", serviceName, strings.Join(availableServices, ", "))
				}
			}

			return updateServiceWorkers(rc, logger, workersToUpdate, dryRun, skipBackup, skipRestart)
		}),
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Update all Delphi service workers")
	cmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Show what would be done without making changes")
	cmd.Flags().BoolVar(&skipBackup, "skip-backup", false, "Skip backing up existing workers")
	cmd.Flags().BoolVar(&skipRestart, "skip-restart", false, "Skip restarting services after update")

	return cmd
}

func updateServiceWorkers(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, workers []ServiceWorkerInfo, dryRun, skipBackup, skipRestart bool) error {
	logger.Info("Planning to update workers",
		zap.Int("worker_count", len(workers)),
		zap.Bool("dry_run", dryRun))

	// Pre-flight checks
	for _, worker := range workers {
		// Check source file exists
		if !fileExists(worker.SourcePath) {
			return fmt.Errorf("source file not found: %s", worker.SourcePath)
		}

		// Check target directory exists
		targetDir := filepath.Dir(worker.TargetPath)
		if !fileExists(targetDir) {
			// Attempt to create the target directory if it doesn't exist
			logger.Info("Target directory does not exist, attempting to create it",
				zap.String("directory", targetDir))
			if err := os.MkdirAll(targetDir, 0755); err != nil {
				return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
			}
		}

		logger.Info("Pre-flight check passed",
			zap.String("service", worker.ServiceName),
			zap.String("source", worker.SourcePath),
			zap.String("target", worker.TargetPath))
	}

	if dryRun {
		logger.Info("DRY RUN - would perform the following actions:")
		for _, worker := range workers {
			logger.Info("Service worker update plan",
				zap.String("service", worker.ServiceName),
				zap.String("source", worker.SourcePath),
				zap.String("target", worker.TargetPath),
				zap.String("backup", worker.BackupPath),
				zap.Bool("will_backup", !skipBackup && fileExists(worker.TargetPath)),
				zap.Bool("will_restart", !skipRestart))
		}
		return nil
	}

	// Track services that need restarting
	var servicesToRestart []string

	// Update each worker
	for _, worker := range workers {
		logger.Info("Updating service worker",
			zap.String("service", worker.ServiceName))

		// Step 1: Backup existing file if it exists and backup is not skipped
		if !skipBackup && fileExists(worker.TargetPath) {
			logger.Info("Creating backup",
				zap.String("source", worker.TargetPath),
				zap.String("backup", worker.BackupPath))

			if err := copyFile(worker.TargetPath, worker.BackupPath); err != nil {
				return fmt.Errorf("failed to backup %s: %w", worker.ServiceName, err)
			}

			logger.Info("Backup created",
				zap.String("backup_path", worker.BackupPath))
		}

		// Step 2: Deploy new version
		logger.Info("Deploying updated worker",
			zap.String("source", worker.SourcePath),
			zap.String("target", worker.TargetPath))

		if err := copyFile(worker.SourcePath, worker.TargetPath); err != nil {
			return fmt.Errorf("failed to deploy updated %s: %w", worker.ServiceName, err)
		}

		// Set appropriate permissions
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "chmod",
			Args:    []string{"755", worker.TargetPath},
		})
		if err != nil {
			logger.Warn("Failed to set permissions (continuing)",
				zap.String("file", worker.TargetPath),
				zap.Error(err))
		}

		// Set ownership to stanley (if running as root)
		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "chown",
			Args:    []string{"stanley:stanley", worker.TargetPath},
		})
		if err != nil {
			logger.Warn("Failed to set ownership (continuing)",
				zap.String("file", worker.TargetPath),
				zap.Error(err))
		}

		logger.Info("Service worker updated successfully",
			zap.String("service", worker.ServiceName),
			zap.String("target", worker.TargetPath))

		// Add to restart list if service exists
		if eos_unix.ServiceExists(worker.ServiceName) {
			servicesToRestart = append(servicesToRestart, worker.ServiceName)
		} else {
			logger.Warn("Service unit file not found, skipping restart",
				zap.String("service", worker.ServiceName))
		}
	}

	// Step 3: Restart services if not skipped
	if !skipRestart && len(servicesToRestart) > 0 {
		logger.Info("Restarting updated services",
			zap.Strings("services", servicesToRestart))

		for _, service := range servicesToRestart {
			logger.Info("Restarting service",
				zap.String("service", service))

			if err := eos_unix.RestartSystemdUnitWithRetry(rc.Ctx, service, 3, 2); err != nil {
				logger.Error("Failed to restart service",
					zap.String("service", service),
					zap.Error(err))
				return fmt.Errorf("failed to restart %s: %w", service, err)
			}

			logger.Info("Service restarted successfully",
				zap.String("service", service))
		}
	}

	// Step 4: Verify services are running
	if !skipRestart && len(servicesToRestart) > 0 {
		logger.Info("Verifying service status")

		for _, service := range servicesToRestart {
			if err := eos_unix.CheckServiceStatus(rc.Ctx, service); err != nil {
				logger.Warn("Service is not active after restart",
					zap.String("service", service),
					zap.Error(err))
				logger.Info("Check service logs with: eos delphi services logs",
					zap.String("service", service))
			} else {
				logger.Info("Service is running",
					zap.String("service", service))
			}
		}
	}

	logger.Info("Service worker update completed successfully",
		zap.Int("workers_updated", len(workers)),
		zap.Int("services_restarted", len(servicesToRestart)))

	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	err = os.WriteFile(dst, input, 0755)
	if err != nil {
		return err
	}

	return nil
}

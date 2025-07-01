package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
			ServiceName: "email-formatter",
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "email-formatter.py"),
			TargetPath:  "/usr/local/bin/email-formatter.py",
			BackupPath:  fmt.Sprintf("/usr/local/bin/email-formatter.py.%s.bak", timestamp),
		},
		// --- FIX START ---
		{
			ServiceName: "email-sender", // ADDED: New entry for email-sender
			SourcePath:  filepath.Join(eosRoot, "assets", "python_workers", "email-sender.py"),
			TargetPath:  "/usr/local/bin/email-sender.py", // Based on your systemctl status output and typical deployment
			BackupPath:  fmt.Sprintf("/usr/local/bin/email-sender.py.%s.bak", timestamp),
		},
		// --- FIX END ---
	}
}

// REMOVED: detectEosRoot function - now using centralized service registry in pkg/shared

// NewUpdateCmd creates the update command
func NewUpdateCmd() *cobra.Command {
	var (
		all                   bool
		dryRun                bool
		skipBackup            bool
		skipRestart           bool
		skipInstallationCheck bool
		timeout               time.Duration
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
- email-formatter: Email formatting service
- email-sender: Email sending service (Added)

Examples:
  eos delphi services update delphi-listener
  eos delphi services update --all
  eos delphi services update --all --dry-run
  eos delphi services update --all --skip-installation-check
  eos delphi services update delphi-emailer --skip-backup --skip-restart
  eos delphi services update --all --timeout 15m`,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			// Use centralized service registry for autocompletion
			serviceManager := shared.GetGlobalServiceManager()
			workers := serviceManager.GetServiceWorkersForUpdate()
			var services []string
			for _, w := range workers {
				services = append(services, w.ServiceName)
			}
			return services, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			// Extend timeout if specified
			if timeout > 0 {
				logger.Info("  Extending operation timeout",
					zap.Duration("requested_timeout", timeout),
					zap.String("reason", "service update operations can take significant time"))

				// Set environment variable for global watchdog extension
				// Note: This only affects subprocess calls, not the current process
				originalTimeout := os.Getenv("EOS_GLOBAL_TIMEOUT")
				os.Setenv("EOS_GLOBAL_TIMEOUT", timeout.String())
				defer func() {
					if originalTimeout == "" {
						os.Unsetenv("EOS_GLOBAL_TIMEOUT")
					} else {
						os.Setenv("EOS_GLOBAL_TIMEOUT", originalTimeout)
					}
				}()

				logger.Warn("  Global watchdog timeout cannot be extended for current process",
					zap.Duration("global_watchdog", 3*time.Minute),
					zap.Duration("requested_timeout", timeout),
					zap.String("suggestion", "Use shorter operations or split into multiple commands if timeout is exceeded"))

				// Create new context with extended timeout for the command operations
				ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
				defer cancel()
				rc.Ctx = ctx
			}

			logger.Info("Starting Delphi services update",
				zap.Bool("all", all),
				zap.Bool("dry_run", dryRun),
				zap.Bool("skip_backup", skipBackup),
				zap.Bool("skip_restart", skipRestart),
				zap.Duration("timeout", timeout))

			// Use centralized service management
			serviceManager := shared.GetGlobalServiceManager()

			// Phase 0.1: Check for zombie services first (critical safety check)
			logger.Info(" Phase 0.1: Zombie service detection",
				zap.String("phase", "zombie-check"))

			lifecycleManager := shared.GetGlobalServiceLifecycleManager()
			zombieServices, err := lifecycleManager.DetectZombieServices(rc.Ctx)
			if err != nil {
				logger.Warn("Failed to check for zombie services",
					zap.Error(err))
			} else if len(zombieServices) > 0 {
				logger.Error(" DANGER: Zombie services detected - update aborted",
					zap.Int("zombie_count", len(zombieServices)),
					zap.String("reason", "zombie services can cause systemd loops and system instability"))

				for _, zombie := range zombieServices {
					logger.Error(" Zombie service found",
						zap.String("service", zombie.ServiceName),
						zap.Int("pid", zombie.PID),
						zap.String("problem", "running without unit file"))
				}

				logger.Error(" Service update cannot proceed with zombie services present")
				logger.Info(" To fix this issue:")
				logger.Info("  1. Run: eos delphi services cleanup --dry-run")
				logger.Info("  2. Then: eos delphi services cleanup --auto-fix")
				logger.Info("  3. Finally retry: eos delphi services update --all")

				return fmt.Errorf("zombie services detected - clean up required before update can proceed")
			} else {
				logger.Info(" No zombie services detected - safe to proceed")
			}

			// Phase 0.2: Check for missing services and offer installation (if not skipped)
			if !skipInstallationCheck {
				logger.Info(" Phase 0: Service installation verification",
					zap.String("phase", "pre-check"))

				missingServices, err := serviceManager.GetServicesRequiringInstallation(rc.Ctx)
				if err != nil {
					logger.Warn("Failed to check service installation status",
						zap.Error(err))
				} else if len(missingServices) > 0 {
					logger.Info(" Detected services requiring installation",
						zap.Int("missing_count", len(missingServices)))

					servicesToInstall, err := serviceManager.PromptForServiceInstallation(rc.Ctx, missingServices)
					if err != nil {
						return fmt.Errorf("failed to determine services to install: %w", err)
					}

					if len(servicesToInstall) > 0 {
						logger.Info(" Installing missing services automatically")
						if err := serviceManager.AutoInstallServices(rc.Ctx, servicesToInstall); err != nil {
							return fmt.Errorf("failed to auto-install services: %w", err)
						}
						logger.Info(" Service installation completed")
					}
				}
			} else {
				logger.Info("⏭️  Skipping service installation check",
					zap.String("reason", "skip-installation-check flag enabled"),
					zap.String("note", "assuming all required services are already installed"))
			}

			// Get all service workers from centralized registry
			allWorkers := serviceManager.GetServiceWorkersForUpdate()

			// Determine which workers to update
			var workersToUpdate []shared.ServiceWorkerInfo
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
						workersToUpdate = []shared.ServiceWorkerInfo{worker}
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
	cmd.Flags().BoolVar(&skipInstallationCheck, "skip-installation-check", false, "Skip checking if services need installation (faster, assumes services are installed)")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "Operation timeout (default 10m, set to 0 to use global 3m timeout)")

	return cmd
}

func updateServiceWorkers(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, workers []shared.ServiceWorkerInfo, dryRun, skipBackup, skipRestart bool) error {
	logger.Info(" Starting enhanced service update process",
		zap.Int("worker_count", len(workers)),
		zap.Bool("dry_run", dryRun),
		zap.Bool("backup_enabled", !skipBackup),
		zap.Bool("restart_enabled", !skipRestart),
		zap.String("phase", "initialization"))

	overallStart := time.Now()

	logger.Info(" Update process configuration",
		zap.String("mode", func() string {
			if dryRun {
				return "DRY_RUN"
			}
			return "LIVE"
		}()),
		zap.String("backup_policy", func() string {
			if skipBackup {
				return "SKIP"
			}
			return "ENABLED"
		}()),
		zap.String("restart_policy", func() string {
			if skipRestart {
				return "SKIP"
			}
			return "ENHANCED_VISIBILITY"
		}()))

	// Phase 1: Pre-flight checks
	logger.Info(" Phase 1: Pre-flight validation",
		zap.String("phase", "pre-flight"),
		zap.Int("services_to_check", len(workers)))

	preflightStart := time.Now()

	for i, worker := range workers {
		logger.Info(" Validating service",
			zap.String("service", worker.ServiceName),
			zap.Int("progress", i+1),
			zap.Int("total", len(workers)))

		// Check source file exists
		if !fileExists(worker.SourcePath) {
			return fmt.Errorf("source file not found: %s", worker.SourcePath)
		}

		// Check target directory exists
		targetDir := filepath.Dir(worker.TargetPath)
		if !fileExists(targetDir) {
			// Attempt to create the target directory if it doesn't exist
			logger.Info("📁 Target directory does not exist, creating it",
				zap.String("directory", targetDir))
			if err := os.MkdirAll(targetDir, 0755); err != nil {
				return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
			}
		}

		logger.Info(" Pre-flight check passed",
			zap.String("service", worker.ServiceName),
			zap.String("source", worker.SourcePath),
			zap.String("target", worker.TargetPath))
	}

	logger.Info(" Phase 1 completed: Pre-flight validation",
		zap.Duration("duration", time.Since(preflightStart)),
		zap.Int("services_validated", len(workers)))

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

		// Step 1: Backup existing Python worker file if it exists and backup is not skipped
		if !skipBackup && fileExists(worker.TargetPath) {
			logger.Info("Creating Python worker backup",
				zap.String("source", worker.TargetPath),
				zap.String("backup", worker.BackupPath))

			if err := copyFile(worker.TargetPath, worker.BackupPath); err != nil {
				return fmt.Errorf("failed to backup %s: %w", worker.ServiceName, err)
			}

			logger.Info("Python worker backup created",
				zap.String("backup_path", worker.BackupPath))
		}

		// Step 1.5: Backup systemd service file if it exists and backup is not skipped
		if !skipBackup {
			serviceFilePath := fmt.Sprintf("/etc/systemd/system/%s.service", worker.ServiceName)
			if fileExists(serviceFilePath) {
				// Extract timestamp from worker.BackupPath to use the same timestamp for service file
				timestamp := extractTimestampFromBackupPath(worker.BackupPath)
				serviceBackupPath := fmt.Sprintf("%s.%s.bak", serviceFilePath, timestamp)

				logger.Info("Creating systemd service backup",
					zap.String("source", serviceFilePath),
					zap.String("backup", serviceBackupPath))

				if err := copyFile(serviceFilePath, serviceBackupPath); err != nil {
					logger.Warn("Failed to backup systemd service file (continuing)",
						zap.String("service", worker.ServiceName),
						zap.String("service_file", serviceFilePath),
						zap.Error(err))
				} else {
					logger.Info("Systemd service backup created",
						zap.String("backup_path", serviceBackupPath))
				}
			}
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

		// Add to restart list if service exists using centralized service manager
		serviceManager := shared.GetGlobalServiceManager()
		if serviceManager.CheckServiceExists(worker.ServiceName) {
			servicesToRestart = append(servicesToRestart, worker.ServiceName)
		} else {
			logger.Warn("Service unit file not found, skipping restart",
				zap.String("service", worker.ServiceName),
				zap.String("suggestion", "Run 'eos delphi services create "+worker.ServiceName+"' to install the service"))
		}
	}

	// Phase 3: Enhanced service restart
	if !skipRestart && len(servicesToRestart) > 0 {
		logger.Info(" Phase 3: Enhanced service restart",
			zap.String("phase", "restart"),
			zap.Strings("services", servicesToRestart),
			zap.Int("services_to_restart", len(servicesToRestart)),
			zap.String("restart_mode", "enhanced_visibility"))

		restartPhaseStart := time.Now()

		for _, service := range servicesToRestart {
			logger.Info(" Preparing enhanced service restart",
				zap.String("service", service),
				zap.String("enhanced_features", "real-time logs, state monitoring, graceful stop analysis"))

			if err := eos_unix.RestartSystemdUnitWithVisibility(rc.Ctx, service, 3, 2); err != nil {
				logger.Error(" Enhanced service restart failed",
					zap.String("service", service),
					zap.Error(err))
				return fmt.Errorf("failed to restart %s: %w", service, err)
			}

			logger.Info(" Enhanced service restart completed",
				zap.String("service", service))
		}

		logger.Info(" Phase 3 completed: Enhanced service restart",
			zap.Duration("restart_phase_duration", time.Since(restartPhaseStart)),
			zap.Int("services_restarted", len(servicesToRestart)))
	}

	// Phase 4: Service verification
	if !skipRestart && len(servicesToRestart) > 0 {
		logger.Info(" Phase 4: Service health verification",
			zap.String("phase", "verification"),
			zap.Int("services_to_verify", len(servicesToRestart)))

		verificationStart := time.Now()

		healthyServices := 0
		for _, service := range servicesToRestart {
			// Check if this is a oneshot service
			isOneshot, err := isOneshotService(service)
			if err != nil {
				logger.Warn("Could not determine service type, using standard check",
					zap.String("service", service),
					zap.Error(err))
				isOneshot = false
			}

			var checkErr error
			if isOneshot {
				// For oneshot services, check the exit code rather than active state
				checkErr = checkOneshotServiceHealth(rc.Ctx, service)
				if checkErr != nil {
					logger.Warn("  Oneshot service health check failed",
						zap.String("service", service),
						zap.String("service_type", "oneshot"),
						zap.Error(checkErr))
				} else {
					logger.Info(" Oneshot service health check passed",
						zap.String("service", service),
						zap.String("service_type", "oneshot"),
						zap.String("status", "completed successfully"))
					healthyServices++
				}
			} else {
				// For regular services, use the standard active state check
				checkErr = eos_unix.CheckServiceStatus(rc.Ctx, service)
				if checkErr != nil {
					logger.Warn("  Service health check failed",
						zap.String("service", service),
						zap.String("service_type", "standard"),
						zap.Error(checkErr))
				} else {
					logger.Info(" Service health check passed",
						zap.String("service", service),
						zap.String("service_type", "standard"),
						zap.String("status", "active"))
					healthyServices++
				}
			}

			if checkErr != nil {
				logger.Info(" Troubleshooting suggestion",
					zap.String("service", service),
					zap.String("command", "eos delphi services logs"),
					zap.String("alt_command", fmt.Sprintf("journalctl -u %s -f", service)))
			}
		}

		logger.Info(" Phase 4 completed: Service health verification",
			zap.Duration("verification_duration", time.Since(verificationStart)),
			zap.Int("services_verified", len(servicesToRestart)),
			zap.Int("healthy_services", healthyServices),
			zap.Int("unhealthy_services", len(servicesToRestart)-healthyServices))
	}

	logger.Info(" Service worker update completed successfully",
		zap.Int("workers_updated", len(workers)),
		zap.Int("services_restarted", len(servicesToRestart)),
		zap.Duration("total_duration", time.Since(overallStart)),
		zap.String("phase", "completion"))

	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// extractTimestampFromBackupPath extracts the timestamp from a backup path like "/path/file.20250701_212225.bak"
func extractTimestampFromBackupPath(backupPath string) string {
	// Find the last occurrence of a timestamp pattern in the backup path
	// Expected format: filename.YYYYMMDD_HHMMSS.bak
	parts := strings.Split(filepath.Base(backupPath), ".")
	if len(parts) >= 3 {
		// Look for the timestamp part (should be second to last before .bak)
		timestampPart := parts[len(parts)-2]
		// Validate it looks like a timestamp (YYYYMMDD_HHMMSS)
		if len(timestampPart) == 15 && strings.Contains(timestampPart, "_") {
			return timestampPart
		}
	}
	// Fallback: generate new timestamp if we can't extract one
	return time.Now().Format("20060102_150405")
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

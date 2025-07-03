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
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/cmd_helpers"

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

// In the command function:
func updateServiceWorkers(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, workersToUpdate []shared.ServiceWorkerInfo, dryRun, skipBackup, skipRestart bool) error {
    // Create file service container
    fileContainer, err := cmd_helpers.NewFileServiceContainer(rc)
    if err != nil {
        return fmt.Errorf("failed to initialize file operations: %w", err)
    }
    
    // Process each worker
    for _, worker := range workersToUpdate {
        logger.Info("Processing service worker", 
            zap.String("service", worker.ServiceName),
            zap.Bool("dry_run", dryRun))
        
        if dryRun {
            logger.Info("Would update service worker", zap.String("service", worker.ServiceName))
            continue
        }
        
        // Check if source file exists
        if !fileContainer.FileExists(worker.SourcePath) {
            return fmt.Errorf("source file not found: %s", worker.SourcePath)
        }
        
        // Create backup if not skipped
        if !skipBackup {
            if err := fileContainer.CopyFile(worker.TargetPath, worker.BackupPath); err != nil {
                return fmt.Errorf("failed to backup %s: %w", worker.ServiceName, err)
            }
        }
        
        // Deploy updated file
        if err := fileContainer.CopyFileWithBackup(worker.SourcePath, worker.TargetPath); err != nil {
            return fmt.Errorf("failed to deploy updated %s: %w", worker.ServiceName, err)
        }
        
        logger.Info("Successfully updated service worker", zap.String("service", worker.ServiceName))
    }
    
    return nil
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
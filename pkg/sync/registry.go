// pkg/sync/registry.go
package sync

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// connectorRegistry holds all registered service connectors
var connectorRegistry = make(map[string]ServiceConnector)

// RegisterConnector registers a service connector in the global registry
func RegisterConnector(connector ServiceConnector) {
	connectorRegistry[connector.ServicePair()] = connector
}

// GetConnector retrieves a connector for the given service pair
func GetConnector(servicePair string) (ServiceConnector, error) {
	connector, exists := connectorRegistry[servicePair]
	if !exists {
		return nil, fmt.Errorf("no connector registered for service pair: %s", servicePair)
	}
	return connector, nil
}

// ListConnectors returns all registered service pairs
func ListConnectors() []string {
	pairs := make([]string, 0, len(connectorRegistry))
	for pair := range connectorRegistry {
		pairs = append(pairs, pair)
	}
	return pairs
}

// ExecuteSync executes the full synchronization workflow using the provided connector
func ExecuteSync(rc *eos_io.RuntimeContext, connector ServiceConnector, config *SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Initialize operation context for tracking and correlation
	rc.Operation = eos_io.NewSyncOperationContext(config.Service1, config.Service2)
	startTime := rc.Operation.StartTime

	logger.Info("Sync operation initialized",
		zap.String("operation_id", rc.Operation.OperationID),
		zap.String("connector", connector.Name()),
		zap.String("service_pair", connector.ServicePair()),
		zap.String("service1", config.Service1),
		zap.String("service2", config.Service2),
		zap.Bool("dry_run", config.DryRun),
		zap.Bool("force", config.Force),
		zap.Bool("skip_backup", config.SkipBackup),
		zap.Bool("skip_health_check", config.SkipHealthCheck))

	// ASSESS: Pre-flight checks
	rc.Operation.SetPhase(rc, "ASSESS")
	preflightStart := time.Now()

	logger.Info("[ASSESS] Pre-flight check phase starting")
	if err := connector.PreflightCheck(rc, config); err != nil {
		rc.Operation.LogError(rc, err, "PreflightCheck()")
		return fmt.Errorf("pre-flight check failed: %w", err)
	}

	rc.Operation.LogTiming(rc, "preflight_checks", preflightStart)
	logger.Info("[ASSESS] Pre-flight checks completed")

	// Check current connection state
	connStateStart := time.Now()
	logger.Info("[ASSESS] Connection state assessment starting")

	state, err := connector.CheckConnection(rc, config)
	if err != nil {
		rc.Operation.LogError(rc, err, "CheckConnection()")
		return fmt.Errorf("failed to check connection state: %w", err)
	}

	rc.Operation.LogTiming(rc, "check_connection_state", connStateStart)
	logger.Info("[ASSESS] Connection state determined",
		zap.Bool("connected", state.Connected),
		zap.Bool("healthy", state.Healthy),
		zap.String("reason", state.Reason),
		zap.Bool("will_skip", state.Connected && !config.Force))

	// Skip if already connected (unless forced)
	if state.Connected && !config.Force {
		logger.Info("Services already connected (use --force to reconnect)")
		rc.Operation.LogCompletion(rc, true, "Already connected - no action needed")
		return nil
	}

	// Dry-run mode: Show what would be done
	if config.DryRun {
		logger.Info("================================================================================")
		logger.Info("DRY RUN MODE - No changes will be made")
		logger.Info("================================================================================")
		logger.Info("")
		logger.Info("Would perform the following actions:",
			zap.String("operation_id", rc.Operation.OperationID),
			zap.Strings("planned_actions", []string{
				"Backup service configurations",
				"Configure services to connect",
				"Restart services if needed",
				"Verify connectivity",
			}))
		logger.Info("  1. Backup service configurations")
		logger.Info("  2. Configure services to connect")
		logger.Info("  3. Restart services if needed")
		logger.Info("  4. Verify connectivity")
		logger.Info("")
		logger.Info("Run without --dry-run to apply changes")
		rc.Operation.LogCompletion(rc, true, "Dry-run completed - no changes made")
		return nil
	}

	// INTERVENE: Backup configurations (unless skipped)
	rc.Operation.SetPhase(rc, "INTERVENE")

	var backup *BackupMetadata
	if !config.SkipBackup {
		backupStart := time.Now()
		logger.Info("[INTERVENE] Backup phase starting",
			zap.Bool("skip_backup", false))

		backup, err = connector.Backup(rc, config)
		if err != nil {
			rc.Operation.LogError(rc, err, "Backup()")
			return fmt.Errorf("backup failed: %w", err)
		}

		rc.Operation.LogTiming(rc, "backup_configurations", backupStart)
		logger.Info("[INTERVENE] Backup completed",
			zap.String("backup_dir", backup.BackupDir))
	} else {
		logger.Warn("[INTERVENE] Skipping configuration backup",
			zap.Bool("skip_backup", true),
			zap.String("reason", "--skip-backup flag set"))
	}

	// INTERVENE: Connect services
	connectStart := time.Now()
	logger.Info("[INTERVENE] Connection phase starting")

	if err := connector.Connect(rc, config); err != nil {
		rc.Operation.LogError(rc, err, "Connect()")
		logger.Error("[INTERVENE] Connection failed, attempting rollback",
			zap.Error(err),
			zap.Duration("elapsed_before_failure", time.Since(connectStart)))

		if backup != nil {
			rollbackStart := time.Now()
			logger.Info("[INTERVENE] Rollback phase starting")

			if rollbackErr := connector.Rollback(rc, config, backup); rollbackErr != nil {
				rc.Operation.LogError(rc, rollbackErr, "Rollback()")
				logger.Error("[INTERVENE] Rollback failed",
					zap.Error(rollbackErr),
					zap.Duration("rollback_duration", time.Since(rollbackStart)))
				return fmt.Errorf("connection failed and rollback failed: %w (rollback error: %v)", err, rollbackErr)
			}

			rc.Operation.LogTiming(rc, "rollback", rollbackStart)
			logger.Info("[INTERVENE] Successfully rolled back changes")
		}
		return fmt.Errorf("connection failed: %w", err)
	}

	rc.Operation.LogTiming(rc, "connect_services", connectStart)
	logger.Info("[INTERVENE] Services connected successfully")

	// EVALUATE: Verify connection (unless skipped)
	rc.Operation.SetPhase(rc, "EVALUATE")

	if !config.SkipHealthCheck {
		verifyStart := time.Now()
		logger.Info("[EVALUATE] Verification phase starting")

		if err := connector.Verify(rc, config); err != nil {
			rc.Operation.LogError(rc, err, "Verify()")
			logger.Error("[EVALUATE] Verification failed, attempting rollback",
				zap.Error(err),
				zap.Duration("elapsed_before_failure", time.Since(verifyStart)))

			if backup != nil {
				rollbackStart := time.Now()
				logger.Info("[EVALUATE] Rollback phase starting")

				if rollbackErr := connector.Rollback(rc, config, backup); rollbackErr != nil {
					rc.Operation.LogError(rc, rollbackErr, "Rollback()")
					logger.Error("[EVALUATE] Rollback failed",
						zap.Error(rollbackErr),
						zap.Duration("rollback_duration", time.Since(rollbackStart)))
					return fmt.Errorf("verification failed and rollback failed: %w (rollback error: %v)", err, rollbackErr)
				}

				rc.Operation.LogTiming(rc, "rollback", rollbackStart)
				logger.Info("[EVALUATE] Successfully rolled back changes")
			}
			return fmt.Errorf("verification failed: %w", err)
		}

		rc.Operation.LogTiming(rc, "verify_connection", verifyStart)
		logger.Info("[EVALUATE] Connection verified successfully")
	} else {
		logger.Warn("[EVALUATE] Skipping connection verification",
			zap.Bool("skip_health_check", true),
			zap.String("reason", "--skip-health-check flag set"))
	}

	// Final completion logging
	rc.Operation.LogCompletion(rc, true, "Sync operation completed successfully")
	logger.Info("Sync operation total timing",
		zap.Duration("total_elapsed", time.Since(startTime)))

	return nil
}

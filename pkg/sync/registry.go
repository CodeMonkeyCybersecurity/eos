// pkg/sync/registry.go
package sync

import (
	"fmt"

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

	logger.Info("Executing sync workflow",
		zap.String("connector", connector.Name()),
		zap.String("service_pair", connector.ServicePair()))

	// ASSESS: Pre-flight checks
	logger.Info("Running pre-flight checks")
	if err := connector.PreflightCheck(rc, config); err != nil {
		return fmt.Errorf("pre-flight check failed: %w", err)
	}
	logger.Info("Pre-flight checks passed")

	// Check current connection state
	logger.Info("Checking current connection state")
	state, err := connector.CheckConnection(rc, config)
	if err != nil {
		return fmt.Errorf("failed to check connection state: %w", err)
	}

	logger.Info("Current connection state",
		zap.Bool("connected", state.Connected),
		zap.Bool("healthy", state.Healthy),
		zap.String("reason", state.Reason))

	// Skip if already connected (unless forced)
	if state.Connected && !config.Force {
		logger.Info("Services already connected (use --force to reconnect)")
		return nil
	}

	// Dry-run mode: Show what would be done
	if config.DryRun {
		logger.Info("================================================================================")
		logger.Info("DRY RUN MODE - No changes will be made")
		logger.Info("================================================================================")
		logger.Info("")
		logger.Info("Would perform the following actions:")
		logger.Info("  1. Backup service configurations")
		logger.Info("  2. Configure services to connect")
		logger.Info("  3. Restart services if needed")
		logger.Info("  4. Verify connectivity")
		logger.Info("")
		logger.Info("Run without --dry-run to apply changes")
		return nil
	}

	// INTERVENE: Backup configurations (unless skipped)
	var backup *BackupMetadata
	if !config.SkipBackup {
		logger.Info("Backing up service configurations")
		backup, err = connector.Backup(rc, config)
		if err != nil {
			return fmt.Errorf("backup failed: %w", err)
		}
		logger.Info("Backup completed",
			zap.String("backup_dir", backup.BackupDir))
	} else {
		logger.Warn("Skipping configuration backup (--skip-backup)")
	}

	// INTERVENE: Connect services
	logger.Info("Connecting services")
	if err := connector.Connect(rc, config); err != nil {
		logger.Error("Connection failed, attempting rollback", zap.Error(err))
		if backup != nil {
			if rollbackErr := connector.Rollback(rc, config, backup); rollbackErr != nil {
				logger.Error("Rollback failed", zap.Error(rollbackErr))
				return fmt.Errorf("connection failed and rollback failed: %w (rollback error: %v)", err, rollbackErr)
			}
			logger.Info("Successfully rolled back changes")
		}
		return fmt.Errorf("connection failed: %w", err)
	}
	logger.Info("Services connected successfully")

	// EVALUATE: Verify connection (unless skipped)
	if !config.SkipHealthCheck {
		logger.Info("Verifying connection")
		if err := connector.Verify(rc, config); err != nil {
			logger.Error("Verification failed, attempting rollback", zap.Error(err))
			if backup != nil {
				if rollbackErr := connector.Rollback(rc, config, backup); rollbackErr != nil {
					logger.Error("Rollback failed", zap.Error(rollbackErr))
					return fmt.Errorf("verification failed and rollback failed: %w (rollback error: %v)", err, rollbackErr)
				}
				logger.Info("Successfully rolled back changes")
			}
			return fmt.Errorf("verification failed: %w", err)
		}
		logger.Info("Connection verified successfully")
	} else {
		logger.Warn("Skipping connection verification (--skip-health-check)")
	}

	return nil
}

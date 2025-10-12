package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lib/pq"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WatchAlerts watches alerts table for real-time changes
// Migrated from cmd/read/pipeline_alerts.go watchAlerts
func WatchAlerts(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, limit, refresh int) error {
	// ASSESS - Prepare alerts monitoring
	logger.Info(" Assessing alerts monitoring setup",
		zap.Int("limit", limit),
		zap.Int("refresh_seconds", refresh))

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Get database connection string from environment for listener
	connStr := os.Getenv("AGENTS_PG_DSN")
	if connStr == "" {
		return fmt.Errorf("AGENTS_PG_DSN environment variable required for notifications")
	}

	// INTERVENE - Create PostgreSQL listener for real-time notifications
	logger.Debug("Creating PostgreSQL notification listener",
		zap.String("connection", "AGENTS_PG_DSN"))

	// Create a listener for PostgreSQL notifications
	listener := pq.NewListener(connStr, 10*time.Second, time.Minute, func(ev pq.ListenerEventType, err error) {
		if err != nil {
			logger.Error("PostgreSQL listener error", zap.Error(err))
		}
	})
	defer func() {
		if err := listener.Close(); err != nil {
			logger.Error("🔌 Failed to close PostgreSQL listener", zap.Error(err))
		}
	}()

	// Listen for new alert notifications
	err := listener.Listen("new_alert")
	if err != nil {
		return fmt.Errorf("failed to listen for new_alert notifications: %w", err)
	}

	// Listen for alert response notifications
	err = listener.Listen("new_response")
	if err != nil {
		return fmt.Errorf("failed to listen for new_response notifications: %w", err)
	}

	// Listen for alert sent notifications
	err = listener.Listen("alert_sent")
	if err != nil {
		return fmt.Errorf("failed to listen for alert_sent notifications: %w", err)
	}

	logger.Info("📡 Listening for database notifications...")

	// Initial display
	DisplayAlerts(ctx, logger, db, limit)

	// Create ticker for periodic refresh
	ticker := time.NewTicker(time.Duration(refresh) * time.Second)
	defer ticker.Stop()

	// EVALUATE - Monitor alerts with real-time updates
	for {
		select {
		case <-ctx.Done():
			logger.Info(" Context cancelled, stopping alerts watch")
			return nil

		case sig := <-sigChan:
			logger.Info(" Received signal, stopping alerts watch", zap.String("signal", sig.String()))
			return nil

		case notification := <-listener.Notify:
			if notification != nil {
				logger.Debug("📬 Received database notification",
					zap.String("channel", notification.Channel),
					zap.String("payload", notification.Extra))

				// Refresh display on notification
				DisplayAlerts(ctx, logger, db, limit)
			}

		case <-ticker.C:
			// Periodic refresh
			DisplayAlerts(ctx, logger, db, limit)
		}
	}
}

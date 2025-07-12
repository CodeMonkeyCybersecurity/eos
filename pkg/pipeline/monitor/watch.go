package monitor

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

// WatchAll watches both alerts and agents tables simultaneously
// Migrated from cmd/read/pipeline.go watchAll
func WatchAll(ctx context.Context, logger otelzap.LoggerWithCtx, db *sql.DB, alertLimit, agentLimit, refresh int) error {
	// ASSESS - Prepare real-time monitoring setup
	logger.Info("Assessing real-time monitoring setup",
		zap.Int("alert_limit", alertLimit),
		zap.Int("agent_limit", agentLimit),
		zap.Int("refresh_seconds", refresh))

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Get database connection string from environment for listener
	connStr := os.Getenv("AGENTS_PG_DSN")
	if connStr == "" {
		logger.Error("Database connection string not available for notifications")
		return fmt.Errorf("AGENTS_PG_DSN environment variable required for notifications")
	}

	// INTERVENE - Create and configure PostgreSQL listener
	logger.Debug("Setting up PostgreSQL listener for real-time notifications")

	// Create a listener for PostgreSQL notifications
	listener := pq.NewListener(connStr, 10*time.Second, time.Minute, func(ev pq.ListenerEventType, err error) {
		if err != nil {
			logger.Error("PostgreSQL listener error", zap.Error(err))
		}
	})
	defer func() {
		if err := listener.Close(); err != nil {
			logger.Error("Failed to close PostgreSQL listener", zap.Error(err))
		}
	}()

	// Listen for alert-related notifications
	channels := []string{"new_alert", "new_response", "alert_sent"}
	for _, channel := range channels {
		err := listener.Listen(channel)
		if err != nil {
			logger.Error("Failed to listen for notifications",
				zap.String("channel", channel),
				zap.Error(err))
			return fmt.Errorf("failed to listen for %s notifications: %w", channel, err)
		}
	}

	logger.Info("Listening for database notifications...")

	// Initial display
	DisplayAll(ctx, logger, db, alertLimit, agentLimit)

	// Create ticker for periodic refresh
	ticker := time.NewTicker(time.Duration(refresh) * time.Second)
	defer ticker.Stop()

	// EVALUATE - Start monitoring loop
	logger.Info("Real-time monitoring started successfully")

	for {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled, stopping combined watch")
			return nil

		case sig := <-sigChan:
			logger.Info("Received signal, stopping combined watch", zap.String("signal", sig.String()))
			return nil

		case notification := <-listener.Notify:
			if notification != nil {
				logger.Debug("📬 Received database notification",
					zap.String("channel", notification.Channel),
					zap.String("payload", notification.Extra))

				// Refresh display on notification
				DisplayAll(ctx, logger, db, alertLimit, agentLimit)
			}

		case <-ticker.C:
			// Periodic refresh
			DisplayAll(ctx, logger, db, alertLimit, agentLimit)
		}
	}
}

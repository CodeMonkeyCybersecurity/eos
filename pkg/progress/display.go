// pkg/progress/display.go
//
// Reusable progress display utilities for long-running operations
// Provides consistent user feedback across Eos

package progress

import (
	"context"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Operation represents a long-running operation that needs progress feedback
type Operation struct {
	Name        string // Operation name (e.g., "Pulling Docker images")
	Duration    string // Estimated duration (e.g., "5-10 minutes")
	Note        string // Optional note (e.g., "SSH may appear to hang")
	PollSeconds int    // How often to show "still working" (default: 30)
	logger      otelzap.LoggerWithCtx
	ctx         context.Context
	done        chan struct{}
}

// NewOperation creates a new progress operation
func NewOperation(ctx context.Context, name, duration string) *Operation {
	return &Operation{
		Name:        name,
		Duration:    duration,
		PollSeconds: 30, // Default: update every 30 seconds
		logger:      otelzap.Ctx(ctx),
		ctx:         ctx,
		done:        make(chan struct{}),
	}
}

// WithNote adds an optional note to the operation
func (op *Operation) WithNote(note string) *Operation {
	op.Note = note
	return op
}

// WithPollInterval sets custom poll interval in seconds
func (op *Operation) WithPollInterval(seconds int) *Operation {
	op.PollSeconds = seconds
	return op
}

// Start begins showing progress
// Call Done() when operation completes
func (op *Operation) Start() {
	op.logger.Info(op.Name,
		zap.String("estimated_duration", op.Duration))

	if op.Note != "" {
		op.logger.Info("Note: " + op.Note)
	}

	// Start background ticker for progress updates
	go op.ticker()
}

// ticker runs in background and shows "still working" messages
func (op *Operation) ticker() {
	ticker := time.NewTicker(time.Duration(op.PollSeconds) * time.Second)
	defer ticker.Stop()

	elapsed := 0
	for {
		select {
		case <-op.done:
			return
		case <-ticker.C:
			elapsed += op.PollSeconds
			op.logger.Info("Progress update",
				zap.String("status", "still working"),
				zap.Int("elapsed_seconds", elapsed),
				zap.String("operation", op.Name))
		}
	}
}

// Done stops the progress display
func (op *Operation) Done() {
	close(op.done)
	op.logger.Info("Operation completed",
		zap.String("operation", op.Name))
}

// ShowPercentage is a helper for operations with known progress (like downloads)
// Call this from your progress callback
func ShowPercentage(ctx context.Context, operation string, percent int64, status string) {
	logger := otelzap.Ctx(ctx)

	// Only log at 10% intervals to avoid spam
	if percent%10 == 0 {
		logger.Info("Download progress",
			zap.Int64("percent", percent),
			zap.String("status", status),
			zap.String("operation", operation))
	}
}

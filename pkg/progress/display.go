// pkg/progress/display.go
//
// Reusable progress display utilities for long-running operations
// Provides consistent user feedback across Eos

package progress

import (
	"context"
	"sync"
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

// PercentageTracker tracks percentage progress and only logs when it changes
// This prevents log spam when progress callbacks fire multiple times at same percentage
type PercentageTracker struct {
	mu          sync.Mutex
	lastLogged  int64
	logInterval int64 // Log every N percent (default: 10)
	operation   string
	ctx         context.Context
}

// NewPercentageTracker creates a progress tracker that deduplicates logs
func NewPercentageTracker(ctx context.Context, operation string) *PercentageTracker {
	return &PercentageTracker{
		lastLogged:  -1, // Never logged yet
		logInterval: 10, // Log every 10%
		operation:   operation,
		ctx:         ctx,
	}
}

// WithInterval sets custom log interval (e.g., 5 for every 5%)
func (pt *PercentageTracker) WithInterval(interval int64) *PercentageTracker {
	pt.logInterval = interval
	return pt
}

// Update logs progress only when percentage crosses a log interval boundary
// Example: With interval=10, logs at 0%, 10%, 20%... but NOT multiple times at 10%
func (pt *PercentageTracker) Update(percent int64, status string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	logger := otelzap.Ctx(pt.ctx)

	// Calculate which interval bucket this percentage falls into
	// Example: percent=23 with interval=10 -> bucket=20
	bucket := (percent / pt.logInterval) * pt.logInterval

	// Only log if we've crossed into a new bucket
	if bucket != pt.lastLogged {
		logger.Info("Download progress",
			zap.Int64("percent", percent),
			zap.String("status", status),
			zap.String("operation", pt.operation))
		pt.lastLogged = bucket
	}
}

// ShowPercentage is a helper for operations with known progress (like downloads)
// DEPRECATED: Use NewPercentageTracker().Update() instead to avoid log spam
// This function has no state and will spam logs when called repeatedly at same percentage
func ShowPercentage(ctx context.Context, operation string, percent int64, status string) {
	logger := otelzap.Ctx(ctx)

	// Only log at 10% intervals to avoid spam
	// WARNING: This still logs on EVERY call when percent is multiple of 10
	if percent%10 == 0 {
		logger.Info("Download progress",
			zap.Int64("percent", percent),
			zap.String("status", status),
			zap.String("operation", operation))
	}
}

// pkg/eos_cli/signals.go
//
// Signal handling and graceful shutdown for EOS operations
// Implements proper cleanup on Ctrl-C and process termination

package eos_cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CleanupFunc is a function that performs cleanup operations
type CleanupFunc func() error

// SignalHandler manages graceful shutdown on signals
type SignalHandler struct {
	ctx          context.Context
	cancel       context.CancelFunc
	cleanupFuncs []CleanupFunc
	sigChan      chan os.Signal
	doneChan     chan struct{}
}

// NewSignalHandler creates a new signal handler
func NewSignalHandler(ctx context.Context) *SignalHandler {
	ctx, cancel := context.WithCancel(ctx)

	handler := &SignalHandler{
		ctx:          ctx,
		cancel:       cancel,
		cleanupFuncs: make([]CleanupFunc, 0),
		sigChan:      make(chan os.Signal, 1),
		doneChan:     make(chan struct{}),
	}

	// Notify on SIGINT (Ctrl-C) and SIGTERM
	signal.Notify(handler.sigChan, os.Interrupt, syscall.SIGTERM)

	// Start signal handling goroutine
	go handler.handleSignals()

	return handler
}

// RegisterCleanup adds a cleanup function to be called on shutdown
// Cleanup functions are called in REVERSE order (LIFO)
func (h *SignalHandler) RegisterCleanup(cleanup CleanupFunc) {
	h.cleanupFuncs = append(h.cleanupFuncs, cleanup)
}

// Context returns the cancellable context
// Operations should use this context to detect cancellation
func (h *SignalHandler) Context() context.Context {
	return h.ctx
}

// handleSignals waits for signals and initiates cleanup
func (h *SignalHandler) handleSignals() {
	logger := otelzap.Ctx(h.ctx)

	select {
	case sig := <-h.sigChan:
		logger.Info("Received signal, initiating cleanup",
			zap.String("signal", sig.String()))

		fmt.Fprintf(os.Stderr, "\n\n⚠️  Received %v, cleaning up...\n", sig)

		// Cancel context to stop ongoing operations
		h.cancel()

		// Perform cleanup with timeout
		if err := h.runCleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "Cleanup completed with errors: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, "✓ Cleanup complete")
		os.Exit(130) // Standard exit code for SIGINT

	case sig := <-h.sigChan:
		// Second signal - force exit
		logger.Error("Received second signal, forcing exit",
			zap.String("signal", sig.String()))

		fmt.Fprintln(os.Stderr, "\n⚠️  Received second interrupt, forcing exit!")
		os.Exit(1)
	}
}

// runCleanup executes all cleanup functions with a timeout
func (h *SignalHandler) runCleanup() error {
	logger := otelzap.Ctx(h.ctx)

	// Create cleanup context with timeout
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Channel for cleanup completion
	done := make(chan error, 1)

	go func() {
		// Execute cleanup functions in reverse order (LIFO)
		var lastErr error
		for i := len(h.cleanupFuncs) - 1; i >= 0; i-- {
			cleanup := h.cleanupFuncs[i]
			if err := cleanup(); err != nil {
				logger.Warn("Cleanup function failed",
					zap.Int("index", i),
					zap.Error(err))
				lastErr = err
			}
		}
		done <- lastErr
	}()

	// Wait for cleanup or timeout
	select {
	case err := <-done:
		return err
	case <-cleanupCtx.Done():
		logger.Error("Cleanup timed out after 5 seconds")
		return fmt.Errorf("cleanup timed out")
	}
}

// Stop gracefully stops the signal handler
// Should be called at the end of successful operations
func (h *SignalHandler) Stop() {
	signal.Stop(h.sigChan)
	close(h.sigChan)
	close(h.doneChan)
}

// WithCleanup is a helper to execute an operation with automatic cleanup
// Example:
//
//	err := eos_cli.WithCleanup(ctx, func() error {
//	    return performOperation()
//	}, cleanupFunc1, cleanupFunc2)
func WithCleanup(ctx context.Context, operation func() error, cleanupFuncs ...CleanupFunc) error {
	handler := NewSignalHandler(ctx)
	defer handler.Stop()

	// Register cleanup functions
	for _, cleanup := range cleanupFuncs {
		handler.RegisterCleanup(cleanup)
	}

	// Execute operation with cancellable context
	return operation()
}

// OperationState represents the state of an ongoing operation
// Used for recovery after crashes
type OperationState struct {
	Operation string    `json:"operation"`
	StartTime time.Time `json:"start_time"`
	Path      string    `json:"path,omitempty"`
	PID       int       `json:"pid"`
	Completed bool      `json:"completed"`
}

// SaveOperationState writes operation state to a recovery file
// This allows detecting and cleaning up incomplete operations after crashes
func SaveOperationState(state OperationState) error {
	// TODO: Implement state persistence if needed
	// For now, we rely on lock files for concurrent operation detection
	return nil
}

// CheckForIncompleteOperations looks for operations that didn't complete
// Should be called at startup to offer recovery/cleanup
func CheckForIncompleteOperations() ([]OperationState, error) {
	// TODO: Implement if state persistence is added
	return nil, nil
}

// Example usage pattern:
//
//	func runCreateRepo(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
//	    handler := eos_cli.NewSignalHandler(rc.Ctx)
//	    defer handler.Stop()
//
//	    // Register cleanup for partial operations
//	    var lockCleanup func()
//	    handler.RegisterCleanup(func() error {
//	        if lockCleanup != nil {
//	            lockCleanup()
//	        }
//	        return nil
//	    })
//
//	    // Acquire lock
//	    var err error
//	    lockCleanup, err = git.AcquireRepositoryLock(handler.Context(), path)
//	    if err != nil {
//	        return err
//	    }
//
//	    // Perform operation using handler.Context()
//	    return performOperation(handler.Context())
//	}

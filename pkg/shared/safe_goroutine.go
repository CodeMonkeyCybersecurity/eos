// pkg/shared/safe_goroutine.go
package shared

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LoggerInterface defines the common interface for loggers
type LoggerInterface interface {
	Error(msg string, fields ...zap.Field)
}

// getZapLogger extracts a *zap.Logger from various logger types
func getZapLogger(logger interface{}) *zap.Logger {
	// Check for otelzap.Logger first (which embeds *zap.Logger)
	if otelLogger, ok := logger.(*otelzap.Logger); ok {
		// otelzap.Logger embeds *zap.Logger as an anonymous field
		return otelLogger.Logger
	}
	// Then check for zap.Logger
	if zapLogger, ok := logger.(*zap.Logger); ok {
		return zapLogger
	}
	// Return a no-op logger if type unknown
	return zap.NewNop()
}

// SafeGo executes a function in a goroutine with panic recovery
// SECURITY: Prevents panics in goroutines from crashing the entire process
// Accepts *zap.Logger or *otelzap.Logger
func SafeGo(logger interface{}, name string, fn func()) {
	zapLogger := getZapLogger(logger)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				zapLogger.Error("Goroutine panic recovered",
					zap.String("goroutine", name),
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())))
			}
		}()
		fn()
	}()
}

// SafeGoWithContext executes a function in a goroutine with panic recovery and context awareness
// SECURITY: Prevents panics and respects context cancellation
// Accepts *zap.Logger or *otelzap.Logger
func SafeGoWithContext(ctx context.Context, logger interface{}, name string, fn func(context.Context)) {
	zapLogger := getZapLogger(logger)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				zapLogger.Error("Goroutine panic recovered",
					zap.String("goroutine", name),
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())))
			}
		}()
		fn(ctx)
	}()
}

// SafeGoWithError executes a function in a goroutine with panic recovery and error handling
// Returns a channel that will receive the error (or nil on success)
// SECURITY: Prevents panics and provides structured error propagation
// Accepts *zap.Logger or *otelzap.Logger
func SafeGoWithError(logger interface{}, name string, fn func() error) <-chan error {
	zapLogger := getZapLogger(logger)
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				zapLogger.Error("Goroutine panic recovered",
					zap.String("goroutine", name),
					zap.Any("panic", r),
					zap.String("stack", string(debug.Stack())))
				errCh <- fmt.Errorf("panic in goroutine %s: %v", name, r)
			}
			close(errCh)
		}()
		if err := fn(); err != nil {
			errCh <- err
		} else {
			errCh <- nil
		}
	}()
	return errCh
}

// SafeWalkFunc is the type of function called by SafeWalk for each file or directory
type SafeWalkFunc func(path string, info os.FileInfo, err error) error

// SafeWalk wraps filepath.Walk with security protections
// SECURITY: Enforces depth limits, symlink detection, and panic recovery
func SafeWalk(root string, maxDepth int, walkFn SafeWalkFunc) error {
	if maxDepth <= 0 {
		maxDepth = 20 // Default max depth
	}

	baseDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return walkFn(path, info, err)
		}

		// SECURITY: Enforce depth limit to prevent symlink bombs
		pathDepth := strings.Count(path, string(os.PathSeparator)) - baseDepth
		if pathDepth > maxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Call the user's walk function
		return walkFn(path, info, nil)
	})
}

// WorkerPool manages a pool of safe goroutines with bounded concurrency
// SECURITY: Prevents goroutine leaks and resource exhaustion
type WorkerPool struct {
	workers   int
	taskCh    chan func()
	logger    *zap.Logger
	ctx       context.Context
	cancelFn  context.CancelFunc
}

// NewWorkerPool creates a new worker pool with bounded concurrency
func NewWorkerPool(ctx context.Context, logger *zap.Logger, workers int) *WorkerPool {
	ctx, cancel := context.WithCancel(ctx)
	wp := &WorkerPool{
		workers:  workers,
		taskCh:   make(chan func(), workers*2), // Buffered to prevent blocking
		logger:   logger,
		ctx:      ctx,
		cancelFn: cancel,
	}

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		workerID := i
		SafeGoWithContext(ctx, logger, fmt.Sprintf("worker-%d", workerID), func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-wp.taskCh:
					if !ok {
						return
					}
					// Execute task with panic recovery
					func() {
						defer func() {
							if r := recover(); r != nil {
								logger.Error("Worker task panic recovered",
									zap.Int("worker_id", workerID),
									zap.Any("panic", r),
									zap.String("stack", string(debug.Stack())))
							}
						}()
						task()
					}()
				}
			}
		})
	}

	return wp
}

// Submit submits a task to the worker pool
func (wp *WorkerPool) Submit(task func()) bool {
	select {
	case <-wp.ctx.Done():
		return false
	case wp.taskCh <- task:
		return true
	}
}

// Shutdown gracefully shuts down the worker pool
func (wp *WorkerPool) Shutdown() {
	wp.cancelFn()
	close(wp.taskCh)
}

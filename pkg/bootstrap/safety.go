// pkg/bootstrap/safety.go

package bootstrap

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// BootstrapCircuitBreaker prevents repeated failed bootstrap attempts
type BootstrapCircuitBreaker struct {
	mu              sync.Mutex
	failureCount    int
	lastFailureTime time.Time
	cooldownPeriod  time.Duration
	maxFailures     int
}

// NewBootstrapCircuitBreaker creates a circuit breaker with default settings
func NewBootstrapCircuitBreaker() *BootstrapCircuitBreaker {
	return &BootstrapCircuitBreaker{
		cooldownPeriod: 5 * time.Minute,
		maxFailures:    3,
	}
}

// CanBootstrap checks if bootstrap is allowed based on recent failures
func (bcb *BootstrapCircuitBreaker) CanBootstrap() (bool, string) {
	bcb.mu.Lock()
	defer bcb.mu.Unlock()

	// If we've failed too many times recently, refuse to run
	if bcb.failureCount >= bcb.maxFailures && time.Since(bcb.lastFailureTime) < bcb.cooldownPeriod {
		remainingTime := bcb.cooldownPeriod - time.Since(bcb.lastFailureTime)
		return false, fmt.Sprintf("bootstrap failed %d times, cooling down for %v", bcb.failureCount, remainingTime.Round(time.Second))
	}

	// Reset counter if cooldown has passed
	if time.Since(bcb.lastFailureTime) > bcb.cooldownPeriod {
		bcb.failureCount = 0
	}

	return true, ""
}

// RecordFailure records a bootstrap failure
func (bcb *BootstrapCircuitBreaker) RecordFailure() {
	bcb.mu.Lock()
	defer bcb.mu.Unlock()

	bcb.failureCount++
	bcb.lastFailureTime = time.Now()
}

// RecordSuccess resets the circuit breaker
func (bcb *BootstrapCircuitBreaker) RecordSuccess() {
	bcb.mu.Lock()
	defer bcb.mu.Unlock()

	bcb.failureCount = 0
}

// BootstrapLock represents a file-based lock for bootstrap operations
type BootstrapLock struct {
	file   *os.File
	logger *zap.Logger
}

// AcquireBootstrapLock tries to acquire an exclusive lock for bootstrap
func AcquireBootstrapLock(logger *zap.Logger) (*BootstrapLock, error) {
	lockFile := "/var/run/eos-bootstrap.lock"
	
	// Ensure directory exists
	if err := os.MkdirAll("/var/run", 0755); err != nil {
		return nil, fmt.Errorf("failed to create lock directory: %w", err)
	}

	// Try to create/open lock file
	lock, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}

	// Try to acquire exclusive lock (non-blocking)
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if err == syscall.EWOULDBLOCK {
			// Read PID from lock file to provide better error message
			pidBytes, _ := os.ReadFile(lockFile)
			return nil, fmt.Errorf("bootstrap already in progress (lock held by PID %s)", string(pidBytes))
		}
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	// Write our PID to the lock file
	lock.Truncate(0)
	lock.Seek(0, 0)
	_, _ = fmt.Fprintf(lock, "%d\n", os.Getpid())
	lock.Sync()

	logger.Info("Bootstrap lock acquired", 
		zap.String("lock_file", lockFile),
		zap.Int("pid", os.Getpid()))

	return &BootstrapLock{
		file:   lock,
		logger: logger,
	}, nil
}

// Release releases the bootstrap lock
func (bl *BootstrapLock) Release() error {
	if bl.file == nil {
		return nil
	}

	bl.logger.Info("Releasing bootstrap lock")
	
	// Release the flock
	if err := syscall.Flock(int(bl.file.Fd()), syscall.LOCK_UN); err != nil {
		bl.logger.Error("Failed to release lock", zap.Error(err))
	}

	// Close the file
	if err := bl.file.Close(); err != nil {
		return fmt.Errorf("failed to close lock file: %w", err)
	}

	// Try to remove the lock file (best effort)
	_ = os.Remove("/var/run/eos-bootstrap.lock")

	return nil
}

// SafeBootstrapWrapper provides safety checks around bootstrap operations
func SafeBootstrapWrapper(ctx context.Context, logger *zap.Logger, bootstrapFunc func() error) error {
	// Check circuit breaker
	circuitBreaker := NewBootstrapCircuitBreaker()
	canRun, reason := circuitBreaker.CanBootstrap()
	if !canRun {
		return fmt.Errorf("bootstrap circuit breaker open: %s", reason)
	}

	// Acquire lock
	lock, err := AcquireBootstrapLock(logger)
	if err != nil {
		return fmt.Errorf("cannot acquire bootstrap lock: %w", err)
	}
	defer lock.Release()

	// Execute bootstrap with failure tracking
	bootstrapErr := bootstrapFunc()
	
	if bootstrapErr != nil {
		circuitBreaker.RecordFailure()
		return bootstrapErr
	}

	circuitBreaker.RecordSuccess()
	return nil
}

// CheckBootstrapSafety performs all safety checks before allowing bootstrap
func CheckBootstrapSafety(logger *zap.Logger) error {
	// Check if we're already in a bootstrap process
	if os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS") == "1" {
		return fmt.Errorf("bootstrap recursion detected via environment variable")
	}

	// Check system resources
	if err := checkSystemResources(logger); err != nil {
		return fmt.Errorf("insufficient system resources: %w", err)
	}

	return nil
}

// checkSystemResources verifies the system has enough resources for bootstrap
func checkSystemResources(logger *zap.Logger) error {
	// Check available disk space
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	availableGB := (stat.Bavail * uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	if availableGB < 2 {
		return fmt.Errorf("insufficient disk space: %d GB available, need at least 2 GB", availableGB)
	}

	logger.Info("System resources check passed",
		zap.Uint64("available_disk_gb", availableGB))

	return nil
}
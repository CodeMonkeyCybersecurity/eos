// pkg/hecate/lock.go
// File locking to prevent concurrent Caddyfile modifications

package hecate

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// LockFilePath is where the Hecate operation lock file is stored
	// RATIONALE: /var/run is standard for runtime locks, cleared on reboot
	// SECURITY: Prevents concurrent Caddyfile modifications (race conditions, data loss)
	// THREAT MODEL: Two admins running `eos update hecate --add` simultaneously
	LockFilePath = "/var/run/eos-hecate.lock"

	// LockTimeout from constants.go (FileLockTimeout = 30 * time.Second)
	// Duplicated here for package clarity
	lockTimeout = FileLockTimeout
)

// CaddyfileLock represents a file lock for Caddyfile operations
type CaddyfileLock struct {
	file *os.File
	path string
	rc   *eos_io.RuntimeContext
}

// AcquireCaddyfileLock attempts to acquire an exclusive lock for Caddyfile operations
// This prevents concurrent modifications that could corrupt the Caddyfile or cause data loss
//
// Use pattern:
//
//	lock, err := hecate.AcquireCaddyfileLock(rc)
//	if err != nil {
//	    return err
//	}
//	defer lock.Release()
//
// CRITICAL: Always defer lock.Release() immediately after acquisition
func AcquireCaddyfileLock(rc *eos_io.RuntimeContext) (*CaddyfileLock, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Acquiring Caddyfile lock",
		zap.String("lock_path", LockFilePath),
		zap.Duration("timeout", lockTimeout))

	// Try to create/open lock file
	// 0640 permissions (rw-r-----): root write, caddy group read
	file, err := os.OpenFile(LockFilePath, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}

	// Try to acquire exclusive lock with timeout
	deadline := time.Now().Add(lockTimeout)
	attemptCount := 0
	for time.Now().Before(deadline) {
		attemptCount++
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			// Lock acquired successfully
			// Write PID for debugging (shows which process holds the lock)
			_ = file.Truncate(0)
			_, _ = file.Seek(0, 0)
			_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
			_ = file.Sync()

			logger.Debug("Caddyfile lock acquired",
				zap.String("lock_path", LockFilePath),
				zap.Int("pid", os.Getpid()),
				zap.Int("attempts", attemptCount))

			return &CaddyfileLock{
				file: file,
				path: LockFilePath,
				rc:   rc,
			}, nil
		}

		// Lock held by another process - wait and retry
		if attemptCount == 1 {
			// Only log on first attempt to avoid spam
			logger.Info("Caddyfile lock held by another process, waiting...",
				zap.String("lock_path", LockFilePath),
				zap.Duration("timeout", lockTimeout))
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Timeout - lock not acquired
	_ = file.Close()

	// Read PID of lock holder for error message
	lockData, _ := os.ReadFile(LockFilePath)

	logger.Error("Timeout acquiring Caddyfile lock",
		zap.String("lock_path", LockFilePath),
		zap.Duration("timeout", lockTimeout),
		zap.String("holder_pid", string(lockData)))

	return nil, fmt.Errorf("timeout acquiring Caddyfile lock after %v\n\n"+
		"Another Hecate operation is running (PID: %s)\n"+
		"This prevents concurrent modifications that could corrupt the Caddyfile.\n\n"+
		"Wait for the operation to complete or check:\n"+
		"  ps aux | grep eos\n"+
		"  ps %s",
		lockTimeout, string(lockData), string(lockData))
}

// Release releases the Caddyfile lock
// CRITICAL: Always call this in a defer statement after acquiring the lock
func (l *CaddyfileLock) Release() error {
	if l.file == nil {
		// Already released or never acquired
		return nil
	}

	logger := otelzap.Ctx(l.rc.Ctx)

	logger.Debug("Releasing Caddyfile lock",
		zap.String("lock_path", l.path),
		zap.Int("pid", os.Getpid()))

	// Release the lock
	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	if err != nil {
		return fmt.Errorf("failed to unlock: %w", err)
	}

	// Close file
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("failed to close lock file: %w", err)
	}

	l.file = nil

	logger.Debug("Caddyfile lock released",
		zap.String("lock_path", l.path))

	return nil
}

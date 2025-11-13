// pkg/self/locking.go
//
// File locking utilities for atomic eos self-update operations
// Uses flock(2) for proper kernel-level locking that survives process crashes

package self

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateLock represents an exclusive lock on the eos binary update process
// Uses flock(2) for kernel-level locking that automatically releases on process death
type UpdateLock struct {
	lockFile string
	lockFd   int
	acquired bool
	pid      int
	rc       *eos_io.RuntimeContext
}

// AcquireUpdateLock attempts to acquire an exclusive lock for eos update
// Returns error if another update is already in progress
// Lock is automatically released when process exits (even if crashed)
func AcquireUpdateLock(rc *eos_io.RuntimeContext, binaryPath string) (*UpdateLock, error) {
	logger := otelzap.Ctx(rc.Ctx)
	lockFile := binaryPath + ".update.lock"

	logger.Debug("Attempting to acquire update lock", zap.String("lock_file", lockFile))

	// Open lock file (create if doesn't exist)
	// SECURITY: 0600 permissions - only owner can read/write
	lockFd, err := syscall.Open(lockFile, syscall.O_CREAT|syscall.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockFile, err)
	}

	// Try to acquire exclusive lock (non-blocking)
	// LOCK_EX = exclusive lock
	// LOCK_NB = non-blocking (fail immediately if lock held)
	err = syscall.Flock(lockFd, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		syscall.Close(lockFd)

		if err == syscall.EWOULDBLOCK {
			// Lock is held by another process
			// Try to read PID from lock file for debugging
			holderPID := readPIDFromLockFile(lockFile)
			if holderPID != "" {
				return nil, fmt.Errorf("another eos update is in progress (PID %s holds lock)\n"+
					"If you're sure no update is running, the lock may be stale.\n"+
					"Check process: ps aux | grep %s\n"+
					"If process is dead, remove lock: sudo rm %s",
					holderPID, holderPID, lockFile)
			}

			return nil, fmt.Errorf("another eos update is in progress\n"+
				"Wait for it to complete, or remove stale lock: sudo rm %s",
				lockFile)
		}

		return nil, fmt.Errorf("failed to acquire update lock: %w", err)
	}

	// Lock acquired successfully!
	// Write our PID to lock file for debugging (but flock is the real lock)
	currentPID := os.Getpid()
	pidBytes := []byte(fmt.Sprintf("%d\n%s\n", currentPID, time.Now().Format(time.RFC3339)))

	// Truncate file before writing
	if err := syscall.Ftruncate(lockFd, 0); err != nil {
		logger.Warn("Failed to truncate lock file", zap.Error(err))
	}

	// Write PID (best effort - not critical)
	_, _ = syscall.Write(lockFd, pidBytes)

	lock := &UpdateLock{
		lockFile: lockFile,
		lockFd:   lockFd,
		acquired: true,
		pid:      currentPID,
		rc:       rc,
	}

	logger.Info("Update lock acquired successfully",
		zap.String("lock_file", lockFile),
		zap.Int("pid", currentPID))

	return lock, nil
}

// Release releases the update lock
// Lock is automatically released when file descriptor closes
// This is safe to call multiple times
func (lock *UpdateLock) Release() error {
	if !lock.acquired {
		return nil
	}

	logger := otelzap.Ctx(lock.rc.Ctx)
	logger.Debug("Releasing update lock", zap.String("lock_file", lock.lockFile))

	// Unlock (flock automatically releases when fd closes, but be explicit)
	err := syscall.Flock(lock.lockFd, syscall.LOCK_UN)
	if err != nil {
		logger.Warn("Failed to explicitly unlock", zap.Error(err))
	}

	// Close file descriptor (this also releases flock if unlock failed)
	closeErr := syscall.Close(lock.lockFd)
	if closeErr != nil {
		logger.Warn("Failed to close lock file descriptor", zap.Error(closeErr))
	}

	// Remove lock file (best effort - not critical)
	// IMPORTANT: Don't fail if this fails - lock is already released by close()
	if err := os.Remove(lock.lockFile); err != nil && !os.IsNotExist(err) {
		logger.Debug("Failed to remove lock file (non-critical)", zap.Error(err))
	}

	lock.acquired = false

	logger.Info("Update lock released successfully", zap.Int("pid", lock.pid))
	return nil
}

// readPIDFromLockFile attempts to read the PID from a lock file
// Returns empty string if unable to read
// This is for debugging only - the flock is the actual lock mechanism
func readPIDFromLockFile(lockFile string) string {
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return ""
	}

	// First line should be the PID
	lines := string(data)
	if len(lines) > 0 {
		// Find first newline
		for i, ch := range lines {
			if ch == '\n' {
				return lines[:i]
			}
		}
		return lines
	}

	return ""
}

// CheckLockStatus checks if an update lock exists without trying to acquire it
// Returns true if lock is held, false if available
// Useful for dry-run or status checks
func CheckLockStatus(lockFile string) (bool, string, error) {
	// Try to open lock file
	lockFd, err := syscall.Open(lockFile, syscall.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			// Lock file doesn't exist - lock is available
			return false, "", nil
		}
		return false, "", fmt.Errorf("failed to open lock file: %w", err)
	}
	defer syscall.Close(lockFd)

	// Try to acquire shared lock (non-blocking)
	// LOCK_SH = shared lock (compatible with other shared locks, conflicts with exclusive lock)
	// LOCK_NB = non-blocking
	err = syscall.Flock(lockFd, syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		if err == syscall.EWOULDBLOCK {
			// Exclusive lock is held - update in progress
			holderPID := readPIDFromLockFile(lockFile + ".lock")
			return true, holderPID, nil
		}
		return false, "", fmt.Errorf("failed to check lock status: %w", err)
	}

	// Shared lock acquired - no exclusive lock exists
	// Release shared lock
	syscall.Flock(lockFd, syscall.LOCK_UN)

	return false, "", nil
}

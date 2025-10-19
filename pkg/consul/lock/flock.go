// pkg/consul/lock/flock.go
// File locking to prevent concurrent sync operations

package lock

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

const (
	lockFilePath = "/var/run/eos-consul-sync.lock"
	lockTimeout  = 30 * time.Second
)

// Lock represents a file lock
type Lock struct {
	file *os.File
	path string
}

// Acquire attempts to acquire an exclusive lock
// Prevents concurrent sync operations
func Acquire() (*Lock, error) {
	// Try to create/open lock file
	file, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}

	// Try to acquire exclusive lock with timeout
	deadline := time.Now().Add(lockTimeout)
	for time.Now().Before(deadline) {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			// Lock acquired
			// Write PID for debugging
			file.Truncate(0)
			file.Seek(0, 0)
			fmt.Fprintf(file, "%d\n", os.Getpid())
			file.Sync()

			return &Lock{
				file: file,
				path: lockFilePath,
			}, nil
		}

		// Lock held by another process - wait and retry
		time.Sleep(500 * time.Millisecond)
	}

	file.Close()

	// Read PID of lock holder
	lockData, _ := os.ReadFile(lockFilePath)

	return nil, fmt.Errorf("timeout acquiring lock after %v\n"+
		"Another 'eos sync consul' operation is running (PID: %s)\n"+
		"Wait for it to complete or check: ps aux | grep eos",
		lockTimeout, string(lockData))
}

// Release releases the lock
func (l *Lock) Release() error {
	if l.file == nil {
		return nil
	}

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

	return nil
}

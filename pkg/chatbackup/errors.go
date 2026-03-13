package chatbackup

import "errors"

var (
	// ErrResticNotInstalled indicates the `restic` binary is not available in PATH.
	ErrResticNotInstalled = errors.New("restic not installed")

	// ErrRepositoryNotInitialized indicates the target restic repository is missing config.
	ErrRepositoryNotInitialized = errors.New("repository not initialized")

	// ErrBackupAlreadyRunning indicates a lock conflict for concurrent backup attempts.
	ErrBackupAlreadyRunning = errors.New("backup already running")
)

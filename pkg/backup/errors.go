package backup

import "errors"

// ErrResticNotInstalled indicates that the restic binary could not be found.
var ErrResticNotInstalled = errors.New("restic binary not found in PATH")

// pkg/shared/vars.go

package shared

import (
	"errors"
	"sync/atomic"
)

var DefaultMarkers = []string{"80", "443"}

var (
	ErrNotTTY           = errors.New("cannot prompt: not a TTY")
	ErrFallbackUnusable = errors.New("fallback path unusable")
)

var syncedAlready atomic.Bool

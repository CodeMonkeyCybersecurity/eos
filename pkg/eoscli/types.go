// pkg/eoscli/context.go

package eoscli

import (
	"time"

	"go.uber.org/zap"
)

type RuntimeContext struct {
	Log       *zap.Logger
	StartTime time.Time
	// Add others as needed:
	// shared.VaultClient *api.Client
	// Config      *Config
}

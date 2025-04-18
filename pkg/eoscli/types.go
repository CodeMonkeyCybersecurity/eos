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
	// VaultClient *api.Client
	// Config      *Config
}

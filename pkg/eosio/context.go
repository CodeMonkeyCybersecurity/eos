package eosio

import (
	"context"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// NewRuntimeContextWithTimeout initializes RuntimeContext with a timeout.
func NewRuntimeContextWithTimeout(log *zap.Logger, timeout time.Duration) (*RuntimeContext, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return &RuntimeContext{
		Log:       log,
		Ctx:       ctx,
		Timestamp: time.Now(),
	}, cancel
}

// WithContext replaces the Go context inside RuntimeContext.
func (rc *RuntimeContext) WithContext(ctx context.Context) *RuntimeContext {
	return &RuntimeContext{
		Log:       rc.Log,
		Ctx:       ctx,
		Timestamp: rc.Timestamp,
	}
}

// Logger returns the associated zap.Logger.
func (rc *RuntimeContext) Logger() *zap.Logger {
	return rc.Log
}

// Deadline returns the context deadline, if any.
func (rc *RuntimeContext) Deadline() (time.Time, bool) {
	return rc.Ctx.Deadline()
}

// GetRuntimeContext safely retrieves the RuntimeContext from a cobra command.
func GetRuntimeContext(cmd *cobra.Command) *RuntimeContext {
	val := cmd.Context().Value(RuntimeContextKey)
	if ctx, ok := val.(*RuntimeContext); ok && ctx != nil {
		return ctx
	}
	panic("RuntimeContext missing in command — was PreRunWrapper applied?")
}

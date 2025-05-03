// pkg/eosio/runtime_context.go

package eosio

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// NewRuntimeContextWithTimeout initializes RuntimeContext with a timeout.
func NewRuntimeContextWithTimeout(timeout time.Duration) (*RuntimeContext, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return &RuntimeContext{
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

	zap.L().Fatal("RuntimeContext missing in command — was PreRunWrapper applied?")
	return nil // unreachable, but silences staticcheck
}

// ContextualLogger returns a scoped logger enriched with component and action fields.
// If base is nil, zap.L() is used. Panics if logging is uninitialized.
func ContextualLogger(skipFrames int, base *zap.Logger) *zap.Logger {
	if skipFrames <= 0 {
		skipFrames = 2
	}

	if base == nil {
		base = zap.L()
		if base == nil {
			panic("ContextualLogger: zap.L() returned nil — logger not initialized?")
		}
	}

	component, action, err := getCallContext(skipFrames)
	if err != nil {
		base.Warn("🧭 Context resolution failed", zap.Error(err))
		component, action = "unknown", "unknown"
	}

	return base.With(
		zap.String("component", component),
		zap.String("action", action),
	).Named(component)
}

// getCallContext extracts the calling package and function name.
func getCallContext(skip int) (component, action string, err error) {
	pc, file, _, ok := runtime.Caller(skip)
	if !ok {
		return "unknown", "unknown", fmt.Errorf("runtime.Caller failed")
	}

	// Infer component (directory name or filename)
	parts := strings.Split(file, "/")
	switch {
	case len(parts) >= 2:
		component = parts[len(parts)-2]
	case len(parts) == 1:
		component = strings.TrimSuffix(parts[0], ".go")
	default:
		component = "unknown"
	}

	// Infer action (function name)
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return component, "unknown", fmt.Errorf("runtime.FuncForPC failed for PC %d", pc)
	}
	funcName := fn.Name()
	funcParts := strings.Split(funcName, ".")
	action = funcParts[len(funcParts)-1]

	return component, action, nil
}

func LogRuntimeExecutionContext() {
	currentUser, err := user.Current()
	if err != nil {
		zap.L().Warn("⚠️ Failed to get current user", zap.Error(err))
	} else {
		zap.L().Info("🔎 User + UID/GID context",
			zap.String("username", currentUser.Username),
			zap.String("uid_str", currentUser.Uid),
			zap.String("gid_str", currentUser.Gid),
			zap.String("home", currentUser.HomeDir),
			zap.Int("real_uid", os.Getuid()),
			zap.Int("effective_uid", os.Geteuid()),
			zap.Int("real_gid", os.Getgid()),
			zap.Int("effective_gid", os.Getegid()),
		)
	}

	if execPath, err := os.Executable(); err != nil {
		zap.L().Warn("⚠️ Failed to resolve executable path", zap.Error(err))
	} else {
		zap.L().Info("🗂️ Executing binary", zap.String("path", execPath))
	}
}

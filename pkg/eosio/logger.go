// pkg/eosio/logger.go

package eosio

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"go.uber.org/zap"
)

// ContextualLogger returns a scoped logger enriched with component and action fields.
// If base is nil, logger.L() is used. Panics if logging is uninitialized.
func ContextualLogger(skipFrames int, base *zap.Logger) *zap.Logger {
	if skipFrames <= 0 {
		skipFrames = 2
	}

	if base == nil {
		base = logger.L()
		if base == nil {
			panic("ContextualLogger: logger.L() returned nil — logger not initialized?")
		}
	}

	component, action, err := resolveContext(skipFrames)
	if err != nil {
		base.Warn("🧭 Context resolution failed", zap.Error(err))
		component, action = "unknown", "unknown"
	}

	return base.With(
		zap.String("component", component),
		zap.String("action", action),
	).Named(component)
}

// resolveContext extracts the calling package and function name.
func resolveContext(skip int) (component, action string, err error) {
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

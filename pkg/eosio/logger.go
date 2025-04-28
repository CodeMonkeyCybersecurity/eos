package eosio

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"go.uber.org/zap"
)

// ContextualLogger returns a scoped logger enriched with component and action fields.
// You can optionally pass a base logger; if nil, the default logger.L() is used.
func ContextualLogger(skipFrames int, base *zap.Logger) *zap.Logger {
	if skipFrames <= 0 {
		skipFrames = 2
	}

	if base == nil {
		base = logger.L()
	}

	component, action, err := resolveContext(skipFrames)
	if err != nil {
		base = base.With(zap.Error(err))
	}

	if component == "" {
		component = "unknown"
	}
	if action == "" {
		action = "unknown"
	}

	l := base.With(
		zap.String("component", component),
		zap.String("action", action),
	).Named(component)

	l.Debug("🧭 Contextual logger initialized",
		zap.String("component", component),
		zap.String("action", action),
	)

	return l
}

// resolveContext extracts the caller's package and function names.
func resolveContext(skip int) (component, action string, err error) {
	pc, file, _, ok := runtime.Caller(skip)
	if !ok {
		return "", "", fmt.Errorf("runtime.Caller failed")
	}

	component, action = "unknown", "unknown"

	parts := strings.Split(file, "/")
	if len(parts) >= 2 {
		component = parts[len(parts)-2]
	} else if len(parts) == 1 {
		component = strings.TrimSuffix(parts[0], ".go")
	}

	funcObj := runtime.FuncForPC(pc)
	if funcObj == nil {
		return component, action, fmt.Errorf("runtime.FuncForPC failed")
	}

	funcName := funcObj.Name()
	funcParts := strings.Split(funcName, ".")
	if len(funcParts) > 0 {
		action = funcParts[len(funcParts)-1]
	}

	return component, action, nil
}

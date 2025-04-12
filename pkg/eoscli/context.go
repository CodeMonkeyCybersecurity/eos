/* pkg/eoscli/context.go */

package eoscli

import (
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"go.uber.org/zap"
)

// resolveContext extracts the calling package (as "component") and
// function name (as "action") to enrich log context.
func resolveContext() (component string, action string) {
	pc, file, _, ok := runtime.Caller(2) // 2 frames up to get caller of Wrap(...)
	component = "unknown"
	action = "unknown"

	if ok {
		parts := strings.Split(file, "/")
		if len(parts) > 2 {
			component = parts[len(parts)-2]
		}
		funcName := runtime.FuncForPC(pc).Name()
		funcParts := strings.Split(funcName, ".")
		if len(funcParts) > 0 {
			action = funcParts[len(funcParts)-1]
		}
	}

	return component, action
}

// contextualLogger creates a scoped logger enriched with package/function context.
func contextualLogger() *zap.Logger {
	component, action := resolveContext()
	return logger.L().Named(component).With(
		zap.String("component", component),
		zap.String("action", action),
	)
}

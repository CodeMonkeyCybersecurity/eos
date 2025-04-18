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

	if !ok {
		zap.L().Warn("Unable to resolve caller context: runtime.Caller failed")
		return
	}

	// Extract last two parts of file path to infer component (e.g., "pkg/ldap/handler.go" → "ldap")
	parts := strings.Split(file, "/")
	if len(parts) >= 2 {
		component = parts[len(parts)-2]
	} else if len(parts) == 1 {
		component = strings.TrimSuffix(parts[0], ".go")
	}

	// Resolve full function name
	funcObj := runtime.FuncForPC(pc)
	if funcObj == nil {
		zap.L().Warn("Unable to resolve function name from program counter", zap.Uintptr("pc", pc))
		return
	}
	funcName := funcObj.Name()
	funcParts := strings.Split(funcName, ".")
	if len(funcParts) > 0 {
		action = funcParts[len(funcParts)-1]
	}

	zap.L().Debug("Resolved logger context",
		zap.String("component", component),
		zap.String("action", action),
		zap.String("file", file),
		zap.String("func", funcName),
	)

	return component, action
}

// contextualLogger creates a scoped logger enriched with package/function context.
func contextualLogger() *zap.Logger {
	component, action := resolveContext()

	logger := logger.L().Named(component).With(
		zap.String("component", component),
		zap.String("action", action),
	)

	// Optional: Emit once per command for traceability
	logger.Debug("🧭 Contextual logger initialized", zap.String("component", component), zap.String("action", action))

	return logger
}

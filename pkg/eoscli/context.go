package eoscli

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// resolveContext extracts caller's package and function names.
func resolveContext(skip int) (component, action string, err error) {
	pc, file, _, ok := runtime.Caller(skip)
	if !ok {
		return "", "", fmt.Errorf("runtime.Caller failed")
	}

	// Extract component from file path
	component = "unknown"
	action = "unknown"

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

// contextualLogger creates a scoped logger enriched with package/function context.
// skipFrames is optional (default=2).
func contextualLogger(skipFrames int) *zap.Logger {
	if skipFrames <= 0 {
		skipFrames = 2
	}

	baseLogger := logger.L()
	component, action, err := resolveContext(skipFrames)
	if err != nil {
		baseLogger.Warn("Failed to resolve caller context", zap.Error(err))
	}

	if component == "" {
		component = "unknown"
	}
	if action == "" {
		action = "unknown"
	}

	l := baseLogger.With(
		zap.String("component", component),
		zap.String("action", action),
	).Named(component)

	l.Debug("🧭 Contextual logger initialized",
		zap.String("component", component),
		zap.String("action", action),
	)

	return l
}

// GetRuntimeContext safely extracts RuntimeContext from a Cobra command.
func GetRuntimeContext(cmd *cobra.Command) *RuntimeContext {
	val := cmd.Context().Value(runtimeContextKey)
	ctx, ok := val.(*RuntimeContext)
	if !ok || ctx == nil {
		panic(fmt.Sprintf("RuntimeContext missing in command [%s] — was PreRunWrapper applied?", cmd.Name()))
	}
	return ctx
}

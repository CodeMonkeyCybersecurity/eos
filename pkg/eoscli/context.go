/* pkg/eoscli/context.go
 */

package eoscli

import (
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Wrap adds automatic logger injection and scoped metadata based on calling package.
func wrap(fn func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		start := time.Now()
		log := contextualLogger()

		log.Info("Command started", zap.Time("start_time", start))
		err := fn(cmd, args)
		duration := time.Since(start)

		if err != nil {
			log.Error("Command failed", zap.Duration("duration", duration), zap.Error(err))
		} else {
			log.Info("Command completed", zap.Duration("duration", duration))
		}

		return err
	}
}

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

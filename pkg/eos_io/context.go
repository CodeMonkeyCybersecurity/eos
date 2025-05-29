// pkg/eos_io/context.go

package eos_io

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

type RuntimeContext struct {
	Ctx        context.Context
	Log        *zap.Logger
	Timestamp  time.Time
	Command    string
	Component  string
	Attributes map[string]string
	Validate   *verify.WrapValidation
}

// NewContext sets up tracing, logging and validation hooks.
func NewContext(ctx context.Context, cmdName string) *RuntimeContext {
	comp, action := resolveCallContext(3)
	baseLogger := zap.L()
	if baseLogger == nil {
		baseLogger, _ = zap.NewDevelopment()
	}
	log := baseLogger.With(zap.String("component", comp), zap.String("action", action)).Named(cmdName)
	return &RuntimeContext{
		Ctx:        ctx,
		Log:        log,
		Timestamp:  time.Now(),
		Component:  comp,
		Command:    action,
		Attributes: make(map[string]string),
	}
}

// HandlePanic recovers panics, logs them, and converts to an error.
func (rc *RuntimeContext) HandlePanic(errPtr *error) {
	if r := recover(); r != nil {
		*errPtr = cerr.AssertionFailedf("panic: %v", r)
		rc.Log.Error("panic recovered", zap.Any("panic", r))
	}
}

// ValidateAll runs struct-, CUE-, and OPA-based validation if configured.
func (rc *RuntimeContext) ValidateAll() error {
	if rc.Validate == nil {
		return nil
	}
	v := rc.Validate
	if err := verify.Struct(v.Cfg); err != nil {
		return cerr.WithHint(err, "struct validation failed")
	}
	if err := verify.ValidateYAMLWithCUE(v.SchemaPath, v.YAMLPath); err != nil {
		return cerr.WithHint(err, "CUE schema validation failed")
	}
	denies, err := verify.EnforcePolicy(rc.Ctx, v.PolicyPath, v.PolicyInput())
	if err != nil {
		return cerr.Wrap(err, "OPA policy error")
	}
	if len(denies) > 0 {
		return cerr.Newf("OPA policy denied: %v", denies)
	}
	return nil
}

// End logs outcome, emits a telemetry span with key attributes, and flushes.
func (rc *RuntimeContext) End(errPtr *error) {
	duration := time.Since(rc.Timestamp)
	success := (*errPtr == nil)
	if success {
		rc.Log.Info("Command completed", zap.Duration("duration", duration))
	} else {
		rc.Log.Error("Command failed", zap.Duration("duration", duration), zap.Error(*errPtr))
	}

	vaultAddr := rc.Attributes["vault_addr"]
	if vaultAddr == "" {
		vaultAddr = "(unavailable)"
	}

	attrs := []attribute.KeyValue{
		attribute.Bool("success", success),
		attribute.Int64("duration_ms", duration.Milliseconds()),
		attribute.String("os", runtime.GOOS),
		attribute.String("args", strings.Join(os.Args[1:], " ")),
		attribute.String("vault_addr", vaultAddr),
		attribute.String("version", shared.Version),
		attribute.String("category", classifyCommand(rc.Command)),
		attribute.String("error_type", classifyError(*errPtr)),
	}

	_, span := telemetry.Start(rc.Ctx, rc.Command, attrs...)
	span.End()

	shared.SafeSync()
}

// LogVaultContext logs the VAULT_ADDR lookup and returns the value for telemetry.
func LogVaultContext(log *zap.Logger, addr string, err error) string {
	if err != nil || addr == "" {
		log.Warn("Failed to resolve VAULT_ADDR", zap.Error(err))
		return "(unavailable)"
	}
	log.Info("VAULT_ADDR resolved", zap.String("vault_addr", addr))
	return addr
}

// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// Helper functions
// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––

func resolveCallContext(skip int) (component, action string) {
	pc, file, _, ok := runtime.Caller(skip)
	if !ok {
		return "unknown", "unknown"
	}
	parts := strings.Split(file, "/")
	component = parts[len(parts)-2]
	if fn := runtime.FuncForPC(pc); fn != nil {
		name := fn.Name()
		fields := strings.Split(name, ".")
		action = fields[len(fields)-1]
	} else {
		action = "unknown"
	}
	return
}

func classifyCommand(name string) string {
	if strings.HasPrefix(name, "create") {
		return "lifecycle"
	}
	return "general"
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	if eos_err.IsExpectedUserError(err) {
		return "user"
	}
	return "system"
}

// ContextualLogger returns a scoped logger enriched with component and action fields.
// If base is nil, otelzap.Ctx(rc.Ctx) is used. Panics if logging is uninitialized.
func ContextualLogger(rc *RuntimeContext, skipFrames int, base *zap.Logger) *zap.Logger {
	if skipFrames <= 0 {
		skipFrames = 2
	}

	var logger *zap.Logger
	if base != nil {
		logger = base
	} else if rc != nil && rc.Log != nil {
		logger = rc.Log
	} else {
		logger = zap.L()
		if logger == nil {
			logger, _ = zap.NewDevelopment()
		}
	}

	component, action, err := getCallContext(skipFrames)
	if err != nil {
		logger.Warn("🧭 Context resolution failed", zap.Error(err))
		component, action = "unknown", "unknown"
	}

	return logger.With(
		zap.String("component", component),
		zap.String("action", action),
	).Named(component)
}

func LogRuntimeExecutionContext(rc *RuntimeContext) {
	currentUser, err := user.Current()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Failed to get current user", zap.Error(err))
	} else {
		otelzap.Ctx(rc.Ctx).Info("🔎 User + UID/GID context",
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
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Failed to resolve executable path", zap.Error(err))
	} else {
		otelzap.Ctx(rc.Ctx).Info("🗂️ Executing binary", zap.String("path", execPath))
	}
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

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

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cue"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_opa"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// OperationContext tracks operation lifecycle for structured logging and correlation
type OperationContext struct {
	OperationID   string
	OperationType string
	Service       string
	Service1      string // For sync operations
	Service2      string // For sync operations
	StartTime     time.Time
	CurrentPhase  string
	Timings       map[string]time.Duration
	Errors        []error
}

type RuntimeContext struct {
	Ctx        context.Context
	Log        *zap.Logger
	Timestamp  time.Time
	Command    string
	Component  string
	Attributes map[string]string
	Validate   *verify.WrapValidation
	Operation  *OperationContext // Operation context for structured logging and tracking
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

// NewExtendedContext creates a runtime context with a custom timeout for long-running operations.
// This should only be used for commands that legitimately need extended execution time.
func NewExtendedContext(ctx context.Context, cmdName string, timeout time.Duration) *RuntimeContext {
	// Create context with extended timeout
	extendedCtx, cancel := context.WithTimeout(ctx, timeout)

	// Store cancel function in the context so it can be cleaned up
	// We'll use a custom key to avoid conflicts
	type cancelKey struct{}
	extendedCtx = context.WithValue(extendedCtx, cancelKey{}, cancel)

	comp, action := resolveCallContext(3)
	baseLogger := zap.L()
	if baseLogger == nil {
		baseLogger, _ = zap.NewDevelopment()
	}
	log := baseLogger.With(
		zap.String("component", comp),
		zap.String("action", action),
		zap.Duration("extended_timeout", timeout)).Named(cmdName)

	log.Info(" Created extended runtime context", zap.Duration("timeout", timeout))

	return &RuntimeContext{
		Ctx:        extendedCtx,
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
	if err := eos_cue.ValidateYAMLWithCUE(v.SchemaPath, v.YAMLPath); err != nil {
		return cerr.WithHint(err, "CUE schema validation failed")
	}
	denies, err := eos_opa.EnforcePolicy(rc.Ctx, v.PolicyPath, v.PolicyInput())
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
		logger.Warn(" Context resolution failed", zap.Error(err))
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
		otelzap.Ctx(rc.Ctx).Warn("Failed to get current user", zap.Error(err))
	} else {
		otelzap.Ctx(rc.Ctx).Info(" User + UID/GID context",
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
		otelzap.Ctx(rc.Ctx).Warn("Failed to resolve executable path", zap.Error(err))
	} else {
		otelzap.Ctx(rc.Ctx).Info(" Executing binary", zap.String("path", execPath))
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

// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
// OperationContext constructors and methods
// ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––

// NewOperationContext creates a new operation context for tracking operation lifecycle
func NewOperationContext(operationType, service string) *OperationContext {
	return &OperationContext{
		OperationID:   generateOperationID(),
		OperationType: operationType,
		Service:       service,
		StartTime:     time.Now(),
		CurrentPhase:  "INIT",
		Timings:       make(map[string]time.Duration),
		Errors:        []error{},
	}
}

// NewSyncOperationContext creates an operation context for sync operations between two services
func NewSyncOperationContext(service1, service2 string) *OperationContext {
	return &OperationContext{
		OperationID:   generateOperationID(),
		OperationType: "sync",
		Service1:      service1,
		Service2:      service2,
		StartTime:     time.Now(),
		CurrentPhase:  "INIT",
		Timings:       make(map[string]time.Duration),
		Errors:        []error{},
	}
}

// SetPhase updates the current phase of the operation and logs it
func (oc *OperationContext) SetPhase(rc *RuntimeContext, phase string) {
	oc.CurrentPhase = phase
	otelzap.Ctx(rc.Ctx).Info("Operation phase transition",
		zap.String("operation_id", oc.OperationID),
		zap.String("phase", phase))
}

// LogError records an error and logs it with context
func (oc *OperationContext) LogError(rc *RuntimeContext, err error, operation string) {
	oc.Errors = append(oc.Errors, err)
	otelzap.Ctx(rc.Ctx).Error("Operation error",
		zap.String("operation_id", oc.OperationID),
		zap.String("phase", oc.CurrentPhase),
		zap.String("operation", operation),
		zap.Error(err))
}

// LogTiming records the duration of a specific operation step
func (oc *OperationContext) LogTiming(rc *RuntimeContext, step string, startTime time.Time) {
	duration := time.Since(startTime)
	oc.Timings[step] = duration
	otelzap.Ctx(rc.Ctx).Debug("Operation timing",
		zap.String("operation_id", oc.OperationID),
		zap.String("step", step),
		zap.Duration("duration", duration))
}

// LogCompletion logs the final completion status of the operation
func (oc *OperationContext) LogCompletion(rc *RuntimeContext, success bool, message string) {
	totalDuration := time.Since(oc.StartTime)
	logger := otelzap.Ctx(rc.Ctx)

	if success {
		logger.Info("Operation completed successfully",
			zap.String("operation_id", oc.OperationID),
			zap.String("message", message),
			zap.Duration("total_duration", totalDuration),
			zap.Int("error_count", len(oc.Errors)))
	} else {
		logger.Error("Operation failed",
			zap.String("operation_id", oc.OperationID),
			zap.String("message", message),
			zap.Duration("total_duration", totalDuration),
			zap.Int("error_count", len(oc.Errors)))
	}
}

// generateOperationID creates a unique operation ID for tracking
func generateOperationID() string {
	return fmt.Sprintf("op-%d-%d", time.Now().Unix(), time.Now().UnixNano()%1000000)
}

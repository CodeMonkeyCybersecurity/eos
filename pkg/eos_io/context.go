// pkg/eos_io/context.go

package eos_io

import (
	"context"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_opa"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	cerr "github.com/cockroachdb/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type RuntimeContext struct {
	Ctx        context.Context
	Log        *zap.Logger
	Verify     *verify.Context
	Timestamp  time.Time
	Span       trace.Span
	Command    string
	Component  string
	Attributes map[string]string
	Validation *verify.WrapValidation
}

// NewContext sets up tracing, logging and validation hooks.
func NewContext(cmdName string) *RuntimeContext {
	ctx, span := telemetry.Start(context.Background(), cmdName)
	traceID := span.SpanContext().TraceID().String()

	comp, action := resolveCallContext(3)
	logger := zap.L().With(
		zap.String("component", comp),
		zap.String("action", action),
		zap.String("trace_id", traceID),
	).Named(comp)

	logEnv(logger)

	return &RuntimeContext{
		Ctx:        ctx,
		Span:       span,
		Log:        logger,
		Timestamp:  time.Now(), // capture start time
		Component:  comp,
		Command:    action,
		Verify:     verify.NewContext(),
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
	if rc.Verify == nil {
		return nil
	}
	return rc.ValidateConfig(
		rc.Verify.Cfg,
		rc.Verify.SchemaPath,
		rc.Verify.YAMLPath,
		rc.Verify.PolicyPath,
	)
}

// ValidateConfig executes the three-step validation pipeline.
func (rc *RuntimeContext) ValidateConfig(
	cfg interface{}, schemaPath, yamlPath, policyPath string,
) error {
	if err := rc.Verify.ValidateAll("config", cfg); err != nil {
		return cerr.WithHint(err, "struct validation failed")
	}
	if err := verify.ValidateYAMLWithCUE(schemaPath, yamlPath); err != nil {
		return cerr.WithHint(err, "CUE schema validation failed")
	}
	if err := eos_opa.Enforce(rc.Ctx, policyPath, cfg); err != nil {
		return cerr.Wrapf(err, "OPA policy %s denied", policyPath)
	}
	return nil
}

// End logs outcome, emits a telemetry span with key attributes, and flushes.
func (rc *RuntimeContext) End(errPtr *error) {
	defer rc.Span.End()

	duration := time.Since(rc.Timestamp)
	success := (*errPtr == nil)

	// 1) user‐facing log
	if success {
		rc.Log.Info("Command completed", zap.Duration("duration", duration))
	} else {
		rc.Log.Error("Command failed", zap.Duration("duration", duration), zap.Error(*errPtr))
	}

	// 2) vault_addr was written by the wrapper into Attributes
	vaultAddr := rc.Attributes["vault_addr"]
	if vaultAddr == "" {
		vaultAddr = "(unavailable)"
	}

	// 3) telemetry attributes
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

	// 4) record final span
	_, span := telemetry.Start(rc.Ctx, rc.Command, attrs...)
	span.End()

	// 5) ensure logs/telemetry are flushed
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

func logEnv(log *zap.Logger) {
	if u, err := user.Current(); err == nil {
		log.Info("user context",
			zap.String("username", u.Username),
			zap.String("uid", u.Uid),
			zap.String("gid", u.Gid),
			zap.String("home", u.HomeDir),
		)
	}
	if exe, err := os.Executable(); err == nil {
		log.Info("executable path", zap.String("path", exe))
	}
}

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

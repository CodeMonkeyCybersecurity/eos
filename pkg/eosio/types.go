// pkg/eosio/types.go

package eosio

import (
	"context"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// contextKey is an unexported type used for safely storing RuntimeContext in context.Context.
type contextKey struct {
	name string
}

// RuntimeContextKey is the key used in cobra.Command.Context() to retrieve our RuntimeContext.
// Should be unique and stable.
var RuntimeContextKey = &contextKey{"eos-runtime-context"}

// RuntimeContext holds runtime state for EOS CLI commands and helpers.
type RuntimeContext struct {
	Log        *zap.Logger     // Scoped logger for the current operation
	Ctx        context.Context // Go context (for timeouts, cancellations)
	Timestamp  time.Time       // When this context was created (for diagnostics)
	Validate   *verify.Context
	Span       trace.Span
	TraceID    string
	Command    string            // e.g., "ollama"
	Component  string            // derived from caller
	Attributes map[string]string // enriched by span
	// Optional expansion fields (prepare for future)
	// VaultAddr string
	// Username  string
	// ClusterID string
	// VaultClient *api.Client
}

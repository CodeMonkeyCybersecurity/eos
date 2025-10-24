// pkg/execute/types.go

package execute

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// ExecutionContext tells execute.Run() how to interpret exit codes
// Different operations have different semantics for the same exit code.
// Example: During removal, "service not found" (exit 5) is SUCCESS, not ERROR.
type ExecutionContext string

const (
	// ContextNormal - Standard execution (any non-zero exit = ERROR)
	ContextNormal ExecutionContext = ""

	// ContextRemoval - Removal operation ("not found" = DEBUG, actual failure = ERROR)
	// Use when: Removing packages, stopping services, deleting users
	// Behavior: exit 5/6/1 (not found) → DEBUG, other errors → ERROR
	ContextRemoval ExecutionContext = "removal"

	// ContextVerify - Verification operation (may invert success logic)
	// Use when: Checking that something was removed successfully
	// Behavior: exit 0 (found) may be ERROR, exit 1 (not found) may be INFO
	ContextVerify ExecutionContext = "verify"
)

type Options struct {
	Ctx                context.Context  // Required
	Command            string           // Required
	Args               []string         // Optional
	Dir                string           // Optional working directory
	Env                []string         // Optional environment variables (if nil, inherits from parent)
	Shell              bool             // Shell mode (bash -c)
	Retries            int              // Optional retry count
	Capture            bool             // Return captured output
	LogFields          []zap.Field      // Extra fields
	Delay              time.Duration    // Initial delay between retries (will use exponential backoff)
	Timeout            time.Duration    // Timeout for individual command execution
	MaxRetryTimeout    time.Duration    // Maximum total time for all retries (0 = no limit)
	ExponentialBackoff bool             // Use exponential backoff (default true if Retries > 1)
	DryRun             bool             // Enable dry-run mode
	Logger             *zap.Logger      // Optional logger (set externally)
	Struct             any              // optional Go struct to validate
	SchemaPath         string           // optional CUE schema
	YAMLPath           string           // optional YAML file
	TelemetryOp        string           // optional span name override
	Context            ExecutionContext // Execution context for smart exit code interpretation
}

// Settable globals (optional, but encouraged to override per-call)
var (
	DefaultLogger *zap.Logger
	DefaultDryRun bool
)

// pkg/execute/types.go

package execute

import (
	"context"
	"time"

	"go.uber.org/zap"
)

type Options struct {
	Ctx         context.Context // Required
	Command     string          // Required
	Args        []string        // Optional
	Dir         string          // Optional working directory
	Shell       bool            // Shell mode (bash -c)
	Retries     int             // Optional retry count
	Capture     bool            // Return captured output
	LogFields   []zap.Field     // Extra fields
	Delay       time.Duration
	Timeout     time.Duration
	DryRun      bool        // Enable dry-run mode
	Logger      *zap.Logger // Optional logger (set externally)
	Struct      any         // optional Go struct to validate
	SchemaPath  string      // optional CUE schema
	YAMLPath    string      // optional YAML file
	TelemetryOp string      // optional span name override
}

// Settable globals (optional, but encouraged to override per-call)
var (
	DefaultLogger *zap.Logger
	DefaultDryRun bool
)

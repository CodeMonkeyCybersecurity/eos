package eoscli

import (
	"os"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Config holds optional configuration for EOS CLI commands.
type Config struct {
	AppName  string
	Settings map[string]string
}

// RuntimeContext carries per-command runtime information across EOS CLI commands.
type RuntimeContext struct {
	Log         *zap.Logger       // Logger scoped to this command
	StartTime   time.Time         // Start time for duration tracking
	Env         map[string]string // Environment variables snapshot
	VaultClient *api.Client       // Optional Vault client
	Config      *Config           // Optional loaded configuration
}

// contextKey is a private type for context keys defined in this package.
type contextKey string

// runtimeContextKey is the key used to store RuntimeContext in context.Context.
const runtimeContextKey contextKey = "eos_runtime"

var debugMode bool

// SetDebugMode enables or disables debug output globally.
func SetDebugMode(enabled bool) {
	debugMode = enabled
}

// DebugEnabled returns whether debug output is currently enabled.
func DebugEnabled() bool {
	return debugMode
}

// NewRuntimeContext initializes a new RuntimeContext with basic environment variables.
func NewRuntimeContext(log *zap.Logger) *RuntimeContext {
	return &RuntimeContext{
		Log:       log,
		StartTime: time.Now(),
		Env: map[string]string{
			"VAULT_ADDR": os.Getenv("VAULT_ADDR"),
		},
	}
}

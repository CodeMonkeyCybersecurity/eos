// pkg/logger/types.go

package logger

var DefaultLogPaths = PlatformLogPaths()

// Option A (clean + simple)
type ctxKey string

const traceIDKey ctxKey = "trace_id"

const JournalSinceDefault = "today"

var initialized bool

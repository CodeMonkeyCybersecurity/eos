// pkg/logger/logger.go

package logger

import (
	"sync/atomic"

	"go.uber.org/zap"
)

var GlobalLogger *zap.Logger = zap.NewNop() // default to no-op until set

var globalLogger atomic.Value

func SetLogger(l *zap.Logger) {
	globalLogger.Store(l)
}

func L() *zap.Logger {
	if l, ok := globalLogger.Load().(*zap.Logger); ok {
		return l
	}
	return zap.NewNop()
}

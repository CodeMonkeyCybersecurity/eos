// pkg/logger/logger.go

package logger

import "go.uber.org/zap"

var GlobalLogger *zap.Logger = zap.NewNop() // default to no-op until set

func SetLogger(l *zap.Logger) {
	GlobalLogger = l
}

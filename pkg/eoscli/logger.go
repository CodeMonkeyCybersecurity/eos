package eoscli

import "go.uber.org/zap"

var GlobalLogger *zap.Logger = zap.NewNop() // Default to no-op logger

func SetLogger(log *zap.Logger) {
	GlobalLogger = log
}

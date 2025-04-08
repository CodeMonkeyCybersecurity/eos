/* pkg/logger/writer.go */

package logger

import (
	"fmt"
	"os"

	"go.uber.org/zap/zapcore"
)

func getLogFileWriter(path string) zapcore.WriteSyncer {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ Could not open log file %s: %v\n", path, err)
		return zapcore.AddSync(os.Stdout)
	}
	return zapcore.AddSync(file)
}

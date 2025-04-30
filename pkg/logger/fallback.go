/* pkg/logger/fallback.go */

package logger

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewFallbackLogger() *zap.Logger {
	cfg := DefaultConsoleEncoderConfig()

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(cfg),
		zapcore.AddSync(os.Stdout),
		ParseLogLevel(os.Getenv("LOG_LEVEL")),
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	logger.Info("Logger fallback initialized")
	return logger
}

func InitializeWithFallback() {
	if initialized {
		return
	}
	initialized = true

	path, err := FindWritableLogPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "⚠️  No writable log path found. Logging to console only.")
		log = NewFallbackLogger()
		zap.ReplaceGlobals(log)
		return
	}

	logDir := filepath.Dir(path)
	if stat, statErr := os.Stat(logDir); os.IsNotExist(statErr) {
		if mkErr := os.MkdirAll(logDir, 0o750); mkErr != nil {
			fmt.Fprintf(os.Stderr, "⚠️ Failed to create log dir %s: %v — falling back\n", logDir, mkErr)
			log = NewFallbackLogger()
			zap.ReplaceGlobals(log)
			return
		}
		fmt.Fprintf(os.Stderr, "📁 Created log directory %s\n", logDir)
	} else if statErr == nil && !isWritable(stat) {
		// Exists but may not be writable — try chown
		if os.Geteuid() == 0 {
			u, err := user.Lookup("eos")
			if err == nil {
				uid, _ := strconv.Atoi(u.Uid)
				gid, _ := strconv.Atoi(u.Gid)
				if chErr := os.Chown(logDir, uid, gid); chErr != nil {
					fmt.Fprintf(os.Stderr, "⚠️ Could not chown %s: %v — falling back\n", logDir, chErr)
					log = NewFallbackLogger()
					zap.ReplaceGlobals(log)
					return
				}
			} else {
				fmt.Fprintf(os.Stderr, "⚠️ Could not lookup eos user: %v — skipping chown\n", err)
			}
		}
	}

	writer, err := GetLogFileWriter(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "⚠️  Could not open log file, falling back to stdout:", err)
		log = NewFallbackLogger()
		zap.ReplaceGlobals(log)
		return
	}

	cfg := DefaultConsoleEncoderConfig()
	jsonCfg := zap.NewProductionEncoderConfig()
	jsonCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	jsonCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), zapcore.Lock(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(jsonCfg), writer, zap.InfoLevel),
	)

	log = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	zap.ReplaceGlobals(log)

	log.Info("✅ Logger initialized",
		zap.String("log_level", os.Getenv("LOG_LEVEL")),
		zap.String("log_path", path),
	)
}

// Helper: checks if existing dir is writable
func isWritable(info os.FileInfo) bool {
	mode := info.Mode().Perm()
	return mode&0200 != 0 // owner-writable
}

func DefaultConsoleEncoderConfig() zapcore.EncoderConfig {
	cfg := zap.NewProductionEncoderConfig()
	cfg.TimeKey = "T"
	cfg.LevelKey = "L"
	cfg.NameKey = "N"
	cfg.CallerKey = "C"
	cfg.MessageKey = "M"
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return cfg
}

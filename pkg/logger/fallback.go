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

	// 📁 Attempt to ensure parent log directory exists and is writable by eos
	logDir := filepath.Dir(path)
	if _, statErr := os.Stat(logDir); os.IsNotExist(statErr) {
		if mkErr := os.MkdirAll(logDir, 0o600); mkErr != nil {
			fmt.Fprintf(os.Stderr, "⚠️ Failed to create log dir %s: %v — falling back\n", logDir, mkErr)
			log = NewFallbackLogger()
			zap.ReplaceGlobals(log)
			return
		}
		fmt.Fprintf(os.Stderr, "📁 Created log directory %s\n", logDir)
	}

	info, err := os.Stat(path)
	if err == nil && info.Mode().Perm() != 0o600 {
		fmt.Fprintf(os.Stderr, "⚠️ Unexpected log file permissions: %v\n", info.Mode())
	}

	// ✅ Attempt to chown the log directory to eos:eos if running as root
	if os.Geteuid() == 0 {
		u, err := user.Lookup("eos")
		if err == nil {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			_ = os.Chown(logDir, uid, gid) // optional: check error and fallback
		} else {
			fmt.Fprintf(os.Stderr, "⚠️ Could not lookup eos user: %v — skipping chown\n", err)
		}
	}

	cfg := DefaultConsoleEncoderConfig()
	jsonCfg := zap.NewProductionEncoderConfig()
	jsonCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	jsonCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	writer, err := GetLogFileWriter(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "⚠️  Could not write to log file, falling back to stdout:", err)
		writer = zapcore.AddSync(os.Stdout)
	}

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), zapcore.Lock(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(jsonCfg), writer, zap.InfoLevel),
	)

	log = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	zap.ReplaceGlobals(log)
	log.Info("Logger fallback initialized",
		zap.String("log_level", os.Getenv("LOG_LEVEL")),
		zap.String("log_path", path),
	)
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

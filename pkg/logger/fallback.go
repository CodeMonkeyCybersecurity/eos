/* pkg/logger/fallback.go */

package logger

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewFallbackLogger() *zap.Logger {
	cfg := baseEncoderConfig()
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(cfg),
		zapcore.AddSync(os.Stdout),
		ParseLogLevel(os.Getenv("LOG_LEVEL")),
	)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	logger.Info("Logger fallback initialized")
	return logger
}

// InitializeWithFallback sets up the logger or falls back; returns eoserr.ErrFallbackUsed if fallback engaged.
func InitializeWithFallback(log *zap.Logger) error {
	if initialized {
		return nil
	}
	initialized = true

	path, err := FindWritableLogPath()
	if err != nil {
		useFallback("no writable log path found")
		return eoserr.ErrFallbackUsed
	}

	if os.Geteuid() != 0 && strings.HasPrefix(path, "/var/log/") {
		useFallback("non-root user cannot write to /var/log")
		return eoserr.ErrFallbackUsed
	}

	logDir := filepath.Dir(path)
	if err := prepareLogDir(logDir); err != nil {
		useFallback(fmt.Sprintf("log dir preparation failed: %v", err))
		return eoserr.ErrFallbackUsed
	}

	if !testWritable(logDir, log) {
		useFallback(fmt.Sprintf("write test failed for %s", logDir))
		return eoserr.ErrFallbackUsed
	}

	writer, err := GetLogFileWriter(path)
	if err != nil {
		useFallback(fmt.Sprintf("could not open log file: %v", err))
		return eoserr.ErrFallbackUsed
	}

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewConsoleEncoder(baseEncoderConfig()), zapcore.Lock(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(baseEncoderConfig()), writer, zap.InfoLevel),
	)

	newLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	zap.ReplaceGlobals(newLogger)
	SetLogger(newLogger)

	newLogger.Info("✅ Logger initialized",
		zap.String("log_level", os.Getenv("LOG_LEVEL")),
		zap.String("log_path", path),
	)
	return nil
}

// prepareLogDir ensures the log directory exists and is owned by the 'eos' user if root.
func prepareLogDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, DefaultLogDirPerm); err != nil {
			return fmt.Errorf("mkdir failed: %w", err)
		}
	}

	if os.Geteuid() == 0 {
		u, err := user.Lookup(DefaultLogUser)
		if err != nil {
			L().Warn("🔐 eos user not found", zap.Error(err))
			return fmt.Errorf("eos user lookup failed: %w", err)
		}

		uid, err1 := strconv.Atoi(u.Uid)
		gid, err2 := strconv.Atoi(u.Gid)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid UID/GID: uid=%v, gid=%v", err1, err2)
		}

		if err := os.Chown(dir, uid, gid); err != nil {
			return fmt.Errorf("chown failed: %w", err)
		}
		if err := os.Chmod(dir, DefaultLogDirPerm); err != nil {
			return fmt.Errorf("chmod failed: %w", err)
		}
	}
	return nil
}

func testWritable(dir string, log *zap.Logger) bool {
	testFile := filepath.Join(dir, ".write_test")
	f, err := os.Create(testFile)
	if err != nil {
		return false
	}
	defer shared.SafeClose(f, log)
	shared.SafeRemove(testFile, log)
	return true
}

func baseEncoderConfig() zapcore.EncoderConfig {
	cfg := zap.NewProductionEncoderConfig()
	cfg.TimeKey = "time"
	cfg.LevelKey = "level"
	cfg.CallerKey = "caller"
	cfg.MessageKey = "msg"
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return cfg
}

func DefaultConsoleEncoderConfig() zapcore.EncoderConfig {
	cfg := baseEncoderConfig()
	cfg.TimeKey = "T"
	cfg.LevelKey = "L"
	cfg.NameKey = "N"
	cfg.CallerKey = "C"
	cfg.MessageKey = "M"
	return cfg
}

func useFallback(reason string) {
	logger := NewFallbackLogger()
	zap.ReplaceGlobals(logger)
	SetLogger(logger)

	logger.Warn("⚠️ Fallback logger used",
		zap.String("reason", reason),
		zap.String("user", os.Getenv("USER")),
	)
}

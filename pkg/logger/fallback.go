/* pkg/logger/fallback.go */

package logger

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

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

func InitializeWithFallback() {
	if initialized {
		return
	}
	initialized = true

	path, err := FindWritableLogPath()
	if err != nil {
		useFallback("no writable log path found")
		return
	}

	logDir := filepath.Dir(path)
	if err := prepareLogDir(logDir); err != nil {
		useFallback(fmt.Sprintf("log dir preparation failed: %v", err))
		return
	}

	if !testWritable(logDir) {
		useFallback(fmt.Sprintf("write test failed for %s", logDir))
		return
	}

	writer, err := GetLogFileWriter(path)
	if err != nil {
		useFallback(fmt.Sprintf("could not open log file: %v", err))
		return
	}

	encoderCfg := baseEncoderConfig()
	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewConsoleEncoder(encoderCfg), zapcore.Lock(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), writer, zap.InfoLevel),
	)

	newLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	zap.ReplaceGlobals(newLogger)
	SetLogger(newLogger)

	newLogger.Info("✅ Logger initialized",
		zap.String("log_level", os.Getenv("LOG_LEVEL")),
		zap.String("log_path", path),
	)
}

// prepareLogDir ensures the log directory exists and is owned by the 'eos' user if root.
func prepareLogDir(dir string) error {
	log := L()
	log.Info("🔍 Preparing log directory", zap.String("dir", dir))

	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		log.Warn("📂 Log directory does not exist, creating", zap.String("dir", dir))
		if err := os.MkdirAll(dir, DefaultLogDirPerm); err != nil {
			log.Error("❌ Failed to create log directory", zap.Error(err))
			return fmt.Errorf("mkdir failed: %w", err)
		}
	} else if err != nil {
		log.Error("❌ Failed to stat log directory", zap.Error(err))
		return fmt.Errorf("stat failed: %w", err)
	} else {
		log.Info("✅ Log directory exists", zap.Any("permissions", info.Mode()))
	}

	// Check effective UID
	euid := os.Geteuid()
	log.Info("👤 Effective UID", zap.Int("euid", euid))

	if euid == 0 {
		u, err := user.Lookup(DefaultLogUser)
		if err != nil {
			log.Warn("🔐 eos user not found", zap.Error(err))
			return fmt.Errorf("eos user lookup failed: %w", err)
		}

		uid, err1 := strconv.Atoi(u.Uid)
		gid, err2 := strconv.Atoi(u.Gid)
		if err1 != nil || err2 != nil {
			log.Error("❌ Invalid UID/GID", zap.String("uid", u.Uid), zap.String("gid", u.Gid))
			return fmt.Errorf("invalid UID/GID: uid=%v, gid=%v", err1, err2)
		}

		log.Info("🔧 Changing ownership", zap.Int("uid", uid), zap.Int("gid", gid))
		if err := os.Chown(dir, uid, gid); err != nil {
			log.Error("❌ chown failed", zap.Error(err))
			return fmt.Errorf("chown failed: %w", err)
		}

		log.Info("🔧 Setting permissions", zap.String("permissions", fmt.Sprintf("%#o", DefaultLogDirPerm)))
		if err := os.Chmod(dir, DefaultLogDirPerm); err != nil {
			log.Error("❌ chmod failed", zap.Error(err))
			return fmt.Errorf("chmod failed: %w", err)
		}
	}

	log.Info("✅ Log directory prepared")
	return nil
}

// Update testWritable for detailed error visibility
func testWritable(dir string) bool {
	log := L()
	testFile := filepath.Join(dir, ".write_test")
	log.Info("📝 Testing write permission", zap.String("file", testFile))

	f, err := os.Create(testFile)
	if err != nil {
		log.Warn("❌ Write test failed (create error)",
			zap.String("file", testFile),
			zap.Error(err),
		)
		return false
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Warn("⚠️ Failed to close test file", zap.Error(err))
		}
		if err := os.Remove(testFile); err != nil {
			log.Warn("⚠️ Failed to remove test file", zap.Error(err))
		}
	}()

	log.Info("✅ Write test succeeded")
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

// Modified useFallback with extra directory diagnostics
func useFallback(reason string) {
	logger := NewFallbackLogger()
	zap.ReplaceGlobals(logger)
	SetLogger(logger)

	currentUser, err := user.Current()
	username := "unknown"
	uid := "unknown"
	gid := "unknown"
	homeDir := "unknown"

	if err == nil {
		username = currentUser.Username
		uid = currentUser.Uid
		gid = currentUser.Gid
		homeDir = currentUser.HomeDir
	}

	cwd, _ := os.Getwd()
	envPath := os.Getenv("PATH")
	envUser := os.Getenv("USER")

	// Add directory diagnostics
	logDir := shared.EosLogDir
	info, statErr := os.Stat(logDir)
	if statErr != nil {
		logger.Warn("⚠️ Could not stat log directory",
			zap.String("dir", logDir),
			zap.Error(statErr),
		)
	} else {
		sys := info.Sys().(*syscall.Stat_t)
		logger.Warn("⚠️ Log directory status",
			zap.String("dir", logDir),
			zap.Any("permissions", info.Mode()),
			zap.Uint32("owner_uid", sys.Uid),
			zap.Uint32("owner_gid", sys.Gid),
		)
	}

	// Include fallback context
	logger.Warn("⚠️ Fallback logger used",
		zap.String("reason", reason),
		zap.String("effective_user", envUser),
		zap.String("detected_user", username),
		zap.String("uid", uid),
		zap.String("gid", gid),
		zap.String("home", homeDir),
		zap.String("cwd", cwd),
		zap.String("path", envPath),
	)
}

// pkg/eoscli/logger.go

package eoscli

import (
	"os"
	"os/user"

	"go.uber.org/zap"
)

var GlobalLogger *zap.Logger = zap.NewNop() // Default to no-op logger

func SetLogger(log *zap.Logger) {
	GlobalLogger = log
}

// logRuntimeExecutionContext logs UID/GID info and binary path to help diagnose privilege or permission issues.
func logRuntimeExecutionContext(log *zap.Logger) {
	currentUser, err := user.Current()
	if err != nil {
		log.Warn("⚠️ Failed to get current user", zap.Error(err))
	} else {
		log.Info("🔎 User context",
			zap.String("username", currentUser.Username),
			zap.String("uid_str", currentUser.Uid),
			zap.String("gid_str", currentUser.Gid),
			zap.String("home", currentUser.HomeDir),
		)
	}

	log.Info("🔎 UID/GID (runtime)",
		zap.Int("real_uid", os.Getuid()),
		zap.Int("effective_uid", os.Geteuid()),
		zap.Int("real_gid", os.Getgid()),
		zap.Int("effective_gid", os.Getegid()),
	)

	execPath, err := os.Executable()
	if err != nil {
		log.Warn("⚠️ Failed to resolve executable path", zap.Error(err))
	} else {
		log.Info("🗂️ Executing binary", zap.String("path", execPath))
	}
}

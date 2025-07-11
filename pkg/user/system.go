package user

import (
	"os"
	"os/user"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetSystemUser returns the actual system user (not root) when running under sudo
// Migrated from cmd/create/pipeline_prompts.go getSystemUser
func GetSystemUser(rc *eos_io.RuntimeContext) (*user.User, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check current user context
	logger.Debug("Assessing system user context")
	
	currentUser, err := user.Current()
	if err != nil {
		logger.Error("Failed to get current user", zap.Error(err))
		return nil, err
	}
	
	// INTERVENE - Determine actual user
	// If not running as root, return current user
	if currentUser.Uid != "0" {
		logger.Debug("Not running as root, returning current user",
			zap.String("user", currentUser.Username),
			zap.String("uid", currentUser.Uid))
		return currentUser, nil
	}
	
	// Running as root, check for SUDO_USER
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		logger.Debug("Running as root with SUDO_USER",
			zap.String("sudo_user", sudoUser))
		
		systemUser, err := user.Lookup(sudoUser)
		if err != nil {
			logger.Warn("Failed to lookup SUDO_USER, falling back to root",
				zap.String("sudo_user", sudoUser),
				zap.Error(err))
			return currentUser, nil
		}
		
		// EVALUATE - Return the actual user
		logger.Debug("Returning system user from SUDO_USER",
			zap.String("user", systemUser.Username),
			zap.String("uid", systemUser.Uid))
		return systemUser, nil
	}
	
	// No SUDO_USER, return root
	logger.Debug("No SUDO_USER found, returning root user")
	return currentUser, nil
}
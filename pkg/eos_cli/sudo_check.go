// pkg/eos_cli/sudo_check.go
//
// Sudo detection and privilege escalation warnings
// Follows human-centric principle: warn users about unnecessary privilege escalation

package eos_cli

import (
	"context"
	"os"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SudoContext contains information about sudo usage
type SudoContext struct {
	RunningAsRoot  bool   // Effective UID is 0
	RunningSudo    bool   // Was invoked via sudo
	OriginalUser   string // Original user (SUDO_USER env var)
	OriginalUID    string // Original UID (SUDO_UID env var)
	OriginalGID    string // Original GID (SUDO_GID env var)
	OriginalHome   string // Original home directory
	CurrentUser    string // Current effective user
	CurrentUID     int    // Current effective UID
	CurrentHomeDir string // Current home directory ($HOME)
}

// DetectSudoContext analyzes the current execution environment for sudo usage
func DetectSudoContext() *SudoContext {
	euid := os.Geteuid()
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = os.Getenv("LOGNAME")
	}

	ctx := &SudoContext{
		RunningAsRoot:  euid == 0,
		RunningSudo:    os.Getenv("SUDO_USER") != "",
		OriginalUser:   os.Getenv("SUDO_USER"),
		OriginalUID:    os.Getenv("SUDO_UID"),
		OriginalGID:    os.Getenv("SUDO_GID"),
		OriginalHome:   "", // Will infer if needed
		CurrentUser:    currentUser,
		CurrentUID:     euid,
		CurrentHomeDir: os.Getenv("HOME"),
	}

	// Infer original home directory
	if ctx.RunningSudo && ctx.OriginalUser != "" {
		// Typical pattern: /home/<username>
		ctx.OriginalHome = "/home/" + ctx.OriginalUser
		// Special case: if original user is a system account, home might be different
		// But for warning purposes, /home/<user> is a reasonable heuristic
	}

	return ctx
}

// WarnIfUnnecessarySudo checks if running with sudo and warns if it may cause issues
// This is especially important for git operations, which use different config files for root vs user
func WarnIfUnnecessarySudo(ctx context.Context, operationName string) {
	logger := otelzap.Ctx(ctx)

	sudoCtx := DetectSudoContext()

	if !sudoCtx.RunningSudo {
		// Not running via sudo, no warning needed
		return
	}

	// Running via sudo - warn about potential issues
	logger.Warn("EOS invoked with sudo - this may cause unexpected behavior",
		zap.String("operation", operationName),
		zap.String("original_user", sudoCtx.OriginalUser),
		zap.String("current_user", sudoCtx.CurrentUser),
		zap.Int("current_uid", sudoCtx.CurrentUID),
		zap.String("current_home", sudoCtx.CurrentHomeDir))

	// Detailed warning for specific operations that are affected by sudo
	switch operationName {
	case "git", "repository", "create_repo":
		logger.Warn("Git operations with sudo use root's git config, not your user config",
			zap.String("root_config", "/root/.gitconfig"),
			zap.String("user_config", sudoCtx.OriginalHome+"/.gitconfig"),
			zap.String("recommendation", "Run without sudo unless creating files in protected directories"))

		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: ⚠ WARNING: Running with sudo")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: You invoked EOS with 'sudo'. This means:")
		logger.Info("terminal prompt:   - Git will use root's config (/root/.gitconfig)")
		logger.Info("terminal prompt:   - NOT your user config (~/.gitconfig)")
		logger.Info("terminal prompt:   - Created files will be owned by root")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: For git operations, consider running WITHOUT sudo:")
		logger.Info("terminal prompt:   eos create repo .")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Original user: " + sudoCtx.OriginalUser)
		logger.Info("terminal prompt: Current user:  " + sudoCtx.CurrentUser + " (root)")
		logger.Info("terminal prompt: ")

	case "config", "preferences":
		logger.Warn("Configuration operations with sudo will affect root user, not your account",
			zap.String("original_user", sudoCtx.OriginalUser),
			zap.String("recommendation", "Consider running without sudo for user-level config"))

	default:
		// Generic warning for other operations
		logger.Warn("Sudo may affect file ownership and configuration paths",
			zap.String("recommendation", "Only use sudo if operation requires elevated privileges"))
	}
}

// RequiresSudoForOperation checks if an operation legitimately needs root privileges
// Use this to proactively check before warning users
func RequiresSudoForOperation(operationName string) bool {
	// Operations that legitimately need root
	rootRequired := map[string]bool{
		"install_service":    true, // systemd service installation
		"configure_firewall": true, // ufw/iptables modification
		"install_package":    true, // apt/yum package installation
		"mount_filesystem":   true, // filesystem operations
		"create_user":        true, // user/group management
		"systemd_manage":     true, // systemd operations
	}

	return rootRequired[operationName]
}

// SuggestDropPrivileges returns a message suggesting how to run without sudo
func SuggestDropPrivileges(command string) string {
	return "Consider running without sudo:\n  " + command + "\n\n" +
		"Use sudo only for operations that require elevated privileges\n" +
		"(e.g., system service installation, firewall configuration)"
}

// CheckAndWarnPrivileges is a convenience function that combines detection and warning
// Call this at the start of commands that don't need root but might be run with sudo
func CheckAndWarnPrivileges(ctx context.Context, operationName string, requiresSudo bool) {
	sudoCtx := DetectSudoContext()

	// If operation requires sudo but not running as root
	if requiresSudo && !sudoCtx.RunningAsRoot {
		logger := otelzap.Ctx(ctx)
		logger.Error("This operation requires root privileges but not running with sufficient permissions",
			zap.String("operation", operationName),
			zap.Int("current_uid", sudoCtx.CurrentUID),
			zap.String("recommendation", "Run with: sudo eos ..."))
		// Note: Caller should return error after this
		return
	}

	// If operation doesn't require sudo but running with it
	if !requiresSudo && sudoCtx.RunningSudo {
		WarnIfUnnecessarySudo(ctx, operationName)
	}
}

// IsRootOrSudo returns true if running as root (either directly or via sudo)
func IsRootOrSudo() bool {
	return os.Geteuid() == 0
}

// GetEffectiveUser returns the effective user name
func GetEffectiveUser() string {
	sudoCtx := DetectSudoContext()
	if sudoCtx.RunningSudo {
		return sudoCtx.OriginalUser + " (via sudo as " + sudoCtx.CurrentUser + ")"
	}
	return sudoCtx.CurrentUser
}

// GetConfigHome returns the appropriate config directory based on sudo context
// This helps determine which config files will actually be used
func GetConfigHome() string {
	sudoCtx := DetectSudoContext()

	if sudoCtx.RunningSudo && sudoCtx.OriginalHome != "" {
		// Running via sudo - but user's config is at original home
		// However, current operations will use current HOME (root's)
		return sudoCtx.CurrentHomeDir // What's actually being used
	}

	return sudoCtx.CurrentHomeDir
}

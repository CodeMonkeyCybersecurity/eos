// pkg/privilege_check/privileges.go
package privilege_check

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckPrivileges checks the current user's privilege level following Assess → Intervene → Evaluate pattern
func CheckPrivileges(rc *eos_io.RuntimeContext, config *PrivilegeConfig) (*PrivilegeCheck, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing privilege check request")

	if config == nil {
		config = DefaultPrivilegeConfig()
	}

	check := &PrivilegeCheck{
		Timestamp: time.Now(),
	}

	// INTERVENE
	logger.Info("Checking user privileges")

	// Get current user ID
	check.UserID = os.Geteuid()
	check.GroupID = os.Getegid()

	// Get user information
	currentUser, err := user.Current()
	if err != nil {
		check.Error = fmt.Sprintf("Failed to get current user: %v", err)
		logger.Error("Failed to get current user info", zap.Error(err))
		return check, err
	}

	check.Username = currentUser.Username

	// Get group information
	group, err := user.LookupGroupId(strconv.Itoa(check.GroupID))
	if err != nil {
		logger.Warn("Failed to get group info", zap.Error(err))
		check.Groupname = fmt.Sprintf("gid-%d", check.GroupID)
	} else {
		check.Groupname = group.Name
	}

	// Determine privilege level
	check.IsRoot = (check.UserID == 0)

	if check.IsRoot {
		check.Level = PrivilegeLevelRoot
		check.HasSudo = true // Root inherently has sudo
	} else {
		// Check if user has sudo privileges
		check.HasSudo = checkSudoAccess(rc)
		if check.HasSudo {
			check.Level = PrivilegeLevelSudo
		} else {
			check.Level = PrivilegeLevelRegular
		}
	}

	// EVALUATE
	logger.Info("Privilege check completed successfully",
		zap.String("username", check.Username),
		zap.Int("uid", check.UserID),
		zap.String("level", string(check.Level)),
		zap.Bool("is_root", check.IsRoot),
		zap.Bool("has_sudo", check.HasSudo))

	return check, nil
}

// RequireSudo performs a sudo check with specified requirements following Assess → Intervene → Evaluate pattern
func RequireSudo(rc *eos_io.RuntimeContext, config *PrivilegeConfig, options *CheckOptions) (*SudoCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing sudo requirement check")

	if config == nil {
		config = DefaultPrivilegeConfig()
	}

	if options == nil {
		options = &CheckOptions{
			Requirement: SudoRequired,
		}
	}

	logger.Info("Assessing sudo requirement check",
		zap.String("requirement", string(options.Requirement)),
		zap.Bool("silent", options.SilentMode))

	result := &SudoCheckResult{
		Required:  (options.Requirement == SudoRequired),
		Timestamp: time.Now(),
	}

	// INTERVENE
	logger.Info("Performing sudo requirement check")

	// Check current privileges
	check, err := CheckPrivileges(rc, config)
	if err != nil {
		result.Success = false
		result.Message = fmt.Sprintf("Failed to check privileges: %v", err)
		return result, err
	}

	result.Check = *check

	// Determine if requirements are met
	switch options.Requirement {
	case SudoNotRequired:
		result.Success = true
		result.Message = "No elevated privileges required"

	case SudoPreferred:
		result.Success = true
		if check.IsRoot || check.HasSudo {
			result.Message = "Running with elevated privileges"
		} else {
			result.Message = "Running with regular privileges (elevated privileges preferred but not required)"
		}

	case SudoRequired:
		if check.IsRoot {
			result.Success = true
			result.Message = "Running as root"
		} else if check.HasSudo && config.AllowSudo {
			result.Success = true
			result.Message = "Running with sudo privileges"
		} else {
			result.Success = false
			if options.CustomMessage != "" {
				result.Message = options.CustomMessage
			} else {
				result.Message = "This operation requires root privileges. Please run with sudo."
			}
		}
	}

	// Output colored message if configured and not in silent mode
	if !options.SilentMode && config.ShowColorOutput {
		outputColoredMessage(result)
	}

	// Exit on failure if configured
	if !result.Success && config.ExitOnFailure {
		logger.Error("Privilege check failed, exiting", zap.String("message", result.Message))
		os.Exit(1)
	}

	// EVALUATE
	logger.Info("Sudo requirement check completed",
		zap.Bool("success", result.Success),
		zap.String("message", result.Message))

	return result, nil
}

// CheckSudoOnly is a convenience function for simple sudo checking following Assess → Intervene → Evaluate pattern
func CheckSudoOnly(rc *eos_io.RuntimeContext, config *PrivilegeConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing simple sudo check request")

	// INTERVENE
	result, err := RequireSudo(rc, config, &CheckOptions{
		Requirement: SudoRequired,
		SilentMode:  false,
	})

	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("sudo privileges required")
	}

	// EVALUATE
	logger.Info("Simple sudo check completed successfully")
	return nil
}

// GetPrivilegeInfo returns formatted privilege information following Assess → Intervene → Evaluate pattern
func GetPrivilegeInfo(rc *eos_io.RuntimeContext, config *PrivilegeConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing privilege information request")

	// INTERVENE
	check, err := CheckPrivileges(rc, config)
	if err != nil {
		return "", err
	}

	var info strings.Builder
	info.WriteString(fmt.Sprintf("User: %s (UID: %d)\n", check.Username, check.UserID))
	info.WriteString(fmt.Sprintf("Group: %s (GID: %d)\n", check.Groupname, check.GroupID))
	info.WriteString(fmt.Sprintf("Privilege Level: %s\n", check.Level))
	info.WriteString(fmt.Sprintf("Is Root: %t\n", check.IsRoot))
	info.WriteString(fmt.Sprintf("Has Sudo: %t\n", check.HasSudo))

	// EVALUATE
	logger.Info("Privilege information retrieved successfully")
	return info.String(), nil
}

// Helper functions

func checkSudoAccess(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)

	// Try to run 'sudo -n true' to check if we have passwordless sudo
	cmd := exec.CommandContext(rc.Ctx, "sudo", "-n", "true")
	err := cmd.Run()

	if err == nil {
		logger.Debug("User has passwordless sudo access")
		return true
	}

	// Check if user is in sudo group (Linux) or wheel group (BSD/macOS)
	currentUser, err := user.Current()
	if err != nil {
		logger.Debug("Failed to get current user for group check", zap.Error(err))
		return false
	}

	groups, err := currentUser.GroupIds()
	if err != nil {
		logger.Debug("Failed to get user groups", zap.Error(err))
		return false
	}

	// Check common sudo groups
	sudoGroups := []string{"sudo", "wheel", "admin"}
	for _, groupID := range groups {
		group, err := user.LookupGroupId(groupID)
		if err != nil {
			continue
		}

		for _, sudoGroup := range sudoGroups {
			if group.Name == sudoGroup {
				logger.Debug("User is in sudo group", zap.String("group", sudoGroup))
				return true
			}
		}
	}

	logger.Debug("User does not appear to have sudo access")
	return false
}

func outputColoredMessage(result *SudoCheckResult) {
	// SECURITY: Use structured logging instead of fmt.Printf per CLAUDE.md P0 rule
	logger := otelzap.L()

	if result.Success {
		if result.Check.IsRoot {
			logger.Info("Privilege check success",
				zap.String("status", "✔"),
				zap.String("color", "green"),
				zap.String("message", result.Message))
		} else {
			logger.Info("Privilege check success",
				zap.String("status", "✔"),
				zap.String("color", "yellow"),
				zap.String("message", result.Message))
		}
	} else {
		logger.Error("Privilege check failure",
			zap.String("status", "✘"),
			zap.String("color", "red"),
			zap.String("message", result.Message))
	}
}
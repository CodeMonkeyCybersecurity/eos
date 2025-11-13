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

// PrivilegeManager handles privilege checking operations
type PrivilegeManager struct {
	config *PrivilegeConfig
}

// NewPrivilegeManager creates a new privilege manager
func NewPrivilegeManager(config *PrivilegeConfig) *PrivilegeManager {
	if config == nil {
		config = DefaultPrivilegeConfig()
	}

	return &PrivilegeManager{
		config: config,
	}
}

// CheckPrivileges checks the current user's privilege level
func (pm *PrivilegeManager) CheckPrivileges(rc *eos_io.RuntimeContext) (*PrivilegeCheck, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking user privileges")

	check := &PrivilegeCheck{
		Timestamp: time.Now(),
	}

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
		check.HasSudo = pm.checkSudoAccess(rc)
		if check.HasSudo {
			check.Level = PrivilegeLevelSudo
		} else {
			check.Level = PrivilegeLevelRegular
		}
	}

	logger.Info("Privilege check completed",
		zap.String("username", check.Username),
		zap.Int("uid", check.UserID),
		zap.String("level", string(check.Level)),
		zap.Bool("is_root", check.IsRoot),
		zap.Bool("has_sudo", check.HasSudo))

	return check, nil
}

// RequireSudo performs a sudo check with specified requirements
func (pm *PrivilegeManager) RequireSudo(rc *eos_io.RuntimeContext, options *CheckOptions) (*SudoCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if options == nil {
		options = &CheckOptions{
			Requirement: SudoRequired,
		}
	}

	logger.Info("Performing sudo requirement check",
		zap.String("requirement", string(options.Requirement)),
		zap.Bool("silent", options.SilentMode))

	result := &SudoCheckResult{
		Required:  (options.Requirement == SudoRequired),
		Timestamp: time.Now(),
	}

	// Check current privileges
	check, err := pm.CheckPrivileges(rc)
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
		} else if check.HasSudo && pm.config.AllowSudo {
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
	if !options.SilentMode && pm.config.ShowColorOutput {
		pm.outputColoredMessage(result)
	}

	// Exit on failure if configured
	if !result.Success && pm.config.ExitOnFailure {
		logger.Error("Privilege check failed, exiting", zap.String("message", result.Message))
		os.Exit(1)
	}

	return result, nil
}

// CheckSudoOnly is a convenience method for simple sudo checking
func (pm *PrivilegeManager) CheckSudoOnly(rc *eos_io.RuntimeContext) error {
	result, err := pm.RequireSudo(rc, &CheckOptions{
		Requirement: SudoRequired,
		SilentMode:  false,
	})

	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("sudo privileges required")
	}

	return nil
}

// Helper methods

func (pm *PrivilegeManager) checkSudoAccess(rc *eos_io.RuntimeContext) bool {
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

func (pm *PrivilegeManager) outputColoredMessage(result *SudoCheckResult) {
	if result.Success {
		if result.Check.IsRoot {
			fmt.Printf("\033[32m✔ %s\033[0m\n", result.Message)
		} else {
			fmt.Printf("\033[33m✔ %s\033[0m\n", result.Message)
		}
	} else {
		fmt.Printf("\033[31m✘ %s\033[0m\n", result.Message)
	}
}

// GetPrivilegeInfo returns formatted privilege information
func (pm *PrivilegeManager) GetPrivilegeInfo(rc *eos_io.RuntimeContext) (string, error) {
	check, err := pm.CheckPrivileges(rc)
	if err != nil {
		return "", err
	}

	var info strings.Builder
	info.WriteString(fmt.Sprintf("User: %s (UID: %d)\n", check.Username, check.UserID))
	info.WriteString(fmt.Sprintf("Group: %s (GID: %d)\n", check.Groupname, check.GroupID))
	info.WriteString(fmt.Sprintf("Privilege Level: %s\n", check.Level))
	info.WriteString(fmt.Sprintf("Is Root: %t\n", check.IsRoot))
	info.WriteString(fmt.Sprintf("Has Sudo: %t\n", check.HasSudo))

	return info.String(), nil
}

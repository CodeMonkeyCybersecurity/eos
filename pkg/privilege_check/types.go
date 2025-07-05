package privilege_check

import (
	"time"
)

// PrivilegeLevel represents different privilege levels
type PrivilegeLevel string

const (
	PrivilegeLevelRoot    PrivilegeLevel = "root"
	PrivilegeLevelSudo    PrivilegeLevel = "sudo"
	PrivilegeLevelRegular PrivilegeLevel = "regular"
)

// PrivilegeCheck represents the result of checking privileges
type PrivilegeCheck struct {
	UserID      int            `json:"user_id"`
	Username    string         `json:"username"`
	GroupID     int            `json:"group_id"`
	Groupname   string         `json:"groupname"`
	Level       PrivilegeLevel `json:"level"`
	IsRoot      bool           `json:"is_root"`
	HasSudo     bool           `json:"has_sudo"`
	Timestamp   time.Time      `json:"timestamp"`
	Error       string         `json:"error,omitempty"`
}

// SudoCheckResult represents the result of a sudo check operation
type SudoCheckResult struct {
	Required  bool           `json:"required"`
	Check     PrivilegeCheck `json:"check"`
	Message   string         `json:"message"`
	Success   bool           `json:"success"`
	Timestamp time.Time      `json:"timestamp"`
}

// PrivilegeConfig contains configuration for privilege checking
type PrivilegeConfig struct {
	RequireRoot     bool `json:"require_root" mapstructure:"require_root"`
	AllowSudo       bool `json:"allow_sudo" mapstructure:"allow_sudo"`
	ExitOnFailure   bool `json:"exit_on_failure" mapstructure:"exit_on_failure"`
	ShowColorOutput bool `json:"show_color_output" mapstructure:"show_color_output"`
}

// DefaultPrivilegeConfig returns a configuration with sensible defaults
func DefaultPrivilegeConfig() *PrivilegeConfig {
	return &PrivilegeConfig{
		RequireRoot:     true,
		AllowSudo:       true,
		ExitOnFailure:   true,
		ShowColorOutput: true,
	}
}

// SudoRequirement represents different sudo requirement levels
type SudoRequirement string

const (
	SudoNotRequired SudoRequirement = "not_required"
	SudoPreferred   SudoRequirement = "preferred"
	SudoRequired    SudoRequirement = "required"
)

// CheckOptions contains options for privilege checking
type CheckOptions struct {
	Requirement   SudoRequirement `json:"requirement"`
	CustomMessage string          `json:"custom_message,omitempty"`
	SilentMode    bool            `json:"silent_mode"`
}
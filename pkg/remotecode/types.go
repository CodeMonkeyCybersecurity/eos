// pkg/remotecode/types.go
// Configuration types and constants for remote code development setup
// Supports Windsurf, Claude Code, and VS Code remote SSH development

package remotecode

import (
	"time"
)

// Config holds configuration for remote code development setup
type Config struct {
	// User to configure SSH for (defaults to current user)
	User string

	// MaxSessions sets sshd MaxSessions (default 20 for IDE tools)
	MaxSessions int

	// ClientAliveInterval sets SSH keepalive interval in seconds
	ClientAliveInterval int

	// ClientAliveCountMax sets max keepalive failures before disconnect
	ClientAliveCountMax int

	// AllowTcpForwarding enables TCP forwarding (required for remote dev)
	AllowTcpForwarding bool

	// AllowAgentForwarding enables SSH agent forwarding
	AllowAgentForwarding bool

	// AllowedNetworks are additional CIDR ranges to allow SSH from
	AllowedNetworks []string

	// SkipFirewall skips firewall configuration
	SkipFirewall bool

	// SkipSSHRestart skips SSH service restart (for testing)
	SkipSSHRestart bool

	// DryRun shows what would be done without making changes
	DryRun bool
}

// DefaultConfig returns a configuration optimized for remote IDE development
func DefaultConfig() *Config {
	return &Config{
		MaxSessions:          MaxSessionsDefault,
		ClientAliveInterval:  ClientAliveIntervalDefault,
		ClientAliveCountMax:  ClientAliveCountMaxDefault,
		AllowTcpForwarding:   true,
		AllowAgentForwarding: true,
		AllowedNetworks:      []string{},
		SkipFirewall:         false,
		SkipSSHRestart:       false,
		DryRun:               false,
	}
}

// SSHConfigChange represents a single SSH configuration modification
type SSHConfigChange struct {
	Setting   string // SSH setting name (e.g., "MaxSessions")
	OldValue  string // Previous value (empty if not set)
	NewValue  string // New value to set
	Applied   bool   // Whether the change was applied
	Reason    string // Explanation for the change
	WasBackup bool   // Whether backup was created before change
}

// InstallResult contains the results of the installation process
type InstallResult struct {
	// SSHChanges lists all SSH configuration changes made
	SSHChanges []SSHConfigChange

	// FirewallRulesAdded lists firewall rules that were added
	FirewallRulesAdded []string

	// BackupPath is the path to SSH config backup (if created)
	BackupPath string

	// SSHRestarted indicates if SSH service was restarted
	SSHRestarted bool

	// Warnings contains non-fatal issues encountered
	Warnings []string

	// AccessInstructions contains user-facing access information
	AccessInstructions string
}

// Constants for SSH configuration optimized for remote IDE development
const (
	// MaxSessionsDefault allows multiple IDE connections per user
	// RATIONALE: Each IDE window/workspace opens multiple SSH sessions
	// Default SSH value is 10, which causes "too many logins" errors
	// Value 20 supports ~4 IDE windows with headroom
	MaxSessionsDefault = 20

	// ClientAliveIntervalDefault sends keepalive every 60 seconds
	// RATIONALE: Prevents IDE disconnection on idle
	// Default SSH value is 0 (disabled)
	ClientAliveIntervalDefault = 60

	// ClientAliveCountMaxDefault allows 3 missed keepalives before disconnect
	// RATIONALE: 3 * 60 = 180 seconds of network issues before disconnect
	// Prevents premature disconnection during brief network blips
	ClientAliveCountMaxDefault = 3

	// SSHConfigPath is the main SSH daemon configuration file
	SSHConfigPath = "/etc/ssh/sshd_config"

	// SSHConfigBackupSuffix is appended to create backup filename
	SSHConfigBackupSuffix = ".eos-backup"

	// Network ranges for firewall configuration
	TailscaleNetwork = "100.64.0.0/10"  // Tailscale CGNAT range
	LocalNetworkA    = "192.168.0.0/16" // Private network class C
	LocalNetworkB    = "10.0.0.0/8"     // Private network class A
	LocalNetworkC    = "172.16.0.0/12"  // Private network class B

	// Timeouts for operations
	SSHRestartTimeout = 30 * time.Second
	FirewallTimeout   = 10 * time.Second
)

// SSHSettings maps setting names to their descriptions for documentation
var SSHSettings = map[string]string{
	"MaxSessions": "Maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection",
	"ClientAliveInterval": "Sets a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response",
	"ClientAliveCountMax": "Sets the number of client alive messages which may be sent without sshd receiving any messages back from the client",
	"AllowTcpForwarding": "Specifies whether TCP forwarding is permitted",
	"AllowAgentForwarding": "Specifies whether ssh-agent forwarding is permitted",
}

// SupportedIDEs lists the IDEs this configuration supports
var SupportedIDEs = []string{
	"Windsurf (Codeium)",
	"Claude Code (Anthropic)",
	"VS Code Remote SSH",
	"Cursor",
	"JetBrains Gateway",
}

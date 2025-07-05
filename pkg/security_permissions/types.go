package security_permissions

import (
	"os"
	"strings"
	"time"
)

// PermissionRule represents a file or directory permission rule
type PermissionRule struct {
	Path        string      `json:"path"`
	Mode        os.FileMode `json:"mode"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Category    string      `json:"category"` // ssh, system, ssl, etc.
}

// PermissionCheck represents the result of checking a specific permission
type PermissionCheck struct {
	Rule         PermissionRule `json:"rule"`
	Exists       bool           `json:"exists"`
	CurrentMode  os.FileMode    `json:"current_mode,omitempty"`
	ExpectedMode os.FileMode    `json:"expected_mode"`
	NeedsChange  bool           `json:"needs_change"`
	Error        string         `json:"error,omitempty"`
}

// PermissionScanResult contains results of a permission scan
type PermissionScanResult struct {
	Timestamp   time.Time         `json:"timestamp"`
	Category    string            `json:"category"`
	TotalChecks int               `json:"total_checks"`
	Passed      int               `json:"passed"`
	Failed      int               `json:"failed"`
	Fixed       int               `json:"fixed"`
	Errors      int               `json:"errors"`
	Checks      []PermissionCheck `json:"checks"`
}

// PermissionFixResult contains results of permission fixes
type PermissionFixResult struct {
	Timestamp   time.Time                      `json:"timestamp"`
	DryRun      bool                           `json:"dry_run"`
	Categories  []string                       `json:"categories"`
	Results     map[string]PermissionScanResult `json:"results"`
	Summary     PermissionSummary              `json:"summary"`
}

// PermissionSummary provides an overall summary of permission operations
type PermissionSummary struct {
	TotalFiles    int      `json:"total_files"`
	FilesFixed    int      `json:"files_fixed"`
	FilesSkipped  int      `json:"files_skipped"`
	Errors        []string `json:"errors"`
	Success       bool     `json:"success"`
}

// SecurityConfig contains configuration for permission management
type SecurityConfig struct {
	SSHDirectory      string   `json:"ssh_directory" mapstructure:"ssh_directory"`
	IncludeSystem     bool     `json:"include_system" mapstructure:"include_system"`
	CreateBackups     bool     `json:"create_backups" mapstructure:"create_backups"`
	DryRun            bool     `json:"dry_run" mapstructure:"dry_run"`
	ExcludePatterns   []string `json:"exclude_patterns" mapstructure:"exclude_patterns"`
	CustomRules       []PermissionRule `json:"custom_rules,omitempty" mapstructure:"custom_rules"`
	VerifyOwnership   bool     `json:"verify_ownership" mapstructure:"verify_ownership"`
	BackupDirectory   string   `json:"backup_directory,omitempty" mapstructure:"backup_directory"`
}

// DefaultSecurityConfig returns a configuration with sensible defaults
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		SSHDirectory:    os.ExpandEnv("$HOME/.ssh"),
		IncludeSystem:   false,
		CreateBackups:   true,
		DryRun:          false,
		ExcludePatterns: []string{"*.bak", "*.backup", ".git"},
		VerifyOwnership: true,
	}
}

// Common permission rules
var (
	// SSH permission rules
	SSHPermissionRules = []PermissionRule{
		{
			Path:        "$HOME/.ssh",
			Mode:        0700,
			Description: "SSH directory",
			Required:    true,
			Category:    "ssh",
		},
		{
			Path:        "$HOME/.ssh/id_rsa",
			Mode:        0600,
			Description: "SSH private key",
			Required:    false,
			Category:    "ssh",
		},
		{
			Path:        "$HOME/.ssh/id_ed25519",
			Mode:        0600,
			Description: "SSH Ed25519 private key",
			Required:    false,
			Category:    "ssh",
		},
		{
			Path:        "$HOME/.ssh/config",
			Mode:        0600,
			Description: "SSH client configuration",
			Required:    false,
			Category:    "ssh",
		},
		{
			Path:        "$HOME/.ssh/authorized_keys",
			Mode:        0600,
			Description: "SSH authorized keys",
			Required:    false,
			Category:    "ssh",
		},
		{
			Path:        "$HOME/.ssh/known_hosts",
			Mode:        0644,
			Description: "SSH known hosts",
			Required:    false,
			Category:    "ssh",
		},
	}

	// System permission rules
	SystemPermissionRules = []PermissionRule{
		{
			Path:        "/root",
			Mode:        0700,
			Description: "root home directory",
			Required:    true,
			Category:    "system",
		},
		{
			Path:        "/tmp",
			Mode:        01777, // sticky bit
			Description: "temporary directory",
			Required:    true,
			Category:    "system",
		},
		{
			Path:        "/etc/passwd",
			Mode:        0644,
			Description: "passwd file",
			Required:    true,
			Category:    "system",
		},
		{
			Path:        "/etc/shadow",
			Mode:        0640,
			Description: "shadow file",
			Required:    true,
			Category:    "system",
		},
		{
			Path:        "/etc/group",
			Mode:        0644,
			Description: "group file",
			Required:    true,
			Category:    "system",
		},
		{
			Path:        "/etc/gshadow",
			Mode:        0640,
			Description: "gshadow file",
			Required:    false,
			Category:    "system",
		},
		{
			Path:        "/etc/sudoers",
			Mode:        0440,
			Description: "sudoers file",
			Required:    false,
			Category:    "system",
		},
		{
			Path:        "/etc/ssh/sshd_config",
			Mode:        0600,
			Description: "sshd_config file",
			Required:    false,
			Category:    "system",
		},
	}

	// SSL permission rules
	SSLPermissionRules = []PermissionRule{
		{
			Path:        "/etc/ssl/private",
			Mode:        0700,
			Description: "SSL private keys directory",
			Required:    false,
			Category:    "ssl",
		},
		{
			Path:        "/etc/ssl/certs",
			Mode:        0755,
			Description: "SSL certificates directory",
			Required:    false,
			Category:    "ssl",
		},
	}
)

// GetPermissionRules returns permission rules for the specified categories
func GetPermissionRules(categories []string) []PermissionRule {
	var rules []PermissionRule
	
	for _, category := range categories {
		switch category {
		case "ssh":
			rules = append(rules, SSHPermissionRules...)
		case "system":
			rules = append(rules, SystemPermissionRules...)
		case "ssl":
			rules = append(rules, SSLPermissionRules...)
		}
	}
	
	return rules
}

// IsPrivateKey determines if a file should be treated as a private key
func IsPrivateKey(filename string) bool {
	// Check common private key patterns
	privateKeyPatterns := []string{
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
		"private", "key", "pem",
	}
	
	// If file ends with .pub, it's likely a public key
	if strings.HasSuffix(filename, ".pub") {
		return false
	}
	
	// Check if filename contains private key indicators
	for _, pattern := range privateKeyPatterns {
		if strings.Contains(filename, pattern) {
			return true
		}
	}
	
	return false
}
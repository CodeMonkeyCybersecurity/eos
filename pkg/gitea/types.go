// pkg/gitea/types.go
// Configuration types and constants for self-hosted Gitea integration
// Supports SSH-based authentication to push/pull from private Gitea instances

package gitea

import (
	"time"
)

// Config holds configuration for connecting to a self-hosted Gitea instance
type Config struct {
	// InstanceName is a user-friendly name for this Gitea instance (e.g., "vhost7-gitea")
	InstanceName string

	// Hostname is the Gitea server hostname or IP (e.g., "vhost7", "192.168.1.50")
	Hostname string

	// HTTPPort is the web UI port (e.g., 8167 for http://vhost7:8167)
	HTTPPort int

	// SSHPort is the SSH port for git operations (often 22 or 2222 for Docker setups)
	SSHPort int

	// SSHUser is the git user (always "git" for Gitea)
	SSHUser string

	// SSHKeyPath is the path to the private key for authentication
	SSHKeyPath string

	// SSHKeyName is the name/comment for the key (e.g., "hecate-deploy")
	SSHKeyName string

	// Organization is the Gitea organization (e.g., "cybermonkey")
	Organization string

	// Default is whether this is the default Gitea instance
	Default bool
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		SSHPort: SSHPortDefault,
		SSHUser: SSHUserDefault,
	}
}

// ConfigResult holds the result of configuration operations
type ConfigResult struct {
	// ConfigPath is where the configuration was saved
	ConfigPath string

	// SSHKeyGenerated indicates if a new SSH key was created
	SSHKeyGenerated bool

	// SSHKeyPath is the path to the private key
	SSHKeyPath string

	// SSHPublicKeyPath is the path to the public key
	SSHPublicKeyPath string

	// SSHConfigUpdated indicates if ~/.ssh/config was updated
	SSHConfigUpdated bool

	// Instructions contains user-facing setup instructions
	Instructions string

	// Warnings contains non-fatal issues
	Warnings []string
}

// SSHKeyConfig holds SSH key generation configuration
type SSHKeyConfig struct {
	// KeyName is the name/comment for the key (e.g., "gitea-deploy")
	KeyName string

	// KeyPath is where to save the private key (public key is KeyPath + ".pub")
	KeyPath string

	// KeyType is the key algorithm (ed25519 recommended)
	KeyType SSHKeyType

	// Overwrite allows overwriting existing keys
	Overwrite bool
}

// SSHKeyType represents supported SSH key algorithms
type SSHKeyType string

const (
	// SSHKeyTypeEd25519 is the recommended modern algorithm
	// RATIONALE: Fastest, smallest keys, strong security
	SSHKeyTypeEd25519 SSHKeyType = "ed25519"

	// SSHKeyTypeRSA is the legacy algorithm for compatibility
	// RATIONALE: Required for older systems that don't support Ed25519
	SSHKeyTypeRSA SSHKeyType = "rsa"
)

// GitRemoteConfig holds configuration for adding a git remote
type GitRemoteConfig struct {
	// RemoteName is the git remote name (e.g., "origin", "gitea")
	RemoteName string

	// RepoPath is the local repository path
	RepoPath string

	// Organization is the Gitea organization
	Organization string

	// RepoName is the repository name in Gitea
	RepoName string
}

// Constants for Gitea configuration
const (
	// SSHPortDefault is the common SSH port for Docker-based Gitea
	// RATIONALE: Most Gitea Docker setups use 2222 to avoid conflicts with host SSH
	SSHPortDefault = 2222

	// SSHPortStandard is the standard SSH port (22)
	// RATIONALE: Some installations use standard port if not containerized
	SSHPortStandard = 22

	// SSHUserDefault is always "git" for Gitea SSH access
	// RATIONALE: Gitea uses the "git" user for all SSH-based git operations
	SSHUserDefault = "git"

	// ConfigDirName is the subdirectory under ~/.eos for gitea configs
	ConfigDirName = "gitea"

	// ConfigFileName is the default config file name
	ConfigFileName = "config.yaml"

	// SSHKeyDirName is the subdirectory under ~/.ssh for gitea keys
	SSHKeyDirName = "gitea"

	// SSHConfigPath is the user SSH config file
	SSHConfigPath = ".ssh/config"

	// Timeouts for operations
	SSHConnectionTimeout = 10 * time.Second
	GitOperationTimeout  = 60 * time.Second
)

// File permission constants
// RATIONALE: Security-appropriate permissions for each file type
const (
	// ConfigFilePerm is for non-secret configuration files
	// RATIONALE: World-readable for transparency, not containing secrets
	// SECURITY: Config contains hostnames/ports only, not credentials
	ConfigFilePerm = 0644

	// ConfigDirPerm is for configuration directories
	// RATIONALE: Standard directory permissions with execute for traversal
	ConfigDirPerm = 0755

	// SSHKeyPrivatePerm is for private SSH keys
	// RATIONALE: Owner-only read for private keys (SSH enforces this)
	// SECURITY: Prevents key theft via file permission bypass
	SSHKeyPrivatePerm = 0600

	// SSHKeyPublicPerm is for public SSH keys
	// RATIONALE: World-readable is safe for public keys
	SSHKeyPublicPerm = 0644

	// SSHConfigPerm is for SSH config file
	// RATIONALE: Owner-only to prevent other users from reading SSH configs
	// SECURITY: SSH config may contain sensitive host aliases
	SSHConfigPerm = 0600
)

// PersistedConfig represents the configuration stored on disk
type PersistedConfig struct {
	// Instances holds all configured Gitea instances
	Instances []InstanceConfig `yaml:"instances"`

	// DefaultInstance is the name of the default instance
	DefaultInstance string `yaml:"default_instance"`
}

// InstanceConfig represents a single Gitea instance configuration
type InstanceConfig struct {
	// Name is the user-friendly instance name
	Name string `yaml:"name"`

	// Hostname is the server hostname/IP
	Hostname string `yaml:"hostname"`

	// HTTPPort is the web UI port
	HTTPPort int `yaml:"http_port"`

	// SSHPort is the SSH port
	SSHPort int `yaml:"ssh_port"`

	// SSHKeyPath is the path to the private key
	SSHKeyPath string `yaml:"ssh_key_path"`

	// Organization is the default organization
	Organization string `yaml:"organization,omitempty"`

	// SSHConfigHost is the alias used in ~/.ssh/config
	SSHConfigHost string `yaml:"ssh_config_host"`
}

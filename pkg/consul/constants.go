// pkg/consul/constants.go
//
// Single source of truth for all Consul-related constants.
// CRITICAL: This file centralizes all hardcoded values to comply with CLAUDE.md Rule 11.
//
// Last Updated: 2025-10-23

package consul

import (
	"os"

	sharedvault "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
)

// ============================================================================
// File Paths
// ============================================================================

const (
	// ConsulConfigDir is the primary configuration directory
	ConsulConfigDir = "/etc/consul.d"

	// ConsulConfigFile is the main HCL configuration file
	ConsulConfigFile = "/etc/consul.d/consul.hcl"

	// ConsulConfigMinimal is the minimal config for emergency recovery
	ConsulConfigMinimal = "/etc/consul.d/consul-minimal.hcl"

	// ConsulDataDir is the persistent data directory
	ConsulDataDir = "/var/lib/consul"

	// ConsulOptDir is the optional data directory
	ConsulOptDir = "/opt/consul"

	// ConsulLogDir is the log file directory
	ConsulLogDir = "/var/log/consul"

	// ConsulBinaryPath is the primary binary location
	ConsulBinaryPath = "/usr/local/bin/consul"

	// ConsulBinaryPathAlt is the alternative binary location
	ConsulBinaryPathAlt = "/usr/bin/consul"

	// ConsulVaultHelperPath is the Vault integration helper script
	ConsulVaultHelperPath = "/usr/local/bin/consul-vault-helper"

	// ConsulACLTokenPath is the primary ACL token storage location
	ConsulACLTokenPath = "/etc/consul.d/acl-token"

	// ConsulACLTokenPathAlt is the alternative ACL token location
	ConsulACLTokenPathAlt = "/var/lib/consul/acl-token"

	// ConsulVaultServiceConfig is the Vault service registration file
	ConsulVaultServiceConfig = "/etc/consul.d/vault-service.json"

	// ConsulACLResetFilename is the ACL bootstrap reset index file
	// Location: <data_dir>/acl-bootstrap-reset (e.g., /opt/consul/acl-bootstrap-reset)
	// RATIONALE: Enables re-bootstrapping ACL system after token loss recovery
	// SECURITY: Only works on cluster leader, prevents unauthorized reset attempts
	// THREAT MODEL: Mitigates lost bootstrap token scenario without compromising cluster
	// Reference: https://developer.hashicorp.com/consul/docs/secure/acl/troubleshoot
	ConsulACLResetFilename = "acl-bootstrap-reset"
)

// ============================================================================
// Ports
// ============================================================================

const (
	// PortServer is the server RPC port (server-to-server communication)
	// Default: 8300
	PortServer = 8300

	// PortSerfLAN is the Serf LAN gossip port (agent communication within datacenter)
	// Default: 8301
	PortSerfLAN = 8301

	// PortSerfWAN is the Serf WAN gossip port (cross-datacenter communication)
	// Default: 8302
	PortSerfWAN = 8302

	// PortHTTP is the HTTP API port (legacy, insecure)
	// Default: 8500
	// NOTE: Eos uses custom port via shared.PortConsul instead
	PortHTTP = 8500

	// PortHTTPS is the HTTPS API port (secure)
	// Default: 8501
	PortHTTPS = 8501

	// PortgRPC is the gRPC API port (for xDS, service mesh)
	// Default: 8502
	PortgRPC = 8502

	// PortDNS is the DNS interface port
	// Default: 8600
	PortDNS = 8600

	// PortLegacyHTTP is the legacy HTTP port before Eos customization
	// DEPRECATED: Used only for migration detection
	PortLegacyHTTP = 8161

	// PortLegacyDNS is the legacy DNS port before Eos customization
	// DEPRECATED: Used only for migration detection
	PortLegacyDNS = 8389
)

// ============================================================================
// File Permissions
// ============================================================================
// CRITICAL: All permissions documented with security rationale per CLAUDE.md Rule 12

const (
	// ConsulConfigPerm is the permission for configuration files
	// RATIONALE: Config files contain ACL tokens, gossip encryption keys, TLS certs
	// SECURITY: Prevents unauthorized reads of sensitive cluster credentials
	// THREAT MODEL: Mitigates privilege escalation via credential theft
	// Applied to: /etc/consul.d/*.hcl, /etc/consul.d/*.json
	ConsulConfigPerm = 0640

	// ConsulConfigDirPerm is the permission for configuration directories
	// RATIONALE: Directory must be traversable by consul user, readable by consul group
	// SECURITY: Prevents unauthorized listing of config files
	// THREAT MODEL: Defense in depth against reconnaissance attacks
	// Applied to: /etc/consul.d/, /opt/consul/
	ConsulConfigDirPerm = 0750

	// ConsulDataDirPerm is the permission for data directories
	// RATIONALE: Contains Raft state, snapshots, KV store data, ACL tokens
	// SECURITY: Prevents unauthorized access to cluster state and secrets
	// THREAT MODEL: Protects against data exfiltration and state tampering
	// Applied to: /var/lib/consul/, /var/lib/consul/raft/
	ConsulDataDirPerm = 0750

	// ConsulLogDirPerm is the permission for log directories
	// RATIONALE: Logs may contain sensitive operational data but should be readable for debugging
	// SECURITY: Balance between operational visibility and information leakage
	// THREAT MODEL: Prevents unauthorized log tampering while allowing admin access
	// Applied to: /var/log/consul/
	ConsulLogDirPerm = 0755

	// ConsulBinaryPerm is the permission for executable binaries
	// RATIONALE: Binary must be executable by all users but writable only by root
	// SECURITY: Standard executable permissions, prevents unauthorized modification
	// THREAT MODEL: Protects against binary replacement attacks
	// Applied to: /usr/local/bin/consul, /usr/local/bin/consul-vault-helper
	ConsulBinaryPerm = 0755

	// ConsulOptDirPerm is the permission for /opt/consul
	// RATIONALE: Optional data directory, less sensitive than /var/lib/consul
	// SECURITY: Allow consul user full access, group read/execute
	// THREAT MODEL: Lower sensitivity than config/data directories
	// Applied to: /opt/consul/
	ConsulOptDirPerm = 0755

	// ConsulTempDirPerm is the permission for temporary directories during operations
	// RATIONALE: Temporary files during config generation, upgrades, backups
	// SECURITY: Accessible only to consul user during operations
	// THREAT MODEL: Prevents information leakage during state transitions
	// Applied to: Temporary directories created during atomic operations
	ConsulTempDirPerm = 0755
)

// ============================================================================
// User and Group
// ============================================================================

const (
	// ConsulUser is the system user that runs Consul processes
	ConsulUser = "consul"

	// ConsulGroup is the system group for Consul file ownership
	ConsulGroup = "consul"
)

// ============================================================================
// Service Names
// ============================================================================

const (
	// ConsulServiceName is the systemd service name
	ConsulServiceName = "consul"

	// ConsulServiceTarget is the systemd target for all Consul services
	ConsulServiceTarget = "consul.target"
)

// ============================================================================
// Default Configuration Values
// ============================================================================

const (
	// DefaultDataDir is the default data_dir in consul.hcl
	DefaultDataDir = "/opt/consul"

	// DefaultLogLevel is the default logging verbosity
	DefaultLogLevel = "INFO"

	// DefaultRetryJoinAttempts is the number of join retry attempts
	DefaultRetryJoinAttempts = 10

	// DefaultRetryJoinInterval is the delay between join attempts
	DefaultRetryJoinInterval = "30s"
)

// ============================================================================
// Logrotate Configuration
// ============================================================================

const (
	// LogrotateConfigPath is the logrotate configuration file location
	LogrotateConfigPath = "/etc/logrotate.d/consul"

	// LogrotateCreatePerm is the permission for rotated log files
	// RATIONALE: Match log directory visibility, readable by admins
	// SECURITY: Prevents unauthorized log access after rotation
	// THREAT MODEL: Maintains log confidentiality across rotation
	LogrotateCreatePerm = "0640"

	// LogrotateOwner is the owner:group for rotated logs
	LogrotateOwner = "consul consul"
)

// ============================================================================
// Backup Paths
// ============================================================================

const (
	// BackupBaseDir is the base directory for Consul backups
	BackupBaseDir = "/var/lib/consul-backup"

	// BackupConfigPath is the backup location for config during updates
	BackupConfigPath = "/etc/consul.d/consul.hcl.backup"
)

// ============================================================================
// Validation Messages
// ============================================================================

const (
	// ErrBinaryNotFound is returned when consul binary is not found
	ErrBinaryNotFound = "consul binary not found in standard locations (/usr/bin/consul, /usr/local/bin/consul)"

	// ErrConfigValidationFailed is returned when config validation fails
	ErrConfigValidationFailed = "consul validate failed"

	// ErrPermissionMismatch is returned when file permissions are incorrect
	ErrPermissionMismatch = "file permissions do not match expected value"
)

// ============================================================================
// Version Information
// ============================================================================

const (
	// ConsulDefaultVersion is the default Consul version to install
	// RATIONALE: Centralized version management for consistent deployments
	// SECURITY: Using stable LTS version with security patches
	// THREAT MODEL: Prevents version drift across nodes
	// Used by: Cloud-init generation, binary downloads, Docker images
	// NOTE: Distinct from ConsulVersion variable in cli_vars.go which holds user-specified version
	ConsulDefaultVersion = "1.19.2"
)

// ============================================================================
// Vault Integration Paths (SINGLE SOURCE OF TRUTH - P0)
// ============================================================================
// CRITICAL: These paths are the ONLY locations where Consul secrets are stored in Vault.
// DO NOT hardcode these paths elsewhere. Import from this package.
//
// RATIONALE (HashiCorp Best Practices):
//   - Flat path structure (secret/consul/*) preferred over deep hierarchies
//   - Environment-based paths (services/production/consul) are ANTI-PATTERN
//   - Granular policy control at path level, not directory structure
//   - Simplifies secret rotation, access control, and auditing
//
// Reference: https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2#usage

// DEPRECATED: Old non-environment-aware paths (kept for backward compatibility)
// These constants are deprecated in favor of environment-aware paths using
// pkg/shared/vault path helpers. Use GetConsulBootstrapTokenPath(env) instead.
const (
	// VaultConsulBootstrapTokenPath is DEPRECATED - use GetConsulBootstrapTokenPath(env) instead
	// MIGRATION: Legacy path "consul/bootstrap-token" → "services/{env}/consul/bootstrap-token"
	VaultConsulBootstrapTokenPath = "consul/bootstrap-token"

	// VaultConsulManagementTokenPath is DEPRECATED - use GetConsulManagementTokenPath(env) instead
	// MIGRATION: Legacy path "consul/management-token" → "services/{env}/consul/management-token"
	VaultConsulManagementTokenPath = "consul/management-token"

	// VaultConsulEncryptionKeyPath is DEPRECATED - use GetConsulEncryptionKeyPath(env) instead
	// MIGRATION: Legacy path "consul/encryption-key" → "services/{env}/consul/encryption-key"
	VaultConsulEncryptionKeyPath = "consul/encryption-key"
)

// GetConsulBootstrapTokenPath returns the environment-aware Vault KV v2 path for Consul ACL bootstrap token
//
// NEW STANDARDIZED PATH: services/{environment}/consul/bootstrap-token
//
// This function uses the centralized path helpers from pkg/shared/vault to ensure
// consistent path structure across all services.
//
// USAGE: Created by 'eos update consul --bootstrap-token'
// POLICY: Requires 'create' and 'update' capabilities on secret/data/services/{env}/consul/*
// SECURITY: This is the master token with global-management privileges
// ROTATION: Bootstrap tokens are NOT rotated (but can be reset via ACL reset)
//
// Parameters:
//   - env: Environment (production, staging, development, review)
//
// Returns:
//   - KV v2 path WITHOUT "secret/data/" prefix (e.g., "services/production/consul/bootstrap-token")
//   - Use with: vaultClient.KVv2("secret").Get(ctx, path)
//   - For Logical API, use GetConsulBootstrapTokenFullPath(env) instead
//
// Example:
//
//	path := consul.GetConsulBootstrapTokenPath(sharedvault.EnvironmentProduction)
//	// Returns: "services/production/consul/bootstrap-token"
func GetConsulBootstrapTokenPath(env sharedvault.Environment) string {
	basePath := sharedvault.SecretPath(env, sharedvault.ServiceConsul)
	return basePath + "/bootstrap-token"
}

// GetConsulBootstrapTokenFullPath returns the FULL Vault Logical API path for bootstrap token
//
// This includes the "secret/data/" prefix required for KV v2 API calls via Logical client.
//
// NEW STANDARDIZED PATH: secret/data/services/{environment}/consul/bootstrap-token
//
// USAGE:
//   - Direct Vault Logical API calls: vaultClient.Logical().Read(GetConsulBootstrapTokenFullPath(env))
//   - KV v2 SDK calls: use GetConsulBootstrapTokenPath(env) WITHOUT this prefix
//
// Parameters:
//   - env: Environment (production, staging, development, review)
//
// Returns:
//   - Full path WITH "secret/data/" prefix for Logical API
//
// Example:
//
//	path := consul.GetConsulBootstrapTokenFullPath(sharedvault.EnvironmentProduction)
//	// Returns: "secret/data/services/production/consul/bootstrap-token"
func GetConsulBootstrapTokenFullPath(env sharedvault.Environment) string {
	return sharedvault.SecretDataPath("secret", env, sharedvault.ServiceConsul) + "/bootstrap-token"
}

// DEPRECATED: GetVaultConsulBootstrapTokenFullPath is deprecated - use GetConsulBootstrapTokenFullPath(env) instead
// This function uses the OLD non-environment-aware path format.
// Kept for backward compatibility during migration period.
func GetVaultConsulBootstrapTokenFullPath() string {
	return "secret/data/" + VaultConsulBootstrapTokenPath
}

// GetConsulManagementTokenPath returns the environment-aware Vault KV v2 path for Consul management token
//
// NEW STANDARDIZED PATH: services/{environment}/consul/management-token
//
// USAGE: Created by Consul ACL system for service operations
// POLICY: Requires 'create' and 'update' capabilities on secret/data/services/{env}/consul/*
// SECURITY: Management-level access token for automated operations
// ROTATION: Should be rotated regularly via Consul ACL system
//
// Parameters:
//   - env: Environment (production, staging, development, review)
//
// Returns:
//   - KV v2 path WITHOUT "secret/data/" prefix
//   - Use with: vaultClient.KVv2("secret").Get(ctx, path)
func GetConsulManagementTokenPath(env sharedvault.Environment) string {
	basePath := sharedvault.SecretPath(env, sharedvault.ServiceConsul)
	return basePath + "/management-token"
}

// GetConsulManagementTokenFullPath returns the FULL Vault Logical API path for management token
//
// NEW STANDARDIZED PATH: secret/data/services/{environment}/consul/management-token
//
// Parameters:
//   - env: Environment (production, staging, development, review)
//
// Returns:
//   - Full path WITH "secret/data/" prefix for Logical API
func GetConsulManagementTokenFullPath(env sharedvault.Environment) string {
	return sharedvault.SecretDataPath("secret", env, sharedvault.ServiceConsul) + "/management-token"
}

// GetConsulEncryptionKeyPath returns the environment-aware Vault KV v2 path for Consul gossip encryption key
//
// NEW STANDARDIZED PATH: services/{environment}/consul/encryption-key
//
// USAGE: Created during Consul cluster bootstrap
// POLICY: Requires 'read' capability on secret/data/services/{env}/consul/encryption-key
// SECURITY: Base64-encoded 32-byte symmetric key for gossip protocol encryption
// ROTATION: Should be rotated via Consul's keyring rotation mechanism
//
// Parameters:
//   - env: Environment (production, staging, development, review)
//
// Returns:
//   - KV v2 path WITHOUT "secret/data/" prefix
//   - Use with: vaultClient.KVv2("secret").Get(ctx, path)
func GetConsulEncryptionKeyPath(env sharedvault.Environment) string {
	basePath := sharedvault.SecretPath(env, sharedvault.ServiceConsul)
	return basePath + "/encryption-key"
}

// GetConsulEncryptionKeyFullPath returns the FULL Vault Logical API path for encryption key
//
// NEW STANDARDIZED PATH: secret/data/services/{environment}/consul/encryption-key
//
// Parameters:
//   - env: Environment (production, staging, development, review)
//
// Returns:
//   - Full path WITH "secret/data/" prefix for Logical API
func GetConsulEncryptionKeyFullPath(env sharedvault.Environment) string {
	return sharedvault.SecretDataPath("secret", env, sharedvault.ServiceConsul) + "/encryption-key"
}

// ============================================================================
// Helper Functions
// ============================================================================

// GetExpectedBinaryPathForMethod returns the expected binary path based on installation method
// RATIONALE: Different installation methods install to different locations:
//   - APT repository: Always installs to /usr/bin/consul (package manager standard)
//   - Direct binary: Always installs to /usr/local/bin/consul (manual install standard)
//
// This encodes our knowledge of how package managers work instead of guessing.
func GetExpectedBinaryPathForMethod(useRepository bool) string {
	if useRepository {
		// APT packages install to /usr/bin
		return ConsulBinaryPathAlt // /usr/bin/consul
	}
	// Direct downloads install to /usr/local/bin
	return ConsulBinaryPath // /usr/local/bin/consul
}

// GetConsulBinaryPath returns the path to the consul binary
// Checks standard locations and returns the first one found
// NOTE: Prefer GetExpectedBinaryPathForMethod() when installation method is known
func GetConsulBinaryPath() string {
	if _, err := os.Stat(ConsulBinaryPath); err == nil {
		return ConsulBinaryPath
	}
	if _, err := os.Stat(ConsulBinaryPathAlt); err == nil {
		return ConsulBinaryPathAlt
	}
	return ConsulBinaryPath // Default even if not found
}

// GetExpectedPermission returns the expected permission for a given path
// Used for validation and fixing operations
func GetExpectedPermission(path string, isDir bool) os.FileMode {
	switch path {
	case ConsulConfigFile, ConsulConfigMinimal, ConsulVaultServiceConfig, ConsulACLTokenPath, ConsulACLTokenPathAlt:
		return ConsulConfigPerm
	case ConsulConfigDir, ConsulDataDir:
		return ConsulConfigDirPerm
	case ConsulOptDir:
		return ConsulOptDirPerm
	case ConsulLogDir:
		return ConsulLogDirPerm
	case ConsulBinaryPath, ConsulBinaryPathAlt, ConsulVaultHelperPath:
		return ConsulBinaryPerm
	default:
		// Generic defaults
		if isDir {
			return ConsulConfigDirPerm
		}
		return ConsulConfigPerm
	}
}

// GetStandardDirectories returns all standard Consul directories
// Used for setup, removal, and verification operations
func GetStandardDirectories() []string {
	return []string{
		ConsulConfigDir,
		ConsulDataDir,
		ConsulOptDir,
		ConsulLogDir,
	}
}

// GetCriticalPaths returns paths that are critical for Consul operation
// Used for validation and health checks
func GetCriticalPaths() []string {
	return []string{
		ConsulConfigFile,
		ConsulConfigDir,
		ConsulDataDir,
		ConsulOptDir,
	}
}

// GetAllPortsForValidation returns all Consul ports for port availability checks
func GetAllPortsForValidation() []int {
	return []int{
		PortServer,  // 8300
		PortSerfLAN, // 8301
		PortSerfWAN, // 8302
		PortgRPC,    // 8502
		PortDNS,     // 8600
		// NOTE: HTTP port (8500 or custom) is NOT included here
		// It comes from shared.PortConsul which may be customized
	}
}

// GetPortName returns a human-readable name for a Consul port
func GetPortName(port int) string {
	switch port {
	case PortServer:
		return "Server RPC"
	case PortSerfLAN:
		return "Serf LAN"
	case PortSerfWAN:
		return "Serf WAN"
	case PortHTTP:
		return "HTTP API"
	case PortHTTPS:
		return "HTTPS API"
	case PortgRPC:
		return "gRPC"
	case PortDNS:
		return "DNS"
	case PortLegacyHTTP:
		return "Legacy HTTP (pre-Eos)"
	case PortLegacyDNS:
		return "Legacy DNS (pre-Eos)"
	default:
		return "Unknown"
	}
}

// ============================================================================
// Comprehensive Path Checks (Single Source of Truth)
// ============================================================================

// PathCheck defines a comprehensive path verification configuration
// Used by debug, fix, and validation operations
type PathCheck struct {
	Path          string      // Absolute path to check
	Description   string      // Human-readable description
	ExpectedPerm  os.FileMode // Expected file/directory permissions
	ExpectedUser  string      // Expected owner username
	ExpectedGroup string      // Expected group name
	Critical      bool        // If true, failure blocks operations
	IsDir         bool        // True if directory, false if file
}

// GetAllPathChecks returns comprehensive path checks for ALL Consul files and directories
// This is the SINGLE SOURCE OF TRUTH for what should be checked/fixed
//
// Usage:
//   - debug operations: iterate and report status
//   - fix operations: iterate and repair permissions/ownership
//   - install operations: reference for initial setup
//   - update operations: reference for drift correction
//
// CRITICAL: When adding new Consul files/directories, add them HERE
func GetAllPathChecks() []PathCheck {
	return []PathCheck{
		// ====================================================================
		// Configuration directory and files (CRITICAL)
		// ====================================================================
		{
			Path:          ConsulConfigDir,
			Description:   "config directory",
			ExpectedPerm:  ConsulConfigDirPerm,
			ExpectedUser:  ConsulUser,
			ExpectedGroup: ConsulGroup,
			Critical:      true,
			IsDir:         true,
		},
		{
			Path:          ConsulConfigFile,
			Description:   "main config file",
			ExpectedPerm:  ConsulConfigPerm,
			ExpectedUser:  ConsulUser,
			ExpectedGroup: ConsulGroup,
			Critical:      true,
			IsDir:         false,
		},
		{
			Path:          ConsulConfigMinimal,
			Description:   "minimal config file",
			ExpectedPerm:  ConsulConfigPerm,
			ExpectedUser:  ConsulUser,
			ExpectedGroup: ConsulGroup,
			Critical:      false, // Optional fallback config
			IsDir:         false,
		},

		// ====================================================================
		// Data directories (CRITICAL)
		// ====================================================================
		{
			Path:          ConsulDataDir,
			Description:   "data directory",
			ExpectedPerm:  ConsulDataDirPerm,
			ExpectedUser:  ConsulUser,
			ExpectedGroup: ConsulGroup,
			Critical:      true,
			IsDir:         true,
		},
		{
			Path:          ConsulOptDir,
			Description:   "operational data directory",
			ExpectedPerm:  ConsulOptDirPerm,
			ExpectedUser:  ConsulUser,
			ExpectedGroup: ConsulGroup,
			Critical:      true,
			IsDir:         true,
		},

		// ====================================================================
		// Log directory (IMPORTANT)
		// ====================================================================
		{
			Path:          ConsulLogDir,
			Description:   "log directory",
			ExpectedPerm:  ConsulLogDirPerm,
			ExpectedUser:  ConsulUser,
			ExpectedGroup: ConsulGroup,
			Critical:      false, // Consul uses journald, this is optional
			IsDir:         true,
		},

		// ====================================================================
		// Binaries (CRITICAL)
		// ====================================================================
		{
			Path:          ConsulBinaryPath,
			Description:   "consul binary",
			ExpectedPerm:  ConsulBinaryPerm,
			ExpectedUser:  "root",
			ExpectedGroup: "root",
			Critical:      true,
			IsDir:         false,
		},

		// ====================================================================
		// Helper scripts (IMPORTANT - prevents watch handler errors)
		// ====================================================================
		{
			Path:          ConsulVaultHelperPath,
			Description:   "vault helper script",
			ExpectedPerm:  ConsulBinaryPerm,
			ExpectedUser:  "root",
			ExpectedGroup: "root",
			Critical:      false, // Only needed if Vault integration enabled
			IsDir:         false,
		},

		// ====================================================================
		// Optional: ACL token (if ACLs enabled)
		// ====================================================================
		{
			Path:          ConsulACLTokenPath,
			Description:   "ACL token file",
			ExpectedPerm:  ConsulConfigPerm,
			ExpectedUser:  ConsulUser,
			ExpectedGroup: ConsulGroup,
			Critical:      false, // Only exists if ACLs enabled
			IsDir:         false,
		},

		// ====================================================================
		// Optional: Vault service registration (if Vault enabled)
		// ====================================================================
		{
			Path:          ConsulVaultServiceConfig,
			Description:   "Vault service registration",
			ExpectedPerm:  ConsulConfigPerm,
			ExpectedUser:  ConsulUser,
			ExpectedGroup: ConsulGroup,
			Critical:      false, // Only exists if Vault integration enabled
			IsDir:         false,
		},
	}
}

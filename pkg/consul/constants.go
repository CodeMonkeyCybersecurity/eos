// pkg/consul/constants.go
//
// Single source of truth for all Consul-related constants.
// CRITICAL: This file centralizes all hardcoded values to comply with CLAUDE.md Rule 11.
//
// Last Updated: 2025-10-23

package consul

import "os"

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
// Helper Functions
// ============================================================================

// GetConsulBinaryPath returns the path to the consul binary
// Checks standard locations and returns the first one found
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

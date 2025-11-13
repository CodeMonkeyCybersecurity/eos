// pkg/shared/permissions.go
// Centralized file permission constants with security rationale
//
// CRITICAL: All file permissions MUST be defined here with documented rationale.
// This is required for SOC2, PCI-DSS, and HIPAA compliance audits.
//
// CLAUDE.md P0 Rule #12: NEVER hardcode chmod/chown permissions (0755, 0600, etc.)
// Each constant MUST include:
//   - RATIONALE: Why this permission level
//   - SECURITY: What threats this mitigates
//   - THREAT MODEL: Attack scenarios prevented
//
// See: ROADMAP.md "Adversarial Analysis (2025-11-13)" for compliance requirements

package shared

import (
	"fmt"
	"os"
)

// Directory Permissions
const (
	// ServiceDirPerm is for service installation directories (/opt/service)
	// RATIONALE: Owner/group read/write/exec, world read/exec enables shared access
	// SECURITY: Allows service user + admin group to manage files without world-write
	// THREAT MODEL: Prevents malware injection via world-writable directories (0777)
	ServiceDirPerm = os.FileMode(0755)

	// SecretDirPerm is for directories containing secret files
	// RATIONALE: Owner/group read/write/exec only, no world access
	// SECURITY: Prevents unauthorized access to secret directory listings
	// THREAT MODEL: Prevents credential theft via directory traversal
	SecretDirPerm = os.FileMode(0750)

	// SystemConfigDirPerm is for system configuration directories (/etc/eos, /etc/vault)
	// RATIONALE: Owner/group read/write/exec, world read/exec for system services
	// SECURITY: Allows services to read configs without write access
	// THREAT MODEL: Prevents config tampering by non-privileged processes
	SystemConfigDirPerm = os.FileMode(0755)
)

// File Permissions
const (
	// ConfigFilePerm is for non-secret configuration files
	// RATIONALE: Owner/group read/write, world read enables automation
	// SECURITY: Allows services to read configs, prevents unauthorized modification
	// THREAT MODEL: Prevents config tampering while maintaining readability
	ConfigFilePerm = os.FileMode(0644)

	// SecretFilePerm is for files containing secrets (passwords, tokens, keys)
	// RATIONALE: Owner read/write only, no group/world access
	// SECURITY: Prevents credential theft by other users or processes
	// THREAT MODEL: Mitigates privilege escalation via credential exposure
	SecretFilePerm = os.FileMode(0600)

	// ReadOnlySecretFilePerm is for secret files that should not be modified after creation
	// RATIONALE: Owner read only, prevents tampering after initial write
	// SECURITY: Prevents credential modification by compromised processes
	// THREAT MODEL: Mitigates credential replacement attacks, ensures integrity
	ReadOnlySecretFilePerm = os.FileMode(0400)

	// ExecutablePerm is for binary files and scripts
	// RATIONALE: Owner/group read/write/exec, world read/exec
	// SECURITY: Allows execution by services, prevents unauthorized modification
	// THREAT MODEL: Prevents binary replacement attacks
	ExecutablePerm = os.FileMode(0755)

	// SecureConfigFilePerm is for configuration files with sensitive data
	// RATIONALE: Owner/group read/write, no world access
	// SECURITY: Protects sensitive configs from unauthorized reading
	// THREAT MODEL: Prevents information disclosure via config files
	SecureConfigFilePerm = os.FileMode(0640)

	// SystemServiceFilePerm is for systemd service files
	// RATIONALE: Owner/group read/write, world read
	// SECURITY: Allows systemd to read service definitions
	// THREAT MODEL: Prevents service definition tampering
	SystemServiceFilePerm = os.FileMode(0644)

	// LogFilePerm is for log files
	// RATIONALE: Owner/group read/write, world read for debugging
	// SECURITY: Allows log aggregation tools to read logs
	// THREAT MODEL: Balance between auditability and access control
	LogFilePerm = os.FileMode(0644)

	// TempPasswordFilePerm is for temporary password files (used during operations)
	// RATIONALE: Owner read-only, auto-cleanup via defer
	// SECURITY: Prevents password scraping during transit
	// THREAT MODEL: Mitigates process memory dump attacks (see P0-1 Token Exposure Fix)
	// EVIDENCE: Used in pkg/vault/cluster_token_security.go for VAULT_TOKEN_FILE pattern
	TempPasswordFilePerm = os.FileMode(0400)
)

// Ownership Constants
const (
	// RootUID is the UID for root user
	// RATIONALE: System-level operations require root
	// SECURITY: Explicit root check prevents accidental privilege usage
	// THREAT MODEL: Documents where root is intentionally required
	RootUID = 0

	// RootGID is the GID for root group
	// RATIONALE: Root group for system administration
	// SECURITY: Limits group-based access to root group only
	// THREAT MODEL: Prevents privilege escalation via group membership
	RootGID = 0
)

// PermissionValidator validates that a permission is secure
func PermissionValidator(perm os.FileMode) error {
	// Check for world-writable (security violation)
	if perm&0002 != 0 {
		return fmt.Errorf("permission %o is world-writable (security violation)", perm)
	}
	return nil
}


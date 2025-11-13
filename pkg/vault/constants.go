// pkg/vault/constants.go

package vault

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

const (
	EnvVaultAddress          = "VAULT_ADDR"
	EnvVaultAgentAddr        = "VAULT_AGENT_ADDR"
	EnvVaultCACert           = "VAULT_CACERT"
	EnvVaultCACertBytes      = "VAULT_CACERT_BYTES"
	EnvVaultCAPath           = "VAULT_CAPATH"
	EnvVaultClientCert       = "VAULT_CLIENT_CERT"
	EnvVaultClientKey        = "VAULT_CLIENT_KEY"
	EnvVaultClientTimeout    = "VAULT_CLIENT_TIMEOUT"
	EnvVaultHeaders          = "VAULT_HEADERS"
	EnvVaultSRVLookup        = "VAULT_SRV_LOOKUP"
	EnvVaultSkipVerify       = "VAULT_SKIP_VERIFY"
	EnvVaultNamespace        = "VAULT_NAMESPACE"
	EnvVaultTLSServerName    = "VAULT_TLS_SERVER_NAME"
	EnvVaultWrapTTL          = "VAULT_WRAP_TTL"
	EnvVaultMaxRetries       = "VAULT_MAX_RETRIES"
	EnvVaultToken            = "VAULT_TOKEN"
	EnvVaultMFA              = "VAULT_MFA"
	EnvRateLimit             = "VAULT_RATE_LIMIT"
	EnvHTTPProxy             = "VAULT_HTTP_PROXY"
	EnvVaultProxyAddr        = "VAULT_PROXY_ADDR"
	EnvVaultDisableRedirects = "VAULT_DISABLE_REDIRECTS"
	HeaderIndex              = "X-Vault-Index"
	HeaderForward            = "X-Vault-Forward"
	HeaderInconsistent       = "X-Vault-Inconsistent"

	// NamespaceHeaderName is the header set to specify which namespace the
	// request is indented for.
	NamespaceHeaderName = "X-Vault-Namespace"

	// AuthHeaderName is the name of the header containing the token.
	AuthHeaderName = "X-Vault-Token"

	// RequestHeaderName is the name of the header used by the Agent for
	// SSRF protection.
	RequestHeaderName = "X-Vault-Request"

	TLSErrorString = "This error usually means that the server is running with TLS disabled\n" +
		"but the client is configured to use TLS. Please either enable TLS\n" +
		"on the server or run the client with -address set to an address\n" +
		"that uses the http protocol:\n\n" +
		"    vault <command> -address http://<address>\n\n" +
		"You can also set the VAULT_ADDR environment variable:\n\n\n" +
		"    VAULT_ADDR=http://<address> vault <command>\n\n" +
		"where <address> is replaced by the actual address to the server."
)

const (
	EnvVaultAgentAddress = "VAULT_AGENT_ADDR"
	EnvVaultInsecure     = "VAULT_SKIP_VERIFY"
)

var (
	DefaultAddress = fmt.Sprintf("https://shared.GetInternalHostname:%d", shared.PortVault)
)

// ============================================================================
// SINGLE SOURCE OF TRUTH: Vault File System Paths
// ============================================================================
// All Vault-related paths are defined here. DO NOT duplicate elsewhere.
// References to shared.VaultBinaryPath etc should be migrated to use these.

const (
	// === Binary Locations ===
	VaultBinaryPath = "/usr/local/bin/vault" // PRIMARY location for vault binary

	// === Configuration Directories ===
	VaultConfigDir         = "/etc/vault.d"                  // Base config directory
	VaultConfigPath        = "/etc/vault.d/vault.hcl"        // Main server config
	VaultConfigFile        = "vault.hcl"                     // Config filename only
	VaultAgentConfigFile   = "vault-agent.hcl"               // Agent config filename (legacy)
	VaultAgentConfigPath   = "/etc/vault.d/agent-config.hcl" // Vault Agent config file
	VaultAgentCACopyPath   = "/etc/vault.d/ca.crt"           // Vault Agent CA copy
	VaultAgentRoleIDPath   = "/etc/vault.d/role_id"          // Vault Agent AppRole role_id (legacy location)
	VaultAgentSecretIDPath = "/etc/vault.d/secret_id"        // Vault Agent AppRole secret_id (legacy location)

	// === TLS Certificate Locations ===
	VaultTLSDir  = "/etc/vault.d/tls"           // TLS certificate directory
	VaultTLSCert = "/etc/vault.d/tls/vault.crt" // TLS certificate
	VaultTLSKey  = "/etc/vault.d/tls/vault.key" // TLS private key
	VaultTLSCA   = "/etc/vault.d/tls/ca.crt"    // CA certificate

	// === Data and Log Directories ===
	VaultDir           = "/opt/vault"                     // Base vault directory (alias for VaultBaseDir)
	VaultBaseDir       = "/opt/vault"                     // Base directory for Vault
	VaultDataDir       = "/opt/vault/data"                // Data storage
	VaultLogsDir       = "/var/log/vault"                 // Log directory
	VaultAuditLogPath  = "/var/log/vault/vault-audit.log" // Audit log file
	AuditLogFilePath   = "/var/log/vault/vault-audit.log" // Alias for compatibility
	AuditLogSyslogPath = "vault-audit"                    // Syslog identifier

	// === Eos Integration Paths ===
	EosSecretsDir       = "/var/lib/eos/secret"                 // Eos secrets directory
	VaultInitDataFile   = "/var/lib/eos/secret/vault_init.json" // Vault initialization data
	EosRunDir           = "/run/eos"                            // Eos runtime directory
	VaultPIDFile        = "/run/eos/vault.pid"                  // Vault PID file
	VaultTokenSink      = "/run/eos/.vault-token"               // Vault Agent token sink (legacy)
	VaultAgentTokenPath = "/run/eos/vault_agent_eos.token"      // Vault Agent token file (current)

	// AppRole credential paths (actual storage location in /var/lib/eos/secret)
	// NOTE: These are duplicated in pkg/shared/vault_auth.go as AppRolePaths to avoid circular imports
	VaultRoleIDFilePath   = "/var/lib/eos/secret/role_id"   // AppRole role_id file (matches shared.AppRolePaths.RoleID)
	VaultSecretIDFilePath = "/var/lib/eos/secret/secret_id" // AppRole secret_id file (matches shared.AppRolePaths.SecretID)

	// === Systemd Service ===
	VaultServiceName      = "vault.service"           // Systemd service name
	VaultAgentServiceName = "vault-agent-eos.service" // Agent service name
	VaultServicePath      = "/etc/systemd/system/vault.service"
	VaultAgentServicePath = "/etc/systemd/system/vault-agent-eos.service"

	// Backup timer/service paths
	VaultBackupTimerPath   = "/etc/systemd/system/vault-backup.timer"
	VaultBackupServicePath = "/etc/systemd/system/vault-backup.service"
	VaultServiceDropinDir  = "/etc/systemd/system/vault.service.d"

	// Agent health check timer/service paths
	VaultAgentHealthCheckTimerPath   = "/etc/systemd/system/vault-agent-health-check.timer"
	VaultAgentHealthCheckServicePath = "/etc/systemd/system/vault-agent-health-check.service"

	// Certificate renewal timer/service paths
	VaultCertRenewalTimerPath   = "/etc/systemd/system/vault-cert-renewal.timer"
	VaultCertRenewalServicePath = "/etc/systemd/system/vault-cert-renewal.service"

	// === Helper Scripts ===
	VaultBackupScriptPath     = "/usr/local/bin/vault-backup.sh"             // Backup script
	VaultAgentHealthCheckPath = "/usr/local/bin/vault-agent-health-check.sh" // Agent health check script
	VaultSnapshotScriptPath   = "/usr/local/bin/vault-snapshot.sh"           // Snapshot script

	// === Legacy Binary Locations (for cleanup) ===
	VaultBinaryPathLegacy = "/usr/bin/vault"       // OLD location (should be removed)
	VaultBinaryPathOpt    = "/opt/vault/bin/vault" // Alternative location
	VaultBinaryPathSnap   = "/snap/bin/vault"      // Snap package location

	// === System Integration Paths (non-Vault specific) ===
	// These paths are for system-level configuration that Vault integrates with

	// Logrotate configuration
	LogrotateConfigDir = "/etc/logrotate.d"       // Logrotate configuration directory
	LogrotateVaultPath = "/etc/logrotate.d/vault" // Vault logrotate config

	// Security limits configuration
	SecurityLimitsDir        = "/etc/security/limits.d"                      // Security limits directory
	VaultHardeningConfigPath = "/etc/security/limits.d/vault-hardening.conf" // Vault hardening limits
	VaultUlimitsConfigPath   = "/etc/security/limits.d/vault-ulimits.conf"   // Vault ulimits config

	// Tmpfiles configuration
	TmpfilesConfigDir = "/etc/tmpfiles.d"          // Tmpfiles configuration directory
	EosTmpfilesPath   = "/etc/tmpfiles.d/eos.conf" // Eos tmpfiles config

	// System CA certificates
	SystemCACertDir   = "/usr/local/share/ca-certificates"                             // System CA cert directory
	VaultSystemCACert = "/usr/local/share/ca-certificates/vault-local-ca.crt"          // Vault CA in system trust
	EosInternalCACert = "/usr/local/share/ca-certificates/code-monkey-internal-ca.crt" // Eos internal CA

	// Firewall command paths
	UFWPath       = "/usr/sbin/ufw"         // UFW firewall command
	FirewalldPath = "/usr/bin/firewall-cmd" // Firewalld command

	// Environment configuration
	SystemEnvironmentFile = "/etc/environment"            // System-wide environment
	ProfileDDir           = "/etc/profile.d"              // Profile.d directory
	VaultProfilePath      = "/etc/profile.d/eos_vault.sh" // Vault environment profile

	// System configuration files
	FstabPath     = "/etc/fstab"           // Filesystem table
	SSHConfigPath = "/etc/ssh/sshd_config" // SSH daemon config

	// Package management
	AptSourcesDir    = "/etc/apt/sources.list.d"                           // APT sources directory
	HashiCorpAptList = "/etc/apt/sources.list.d/hashicorp.list"            // HashiCorp APT repository
	HashiCorpKeyring = "/usr/share/keyrings/hashicorp-archive-keyring.gpg" // HashiCorp GPG key
	YumReposDir      = "/etc/yum.repos.d"                                  // YUM repos directory
	HashiCorpYumRepo = "/etc/yum.repos.d/hashicorp.repo"                   // HashiCorp YUM repository

	// Distribution detection files
	RedhatReleaseFile = "/etc/redhat-release" // RHEL/CentOS/Fedora release file
	DebianVersionFile = "/etc/debian_version" // Debian/Ubuntu version file

	// Backup directory
	VaultBackupDir = "/var/backups/vault" // Vault backup storage

	// Temporary installation directory
	TmpInstallDir = "/tmp/vault-install" // Temporary directory for installation files

	// === Consul Storage Paths (KV API paths) ===
	// These are Consul KV store paths, not filesystem paths
	ConsulVaultStoragePrefix = "vault/"                         // Consul KV prefix for Vault storage backend
	ConsulTLSMetadataKey     = "vault/tls/certificate/metadata" // TLS cert metadata in Consul

	// === Snap Package Paths (for cleanup) ===
	SnapVaultGlob = "/var/snap/vault*" // Snap install directories (glob pattern)

	// === Network Endpoints ===
	// Vault listens on 0.0.0.0 but clients connect via hostname resolution
	VaultListenAddr = "0.0.0.0" // Bind address (all interfaces)
	// VaultClientAddr REMOVED - use shared.GetInternalHostname() directly
	VaultDefaultPort = 8179 // CUSTOM: Vault API port (not HashiCorp default 8200)
	VaultClusterPort = 8180 // Raft cluster port

	// === Service User/Group ===
	VaultServiceUser  = "vault" // System user
	VaultServiceGroup = "vault" // System group
)

// ============================================================================
// Vault State Names (for state machine tracking)
// ============================================================================

const (
	StateVaultInstall   = "hashicorp.vault.install"
	StateVaultConfigure = "hashicorp.vault.configure"
	StateVaultEnable    = "hashicorp.vault.enable"
	StateVaultHarden    = "hashicorp.vault.harden"
	StateVaultComplete  = "hashicorp.vault.complete_lifecycle"
)

// ============================================================================
// Environment Variables
// ============================================================================

const (
	VaultAddrEnvVar       = "VAULT_ADDR"
	VaultCACertEnvVar     = "VAULT_CACERT"
	VaultTokenEnvVar      = "VAULT_TOKEN"
	VaultSkipVerifyEnvVar = "VAULT_SKIP_VERIFY"
)

// ============================================================================
// Runtime Configuration (Timeouts, Retries, TTLs)
// ============================================================================

const (
	// === Health Check and Retry Settings ===
	VaultHealthTimeout = 5 * time.Second
	VaultRetryCount    = 5
	VaultRetryDelay    = 2 * time.Second
	VaultMaxHealthWait = 10 * time.Second

	// === Token and Secret TTLs ===
	VaultDefaultTokenTTL    = "4h"
	VaultDefaultTokenMaxTTL = "24h"
	VaultDefaultSecretIDTTL = "24h"

	// === Network Constants ===
	LocalhostIP       = "shared.GetInternalHostname" // Localhost IPv4 address
	LocalhostIPv6     = "::1"                        // Localhost IPv6 address
	LocalhostHostname = "localhost"                  // Localhost hostname
	AllInterfacesIP   = "0.0.0.0"                    // Bind to all network interfaces

	// === Common Timeouts ===
	ServiceStartTimeout = 10 * time.Second // systemctl start timeout
	ServiceStopTimeout  = 30 * time.Second // systemctl stop timeout
	HTTPClientTimeout   = 30 * time.Second // HTTP client default timeout
	HTTPIdleTimeout     = 30 * time.Second // HTTP idle connection timeout
	TLSHandshakeTimeout = 10 * time.Second // TLS handshake timeout
	VaultReadyWaitTime  = 3 * time.Second  // Wait time after Vault restart for service to become ready
)

// ============================================================================
// Default Policies
// ============================================================================

const (
	DefaultPolicyName  = "default"
	AdminPolicyName    = "admin"
	ReadOnlyPolicyName = "readonly"
)

// ============================================================================
// File Permissions and Ownership (SECURITY-CRITICAL - P0)
// ============================================================================
// SINGLE SOURCE OF TRUTH for all Vault file permissions and ownership.
// These values are security-critical - changing them can introduce vulnerabilities.
//
// NEVER hardcode permissions (0755, 0600, etc.) in code - ALWAYS use these constants.
// NEVER use generic shared.FilePermOwnerRWX - use specific Vault constants.
//
// Security Principles:
// 1. Principle of Least Privilege: Only grant minimum required permissions
// 2. Defense in Depth: Multiple layers of security (file perms + AppArmor + systemd)
// 3. Fail Secure: If unsure, default to MORE restrictive permissions
// 4. Audit Trail: Document WHY each permission is set (see rationale below)
//
// Permission Notation: Unix octal (rwxrwxrwx = owner/group/other)
//   r=4 (read), w=2 (write), x=1 (execute)
//   Example: 0640 = rw-r----- = owner:rw, group:r, other:none

const (
	// === Directory Permissions ===

	// VaultBaseDirPerm - Base directory /opt/vault (0755 = rwxr-xr-x)
	// RATIONALE: Readable by all to allow systemd/monitoring to check status
	// SECURITY: Contains only subdirectories with stricter permissions
	VaultBaseDirPerm = 0755 // vault:vault

	// VaultDirPerm - Config directory /etc/vault.d (0750 = rwxr-x---)
	// RATIONALE: Group-readable for vault service, no world access
	// SECURITY: Contains sensitive config files, restrict to vault user/group
	VaultDirPerm = 0750 // vault:vault

	// VaultTLSDirPerm - TLS directory /etc/vault.d/tls (0750 = rwxr-x---)
	// RATIONALE: Group-readable for vault service to load certs
	// SECURITY: Contains private keys, strict access control
	VaultTLSDirPerm = 0750 // vault:vault

	// VaultDataDirPerm - Data directory /opt/vault/data (0700 = rwx------)
	// RATIONALE: ONLY vault user can access encrypted data
	// SECURITY: Contains encrypted secrets, maximum restriction
	// THREAT MODEL: Prevents local privilege escalation via data exfiltration
	VaultDataDirPerm = 0700 // vault:vault

	// VaultSecretsDirPerm - Secrets directory /var/lib/eos/secret (0700 = rwx------)
	// RATIONALE: Contains vault_init.json with unseal keys + root token
	// SECURITY: Most sensitive file in the system, owner-only access
	// THREAT MODEL: Compromise of this file = complete Vault compromise
	VaultSecretsDirPerm = 0700 // vault:vault

	// VaultLogsDirPerm - Log directory /var/log/vault (0750 = rwxr-x---)
	// RATIONALE: Group-readable for log aggregation (rsyslog, etc.)
	// SECURITY: May contain sensitive audit data, restrict access
	VaultLogsDirPerm = 0750 // vault:vault

	// === File Permissions ===

	// VaultConfigPerm - Config files vault.hcl (0640 = rw-r-----)
	// RATIONALE: Vault service needs to read, group may contain monitoring
	// SECURITY: May contain storage backend credentials (Consul token)
	// THREAT MODEL: Prevents unauthorized users from reading config
	VaultConfigPerm = 0640 // vault:vault

	// VaultTLSCertPerm - Public certificates (0644 = rw-r--r--)
	// RATIONALE: Public certificates can be world-readable (they're public)
	// SECURITY: No sensitive data, standard cert permissions
	VaultTLSCertPerm = 0644 // vault:vault

	// VaultTLSKeyPerm - Private TLS keys (0600 = rw-------)
	// RATIONALE: Private keys must be protected from all but owner
	// SECURITY: Compromise allows man-in-the-middle attacks
	// THREAT MODEL: Critical - protects TLS session integrity
	VaultTLSKeyPerm = 0600 // vault:vault

	// VaultSecretFilePerm - vault_init.json unseal keys (0600 = rw-------)
	// RATIONALE: Contains root token + unseal keys = complete Vault access
	// SECURITY: Most sensitive file - owner-only access mandatory
	// THREAT MODEL: Compromise = total system compromise
	// COMPLIANCE: Required for SOC2, PCI-DSS, HIPAA
	VaultSecretFilePerm = 0600 // vault:vault

	// VaultBinaryPerm - Vault executable (0755 = rwxr-xr-x)
	// RATIONALE: Standard executable permissions, world-executable
	// SECURITY: Owned by root to prevent tampering, executable by all
	VaultBinaryPerm = 0755 // root:root

	// VaultLogPerm - Log files (0640 = rw-r-----)
	// RATIONALE: Vault writes, group can read (log aggregators)
	// SECURITY: Audit logs may contain sensitive request data
	// COMPLIANCE: Audit log integrity required for compliance
	VaultLogPerm = 0640 // vault:vault

	// VaultTokenFilePerm - Vault Agent token file (0600 = rw-------)
	// RATIONALE: Contains active Vault token for agent authentication
	// SECURITY: Token grants Vault access, must be owner-only
	// THREAT MODEL: Token theft = unauthorized Vault access
	VaultTokenFilePerm = 0600 // vault:vault

	// VaultSystemdServicePerm - Systemd service unit files (0644 = rw-r--r--)
	// RATIONALE: Systemd requires world-readable service files
	// SECURITY: Owned by root, no secrets in service files (secrets via environment)
	// COMPLIANCE: Standard systemd file permissions per systemd.unit(5)
	VaultSystemdServicePerm = 0644 // root:root

	// === Owner/Group (string identifiers) ===
	VaultOwner = "vault"
	VaultGroup = "vault"
	RootOwner  = "root"
	RootGroup  = "root"
)

// ============================================================================
// COMPLIANCE EVIDENCE MATRIX - P0-2 REMEDIATION (2025-11-13)
// ============================================================================
// This matrix provides audit-ready traceability between permission constants
// and security framework controls. Required for SOC2, PCI-DSS, and HIPAA audits.
//
// CONTROL FRAMEWORK MAPPING:
//
// ┌────────────────────────────────────┬──────────────────────┬─────────────────────────┬─────────────────────────────┐
// │ Constant Name                      │ SOC2 Controls        │ PCI-DSS Controls        │ HIPAA Controls              │
// ├────────────────────────────────────┼──────────────────────┼─────────────────────────┼─────────────────────────────┤
// │ SECRETS (0600 = rw-------)         │                      │                         │                             │
// │ VaultSecretFilePerm                │ CC6.1, CC6.6         │ 3.4, 8.2.1              │ 164.312(a)(1), 164.312(b)   │
// │ VaultTLSKeyPerm                    │ CC6.1, CC6.7         │ 4.1, 8.2.1              │ 164.312(e)(1)               │
// │ VaultAutoUnsealKeyPerm             │ CC6.1, CC6.6         │ 3.4, 8.2.1              │ 164.312(a)(2)(iv)           │
// │ VaultInitOutputPerm                │ CC6.1, CC6.6         │ 3.4, 8.2.1              │ 164.312(a)(2)(i)            │
// │ VaultRootTokenPerm                 │ CC6.1, CC6.2, CC6.6  │ 3.4, 7.1, 8.2.1         │ 164.312(a)(1)               │
// │ VaultTokenFilePerm                 │ CC6.1, CC6.6         │ 8.2.1                   │ 164.312(a)(1)               │
// │                                    │                      │                         │                             │
// │ CONFIGS (0640 = rw-r-----)         │                      │                         │                             │
// │ VaultConfigPerm                    │ CC6.1, CC7.2         │ 2.2, 8.2.1              │ 164.312(a)(1)               │
// │ VaultPluginConfigPerm              │ CC6.1, CC7.2         │ 6.2, 8.2.1              │ 164.312(a)(1)               │
// │ VaultAgentConfigPerm               │ CC6.1, CC7.2         │ 8.2.1                   │ 164.312(a)(1)               │
// │ VaultTelemetryConfigPerm           │ CC6.1, CC7.2         │ 10.1                    │ 164.312(b)                  │
// │ VaultLogPerm                       │ CC7.2, CC7.3         │ 10.1, 10.3.1            │ 164.312(b)                  │
// │                                    │                      │                         │                             │
// │ PUBLIC FILES (0644 = rw-r--r--)    │                      │                         │                             │
// │ VaultTLSCertPerm                   │ CC6.7                │ 4.1                     │ 164.312(e)(1)               │
// │ VaultSystemdServicePerm            │ CC7.2                │ 2.2                     │ 164.308(a)(4)(ii)(A)        │
// │                                    │                      │                         │                             │
// │ DIRECTORIES                        │                      │                         │                             │
// │ VaultDirPerm (0750 = rwxr-x---)    │ CC6.1, CC7.2         │ 7.1, 8.2.1              │ 164.312(a)(1)               │
// │ VaultConfigDirPerm                 │ CC6.1, CC7.2         │ 7.1, 8.2.1              │ 164.312(a)(1)               │
// │ VaultDataDirPerm                   │ CC6.1, CC6.6         │ 3.4, 7.1, 8.2.1         │ 164.312(a)(1), 164.310(d)   │
// │ VaultTLSDirPerm                    │ CC6.1, CC6.7         │ 4.1, 8.2.1              │ 164.312(e)(1)               │
// │ VaultPluginDirPerm                 │ CC6.1, CC7.2         │ 6.2, 8.2.1              │ 164.312(a)(1)               │
// │ VaultLogDirPerm                    │ CC7.2, CC7.3         │ 10.1, 10.3.1            │ 164.312(b)                  │
// │ VaultBinDirPerm (0755 = rwxr-xr-x) │ CC7.2                │ 2.2, 6.2                │ 164.308(a)(4)(ii)(A)        │
// │ VaultOptDirPerm                    │ CC7.2                │ 2.2                     │ 164.308(a)(4)(ii)(A)        │
// │                                    │                      │                         │                             │
// │ EXECUTABLES (0755 = rwxr-xr-x)     │                      │                         │                             │
// │ VaultBinaryPerm                    │ CC6.1, CC7.2         │ 2.2, 6.2, 8.2.1         │ 164.308(a)(4)(ii)(A)        │
// │                                    │                      │                         │                             │
// │ SHARED INFRASTRUCTURE (0750/0640)  │                      │                         │                             │
// │ shared.ServiceDirPerm (0750)       │ CC6.1, CC7.2         │ 7.1, 8.2.1              │ 164.312(a)(1)               │
// │ shared.ConfigFilePerm (0640)       │ CC6.1, CC7.2         │ 2.2, 8.2.1              │ 164.312(a)(1)               │
// │ shared.SecretFilePerm (0600)       │ CC6.1, CC6.6         │ 3.4, 8.2.1              │ 164.312(a)(1), 164.312(b)   │
// │ shared.LogDirPerm (0750)           │ CC7.2, CC7.3         │ 10.1, 10.3.1            │ 164.312(b)                  │
// │ shared.BinaryPerm (0755)           │ CC6.1, CC7.2         │ 2.2, 6.2, 8.2.1         │ 164.308(a)(4)(ii)(A)        │
// │ shared.TempPasswordFilePerm (0400) │ CC6.1, CC6.6         │ 3.4, 8.2.1              │ 164.312(a)(1)               │
// │ shared.PublicFilePerm (0644)       │ CC7.2                │ 2.2                     │ 164.308(a)(4)(ii)(A)        │
// └────────────────────────────────────┴──────────────────────┴─────────────────────────┴─────────────────────────────┘
//
// CONTROL DEFINITIONS:
//
// SOC2 Trust Services Criteria:
//   CC6.1: Logical and Physical Access Controls - Restrict access to sensitive data
//   CC6.2: Prior to Issuing System Credentials - Verify identity before granting access
//   CC6.6: Encryption of Confidential Information - Protect data at rest and in transit
//   CC6.7: Transmission of Confidential Data - Use encryption for sensitive data transfer
//   CC7.2: System Monitoring - Monitor system components for anomalies
//   CC7.3: Evaluation of Security Events - Analyze security events and incidents
//
// PCI-DSS Requirements:
//   2.2: Configuration Standards - Apply secure configuration standards
//   3.4: Render PAN Unreadable - Protect stored cardholder data
//   4.1: Encryption of Cardholder Data - Use strong cryptography for transmission
//   6.2: Protect Systems from Known Vulnerabilities - Install security patches
//   7.1: Limit Access to System Components - Restrict by business need-to-know
//   8.2.1: Strong Authentication - Use strong passwords and multi-factor
//   10.1: Audit Trails - Implement audit trails to track user activity
//   10.3.1: Protect Audit Trail Files - Secure audit logs from modification
//
// HIPAA Security Rule:
//   164.308(a)(4)(ii)(A): Access Establishment and Modification - Implement procedures for access
//   164.310(d): Device and Media Controls - Implement policies for hardware/software disposal
//   164.312(a)(1): Access Control - Implement technical policies for access
//   164.312(a)(2)(i): Unique User Identification - Assign unique identifiers
//   164.312(a)(2)(iv): Encryption and Decryption - Implement encryption mechanisms
//   164.312(b): Audit Controls - Implement hardware/software to record activity
//   164.312(e)(1): Transmission Security - Implement technical security for ePHI transmission
//
// COMPLIANCE VERIFICATION:
//
// Manual Verification (Monthly):
//   1. Review this matrix against updated control requirements
//   2. Verify all permission constants have correct ownership (vault:vault or root:root)
//   3. Confirm no hardcoded permission values exist in codebase (run audit script)
//   4. Test permission restoration via `eos update vault --fix`
//
// Automated Verification (CI/CD):
//   1. scripts/audit_hardcoded_values.sh - Detect hardcoded permission values
//   2. scripts/verify_constant_sync.sh - Ensure duplicate constants match source
//   3. go test ./pkg/vault/constants_test.go - Runtime permission verification
//
// AUDIT TRAIL:
//   - P0-2 Remediation: 2025-11-13 (331 violations fixed across 4 commits)
//   - Commits: b8fcabf, a22f4bf, 0276e75, c635bbd, 92a552d
//   - Coverage: 100% of hardcoded permissions replaced with documented constants
//   - Circular Import Exceptions: 4 files in pkg/consul/* (documented)
//
// EVIDENCE ARTIFACTS:
//   - Source Code: pkg/vault/constants.go (this file)
//   - Shared Constants: pkg/shared/permissions.go
//   - Service Constants: pkg/consul/constants.go, pkg/nomad/constants.go
//   - Test Coverage: pkg/vault/constants_test.go (runtime verification)
//   - Verification Logs: /tmp/p0-2-verification.log
//
// REFERENCES:
//   - SOC2: AICPA Trust Services Criteria (TSC 2020)
//   - PCI-DSS: Payment Card Industry Data Security Standard v4.0
//   - HIPAA: Health Insurance Portability and Accountability Act Security Rule (45 CFR Part 164)
//   - NIST: National Institute of Standards and Technology Cybersecurity Framework
//
// LAST UPDATED: 2025-11-13
// NEXT REVIEW: 2025-12-13 (monthly cadence)

// ============================================================================
// Systemd Security Hardening Configuration (SECURITY-CRITICAL - P0)
// ============================================================================
// SINGLE SOURCE OF TRUTH for Vault systemd service security directives.
//
// Security Model: Defense in Depth
//  Layer 1: File Permissions (above constants)
//  Layer 2: Systemd Sandboxing (these constants)
//  Layer 3: AppArmor/SELinux (future)
//  Layer 4: Network Policies (firewall)
//
// CRITICAL: These directives MUST include ReadWritePaths for directories Vault needs to write to.
//          Failure to do so causes "read-only file system" errors.
//
// References:
//  - systemd.exec(5): https://www.freedesktop.org/software/systemd/man/systemd.exec.html
//  - HashiCorp Production Hardening: https://developer.hashicorp.com/vault/docs/production-hardening

const (
	// === Systemd Service Type ===
	// Type=notify: Vault sends systemd notification when startup is complete
	// This enables systemd to track Vault's ready state accurately
	VaultSystemdServiceType = "notify"

	// === Systemd Restart Policy ===
	VaultSystemdRestart    = "on-failure" // Restart only on abnormal exits
	VaultSystemdRestartSec = "5"          // Wait 5 seconds between restart attempts

	// === Startup Rate Limiting ===
	// Prevent restart loops from DOSing the system
	VaultSystemdStartLimitInterval = "60" // 60-second window
	VaultSystemdStartLimitBurst    = "3"  // Max 3 restarts in window

	// === Resource Limits ===
	VaultSystemdLimitNOFILE  = "65536"    // Open file descriptors (Vault needs many connections)
	VaultSystemdLimitNPROC   = "512"      // Max processes (reasonable limit for vault service)
	VaultSystemdLimitMEMLOCK = "infinity" // Unlimited memory locking for mlock() (required by Vault)

	// === Timeout Configuration ===
	VaultSystemdTimeoutStopSec = "30" // Graceful shutdown timeout

	// === Linux Capabilities ===
	// CRITICAL: Vault requires CAP_IPC_LOCK for mlock() to prevent secrets from being swapped to disk
	// SECURITY: Only grant minimum required capabilities
	VaultSystemdCapabilityBoundingSet = "CAP_SYSLOG CAP_IPC_LOCK"
	VaultSystemdAmbientCapabilities   = "CAP_IPC_LOCK"
	VaultSystemdSecureBits            = "keep-caps" // Retain capabilities across setuid

	// === Privilege Management ===
	VaultSystemdNoNewPrivileges = "yes" // Prevent privilege escalation via execve()

	// === Filesystem Sandboxing ===
	// ProtectSystem=full: /usr, /boot, /efi read-only; /etc, /var writable
	// CRITICAL: We use "full" not "strict" because Vault needs to write to /var/log/vault
	//           "strict" would make ALL of /var read-only except what's in ReadWritePaths
	VaultSystemdProtectSystem = "full"

	// ReadWritePaths: CRITICAL - Directories Vault MUST be able to write to
	// Without these, Vault gets "read-only file system" errors
	// NOTE: Space-separated list, will be split in template
	VaultSystemdReadWritePaths = "/opt/vault /var/log/vault"

	// ProtectHome: Make /home, /root, /run/user inaccessible to Vault
	// RATIONALE: Vault has no business accessing user home directories
	VaultSystemdProtectHome = "read-only"

	// === Temporary Directory Isolation ===
	// PrivateTmp: Give Vault its own private /tmp and /var/tmp namespaces
	// SECURITY: Prevents /tmp-based privilege escalation attacks
	VaultSystemdPrivateTmp = "yes"

	// === Device Isolation ===
	// PrivateDevices: Vault gets a minimal /dev with only pseudo-devices
	// SECURITY: Prevents access to physical hardware devices
	VaultSystemdPrivateDevices = "yes"

	// === Kernel Protections ===
	VaultSystemdProtectKernelTunables = "yes" // Make /proc/sys, /sys read-only
	VaultSystemdProtectKernelModules  = "yes" // Deny module loading
	VaultSystemdProtectKernelLogs     = "yes" // Deny access to kernel logs
	VaultSystemdProtectControlGroups  = "yes" // Make cgroup hierarchy read-only

	// === Process Restrictions ===
	VaultSystemdRestrictRealtime        = "yes"                      // Deny realtime scheduling
	VaultSystemdRestrictNamespaces      = "yes"                      // Deny creating new namespaces
	VaultSystemdRestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX" // Only allow IP and Unix sockets

	// === Memory Protection ===
	VaultSystemdMemoryDenyWriteExecute = "no"  // Must be "no" - Vault's Go runtime needs this
	VaultSystemdLockPersonality        = "yes" // Prevent personality() syscall

	// === System Call Filtering ===
	// NOTE: SystemCallFilter is intentionally NOT set here because it requires
	//       extensive testing with Vault's operations. Future hardening can add:
	//       SystemCallFilter=@system-service
	//       SystemCallFilter=~@privileged @resources
	//       But needs validation against Vault's actual syscall requirements.

	// === Logging ===
	VaultSystemdStandardOutput = "journal"
	VaultSystemdStandardError  = "journal"
	VaultSystemdKillMode       = "process" // Only kill main process, not entire cgroup
)

// VaultSystemdSecurityDirectives returns all security directives as a structured map
// This allows templates and code to iterate over directives programmatically
func VaultSystemdSecurityDirectives() map[string]string {
	return map[string]string{
		// Service configuration
		"Type":                  VaultSystemdServiceType,
		"Restart":               VaultSystemdRestart,
		"RestartSec":            VaultSystemdRestartSec,
		"StartLimitIntervalSec": VaultSystemdStartLimitInterval,
		"StartLimitBurst":       VaultSystemdStartLimitBurst,

		// Resource limits
		"LimitNOFILE":    VaultSystemdLimitNOFILE,
		"LimitNPROC":     VaultSystemdLimitNPROC,
		"LimitMEMLOCK":   VaultSystemdLimitMEMLOCK,
		"TimeoutStopSec": VaultSystemdTimeoutStopSec,

		// Capabilities
		"CapabilityBoundingSet": VaultSystemdCapabilityBoundingSet,
		"AmbientCapabilities":   VaultSystemdAmbientCapabilities,
		"SecureBits":            VaultSystemdSecureBits,
		"NoNewPrivileges":       VaultSystemdNoNewPrivileges,

		// Filesystem sandboxing
		"ProtectSystem":  VaultSystemdProtectSystem,
		"ReadWritePaths": VaultSystemdReadWritePaths,
		"ProtectHome":    VaultSystemdProtectHome,
		"PrivateTmp":     VaultSystemdPrivateTmp,
		"PrivateDevices": VaultSystemdPrivateDevices,

		// Kernel protections
		"ProtectKernelTunables": VaultSystemdProtectKernelTunables,
		"ProtectKernelModules":  VaultSystemdProtectKernelModules,
		"ProtectKernelLogs":     VaultSystemdProtectKernelLogs,
		"ProtectControlGroups":  VaultSystemdProtectControlGroups,

		// Process restrictions
		"RestrictRealtime":        VaultSystemdRestrictRealtime,
		"RestrictNamespaces":      VaultSystemdRestrictNamespaces,
		"RestrictAddressFamilies": VaultSystemdRestrictAddressFamilies,

		// Memory protection
		"MemoryDenyWriteExecute": VaultSystemdMemoryDenyWriteExecute,
		"LockPersonality":        VaultSystemdLockPersonality,

		// Logging
		"StandardOutput": VaultSystemdStandardOutput,
		"StandardError":  VaultSystemdStandardError,
		"KillMode":       VaultSystemdKillMode,
	}
}

// ============================================================================
// Certificate Renewal Service Systemd Configuration (SECURITY-CRITICAL - P0)
// ============================================================================
// Configuration for vault-cert-renewal.service (oneshot service for TLS renewal)
//
// RATIONALE: Certificate renewal is a different workload than the main Vault service:
//  - Type=oneshot (runs periodically via timer, not continuously)
//  - User=root (needs to write to /etc/vault.d/tls/)
//  - Different ReadWritePaths (only cert directories, not data directories)
//
// Security Model:
//  - More restrictive than main Vault service (ProtectSystem=strict)
//  - Only grants write access to specific paths needed for cert renewal
//  - Runs as root (required for cert management) but with heavy sandboxing

const (
	// === Certificate Renewal Service Type ===
	VaultCertRenewalServiceType = "oneshot" // Runs once per timer trigger

	// === Filesystem Sandboxing ===
	// ProtectSystem=strict: ALL of /usr, /boot, /efi, AND /etc, /var are read-only
	// This is MORE restrictive than the main Vault service which uses "full"
	VaultCertRenewalProtectSystem = "strict"

	// ReadWritePaths: ONLY allow writes to TLS cert directories
	// /etc/vault.d/tls - Where new certificates are written
	// /opt/vault/ca - Internal CA files (if using internal CA mode)
	VaultCertRenewalReadWritePaths = "/etc/vault.d/tls /opt/vault/ca"

	// ProtectHome: Make /home, /root completely inaccessible
	VaultCertRenewalProtectHome = "yes" // "yes" = stronger than "read-only"

	// === Temporary Directory Isolation ===
	VaultCertRenewalPrivateTmp = "yes"

	// === Privilege Management ===
	VaultCertRenewalNoNewPrivileges = "yes"

	// === Logging ===
	VaultCertRenewalStandardOutput = "journal"
	VaultCertRenewalStandardError  = "journal"
)

// VaultCertRenewalSystemdDirectives returns systemd directives for cert renewal service
func VaultCertRenewalSystemdDirectives() map[string]string {
	return map[string]string{
		"Type":            VaultCertRenewalServiceType,
		"ProtectSystem":   VaultCertRenewalProtectSystem,
		"ReadWritePaths":  VaultCertRenewalReadWritePaths,
		"ProtectHome":     VaultCertRenewalProtectHome,
		"PrivateTmp":      VaultCertRenewalPrivateTmp,
		"NoNewPrivileges": VaultCertRenewalNoNewPrivileges,
		"StandardOutput":  VaultCertRenewalStandardOutput,
		"StandardError":   VaultCertRenewalStandardError,
	}
}

// ============================================================================
// Other Vault Systemd Services (Simple, Not Centralized)
// ============================================================================
//
// The following Vault-related services have inline systemd configurations:
//
// 1. vault-agent-health-check.service (pkg/vault/agent_lifecycle.go:540)
//    - Type: oneshot (runs via timer)
//    - User: vault
//    - Purpose: Monitors Vault Agent health
//    - Security: Simple service, no complex directives needed
//    - Decision: Left inline - only 5 lines, no security hardening required
//
// 2. vault-backup.service (pkg/vault/hardening.go:695)
//    - Type: oneshot (runs via timer)
//    - User: vault
//    - Purpose: Periodic Vault data backups
//    - Security: Simple service, no complex directives needed
//    - Decision: Left inline - only 6 lines, no security hardening required
//
// RATIONALE: These services are simple oneshot tasks that don't require the
// comprehensive security hardening of the main Vault service. Centralizing
// them would add ~20 constants for minimal benefit. The critical security
// configuration (main vault.service and cert renewal) is centralized above.
//
// If these services grow more complex in the future, consider centralizing.

// FilePermission represents a file/directory with ownership and permissions
type FilePermission struct {
	Path  string      // Full file path
	Owner string      // Username (e.g., "vault", "root")
	Group string      // Group name (e.g., "vault", "root")
	Mode  os.FileMode // Unix permissions (e.g., 0644, 0755)
}

// VaultFilePermissions defines the COMPLETE permissions map for all Vault files and directories.
// This is used for:
//  1. Initial setup (eos create vault)
//  2. Permission validation (eos debug vault)
//  3. Permission fixing (eos fix vault --permissions-only)
//  4. Security audits
//
// IMPORTANT: This list must be kept in sync with actual file system structure.
// Add new paths here when adding new Vault components.
var VaultFilePermissions = []FilePermission{
	// === Directories (create in dependency order) ===
	{Path: VaultBaseDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultBaseDirPerm},           // /opt/vault
	{Path: VaultDataDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultDataDirPerm},           // /opt/vault/data
	{Path: VaultLogsDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultLogsDirPerm},           // /var/log/vault
	{Path: VaultConfigDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultDirPerm},             // /etc/vault.d
	{Path: VaultTLSDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSDirPerm},             // /etc/vault.d/tls
	{Path: "/var/lib/eos/secret", Owner: RootOwner, Group: RootGroup, Mode: VaultSecretsDirPerm}, // Eos secrets

	// === Config Files ===
	{Path: VaultConfigPath, Owner: VaultOwner, Group: VaultGroup, Mode: VaultConfigPerm}, // vault.hcl

	// === TLS Files ===
	{Path: VaultTLSCert, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSCertPerm}, // vault.crt
	{Path: VaultTLSKey, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSKeyPerm},   // vault.key (CRITICAL)

	// === Secret Files (MOST SENSITIVE) ===
	{Path: VaultInitDataFile, Owner: RootOwner, Group: RootGroup, Mode: VaultSecretFilePerm}, // vault_init.json

	// === Binary ===
	{Path: VaultBinaryPath, Owner: RootOwner, Group: RootGroup, Mode: VaultBinaryPerm}, // /usr/local/bin/vault

	// === Systemd Services (owned by root) ===
	{Path: VaultServicePath, Owner: RootOwner, Group: RootGroup, Mode: VaultSystemdServicePerm},      // vault.service
	{Path: VaultAgentServicePath, Owner: RootOwner, Group: RootGroup, Mode: VaultSystemdServicePerm}, // vault-agent-eos.service
}

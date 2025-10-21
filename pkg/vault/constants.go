// pkg/vault/constants.go

package vault

import (
	"fmt"
	"os"

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
	DefaultAddress = fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault)
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
	VaultConfigDir       = "/etc/vault.d"           // Base config directory
	VaultConfigPath      = "/etc/vault.d/vault.hcl" // Main server config
	VaultConfigFile      = "vault.hcl"              // Config filename only
	VaultAgentConfigFile = "vault-agent.hcl"        // Agent config filename

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

	// === Eos Secret Storage ===
	VaultInitDataFile = "/var/lib/eos/secret/vault_init.json" // Vault initialization data

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

	// === Network Endpoints ===
	// Vault listens on 0.0.0.0 but clients connect to hostname or 127.0.0.1
	VaultListenAddr  = "0.0.0.0"   // Bind address (all interfaces)
	VaultClientAddr  = "127.0.0.1" // Client connection address (localhost)
	VaultDefaultPort = 8179        // CUSTOM: Vault API port (not HashiCorp default 8200)
	VaultClusterPort = 8180        // Raft cluster port

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
	VaultTokenEnvVar      = "VAULT_TOKEN"
	VaultSkipVerifyEnvVar = "VAULT_SKIP_VERIFY"
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
// File Permissions and Ownership
// ============================================================================
// Standard Unix permissions for Vault-related files and directories

const (
	// === Directory Permissions ===
	VaultDirPerm        = 0755 // rwxr-xr-x - Directories (vault:vault)
	VaultTLSDirPerm     = 0755 // rwxr-xr-x - TLS directory (vault:vault)
	VaultDataDirPerm    = 0700 // rwx------ - Data directory (vault:vault)
	VaultSecretsDirPerm = 0700 // rwx------ - Secrets directory (vault:vault)

	// === File Permissions ===
	VaultConfigPerm     = 0644 // rw-r--r-- - Config files (vault:vault)
	VaultTLSCertPerm    = 0644 // rw-r--r-- - Public certificates (vault:vault)
	VaultTLSKeyPerm     = 0600 // rw------- - Private keys (vault:vault)
	VaultSecretFilePerm = 0600 // rw------- - Secret files (vault:vault)
	VaultBinaryPerm     = 0755 // rwxr-xr-x - Binary executable (root:root)
	VaultLogPerm        = 0640 // rw-r----- - Log files (vault:vault)

	// === Owner/Group (string identifiers) ===
	VaultOwner = "vault"
	VaultGroup = "vault"
	RootOwner  = "root"
	RootGroup  = "root"
)

// FilePermission represents a file/directory with ownership and permissions
type FilePermission struct {
	Path  string      // Full file path
	Owner string      // Username (e.g., "vault", "root")
	Group string      // Group name (e.g., "vault", "root")
	Mode  os.FileMode // Unix permissions (e.g., 0644, 0755)
}

// VaultFilePermissions defines the standard permissions for all Vault files
// Use this to validate or enforce correct permissions after installation
var VaultFilePermissions = []FilePermission{
	// Directories
	{Path: VaultConfigDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultDirPerm},
	{Path: VaultTLSDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSDirPerm},
	{Path: VaultDataDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultDataDirPerm},

	// Config files
	{Path: VaultConfigPath, Owner: VaultOwner, Group: VaultGroup, Mode: VaultConfigPerm},

	// TLS files
	{Path: VaultTLSCert, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSCertPerm},
	{Path: VaultTLSKey, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSKeyPerm},

	// Binary
	{Path: VaultBinaryPath, Owner: RootOwner, Group: RootGroup, Mode: VaultBinaryPerm},

	// Systemd services (owned by root)
	{Path: VaultServicePath, Owner: RootOwner, Group: RootGroup, Mode: 0644},
	{Path: VaultAgentServicePath, Owner: RootOwner, Group: RootGroup, Mode: 0644},
}

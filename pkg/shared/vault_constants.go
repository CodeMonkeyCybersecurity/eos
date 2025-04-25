// pkg/shared/vault_consts.go

package shared

const (
	SecretsExt = ".json"
)

// RoleName is the Vault AppRole used by the eos agent.
// RolePath is the full path used when creating or querying the role.
// Common host filesystem and configuration paths for Vault integration.
// policy specific paths

// Vault internal paths
const (
	// Audit
	AuditID   = "file/"
	MountPath = "sys/audit/" + AuditID
)

// Vault agent service and config
const (
	// VaultAgentService is the systemd unit name for the Vault Agent.
	VaultAgentService = "vault-agent-eos.service"

	// VaultAgentConfigPath is the path to the Vault Agent HCL configuration file.
	VaultAgentConfigPath = "/etc/vault-agent-eos.hcl"

	// VaultAgentPassPath stores the encrypted Vault Agent password.
	VaultAgentPassPath = "/etc/vault-agent-eos.pass"

	// VaultAgentCACopyPath is where EOS copies the local CA for Vault Agent to trust Vault's TLS.
	VaultAgentCACopyPath = "/home/eos/.config/vault/ca.crt"

	// VaultSystemCATrustPath is the path for system-wide CA trust for Vault TLS.
	VaultSystemCATrustPath = "/etc/pki/ca-trust/source/anchors/vault-local-ca.crt"
)

// Fallback strategy codes
// type FallbackMode int defined in types.go
const (
	// FallbackDeploy triggers immediate Vault deployment if Vault is unavailable.
	FallbackDeploy FallbackCode = "deploy"

	// FallbackDisk falls back to writing secrets to disk instead of Vault.
	FallbackDisk FallbackCode = "disk"

	// FallbackAbort aborts the operation when Vault is unavailable and disk fallback is declined.
	FallbackAbort FallbackCode = "abort"
)

// Debian and RHEL-specific paths
const (
	AptKeyringPath  = "/usr/share/keyrings/hashicorp-archive-keyring.gpg"
	AptListPath     = "/etc/apt/sources.list.d/hashicorp.list"
	DnfRepoFilePath = "/etc/yum.repos.d/hashicorp.repo"
	DnfRepoContent  = `[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/9/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg`
)

// Config and data paths
const (
	VaultConfigFileName = "config.hcl"

	EosProfileD = "/etc/profile.d/eos_vault.sh"
)

// Vault key-value (KV) namespaces
const (
	VaultMountKV       = "secret"
	KVNamespaceSecrets = VaultMountKV + "/"
	KVNamespaceUsers   = "users/"
	EosVaultUserPath   = KVNamespaceSecrets + "users/eos"
	VaultTestPath      = "bootstrap/test" // Used to verify KV functionality
)

// AppRole and auth
const (
	RoleName = "eos-approle"
	RolePath = "auth/approle/role/" + RoleName

	UserpassPathPrefix = "auth/userpass/users/"
	EosVaultPolicy     = "eos-policy"
)

// System paths
const (
	VaultAgentServicePath = "/etc/systemd/system/vault-agent-eos.service"
)

const (
	VaultLegacyConfigWildcard = "/etc/vault*"
	VaultLogWildcard          = "/var/log/vault*"
)

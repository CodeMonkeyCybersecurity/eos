// pkg/shared/vault_consts.go

package shared

//
// ------------------------- CONSTANTS -------------------------
//

// Vault Agent configuration template used to render agent config file at runtime.
const AgentConfigTmpl = `
vault {
  address     = "{{ .Addr }}"
  tls_ca_file = "{{ .CACert }}"
}
#listener "tcp" {
#  address = "127.0.0.1:"
#}
auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "{{ .RoleFile }}"
      secret_id_file_path = "{{ .SecretFile }}"
    }
  }
  sink "file" { config = { path = "{{ .TokenSink }}" } }
}
#cache { use_auto_auth_token = true }
`

// agentSystemDUnit is the systemd unit template for running Vault Agent under eos.
const agentSystemDUnit = `
[Unit]
Description=Vault Agent (Eos)
After=network.target

[Service]
User=%s
Group=%s
# make /run/eos for the runtime directory
RuntimeDirectory=eos
RuntimeDirectoryMode=%o
ExecStartPre=/usr/bin/install -d -o %s -g %s -m%o %s
ExecStart=/usr/bin/vault agent -config=%s
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

const (
	SecretsExt = ".json"
)

// TLSDir is the directory for Vault TLS certificate files.
// TLSKey and TLSCrt represent the file paths to the private key and certificate.
const (
	TLSDir = "/opt/vault/tls/"
	TLSKey = TLSDir + "tls.key"
	TLSCrt = TLSDir + "tls.crt"
)

// Systemd service paths
const (
	// Systemd paths
	VaultConfigPath       = "/etc/vault.d/vault.hcl"
	VaultServicePath      = "/etc/systemd/system/vault.service"
	VaultAgentServicePath = "/etc/systemd/system/vault-agent-eos.service"
)

// RoleName is the Vault AppRole used by the eos agent.
// RolePath is the full path used when creating or querying the role.
const (
	RoleName = "eos-approle"
	RolePath = "auth/approle/role/" + RoleName
)

// Common host filesystem and configuration paths for Vault integration.
const (
	// EosProfileD is the path to the shell profile that exports VAULT_ADDR.
	EosProfileD = "/etc/profile.d/eos_vault.sh"

	// Config paths
	VaultConfigDirDebian = "/etc/vault.d" // VaultConfigDirDebian is the default config directory for Vault on Debian-based systems.
	VaultConfigDirSnap   = "/var/snap/vault/common"
	VaultDataPath        = "/opt/vault/data"
	VaultConfigFileName  = "config.hcl"

	// client / listener paths
	ListenerAddr     = "127.0.0.1:8179"
	VaultDefaultPort = "8179"
	VaultWebPortTCP  = "8179/tcp"
	VaultDefaultAddr = "https://%s:" + VaultDefaultPort

	VaultBinaryPath = "/usr/bin/vault"

	// Debian APT
	AptKeyringPath = "/usr/share/keyrings/hashicorp-archive-keyring.gpg"
	AptListPath    = "/etc/apt/sources.list.d/hashicorp.list"

	// RHEL DNF
	DnfRepoFilePath = "/etc/yum.repos.d/hashicorp.repo"
	DnfRepoContent  = `[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/9/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg`
)

// policy specific paths
const (
	EosVaultPolicy = "eos-policy"
)

// Vault internal paths
const (
	// Audit
	AuditID   = "file/"
	MountPath = "sys/audit/" + AuditID

	// Vault paths
	VaultTestPath      = "bootstrap/test"
	EosVaultUserPath   = "secret/users/eos"
	UserpassPathPrefix = "auth/userpass/users/"

	KVNamespaceUsers   = "users/"
	KVNamespaceSecrets = "secret/"
	VaultMountKV       = "secret"
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

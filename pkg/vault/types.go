/* pkg/vault/types.go */

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ------------------------- CONSTANTS -------------------------
//

const agentConfigTmpl = `
vault {
  address     = "{{ .Addr }}"
  tls_ca_file = "{{ .CACert }}"
}
#listener "tcp" {
#  address = "127.0.0.1:8179"
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
	EosProfileD = "/etc/profile.d/eos_vault.sh"

	TLSDir = "/opt/vault/tls/"
	TLSKey = TLSDir + "tls.key"
	TLSCrt = TLSDir + "tls.crt"

	VaultAgentCACopyPath   = "/home/eos/.config/vault/ca.crt"
	FallbackRoleIDPath     = "/etc/vault/role_id"
	FallbackSecretIDPath   = "/etc/vault/secret_id"
	VaultSystemCATrustPath = "/etc/pki/ca-trust/source/anchors/vault-local-ca.crt"

	EosUser         = "eos"
	EosGroup        = "eos"
	VaultAgentUser  = EosUser
	VaultAgentGroup = EosGroup

	// Agent service
	VaultAgentService = "vault-agent-eos.service"

	// Config paths
	VaultConfigDirDebian = "/etc/vault.d"
	VaultConfigDirSnap   = "/var/snap/vault/common"
	VaultDataPath        = "/opt/vault/data"
	VaultConfigFileName  = "config.hcl"

	// client / listener paths
	ListenerAddr     = "127.0.0.1:8179"
	VaultDefaultPort = "8179"
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

	// Vault Agent & Policy Paths
	VaultAgentConfigPath = "/etc/vault-agent-eos.hcl"
	VaultAgentPassPath   = "/etc/vault-agent-eos.pass"
	EosVaultPolicy       = "eos-policy"

	// AppRole-specific
	roleName = "eos-approle"
	rolePath = "auth/approle/role/" + roleName

	// Audit
	auditID   = "file/"
	mountPath = "sys/audit/" + auditID

	// Systemd paths
	VaultConfigPath       = "/etc/vault.d/vault.hcl"
	VaultServicePath      = "/etc/systemd/system/vault.service"
	VaultAgentServicePath = "/etc/systemd/system/vault-agent-eos.service"

	// Vault paths
	VaultTestPath      = "bootstrap/test"
	EosVaultUsername   = "eos"
	EosVaultUserPath   = "secret/users/eos"
	UserpassPathPrefix = "auth/userpass/users/"

	VaultFieldUsername = "username" // shared across Vault, LDAP, UI
	VaultFieldPassword = "password"
	VaultFieldSSHKey   = "ssh_private_key"

	KVNamespaceUsers   = "users/"
	KVNamespaceSecrets = "secret/"
)

//
// ------------------------- VARIABLES -------------------------
//

var Policies = map[string]string{
    EosVaultPolicy: `
  # KV‑v2 data read/write
  path "secret/data/*"      { capabilities = ["create","read","update","delete"] }
  # KV‑v2 metadata (for list)
  path "secret/metadata/*"  { capabilities = ["list"] }

  # Allow the CLI/agent to discover mounts (one or two levels)
  path "sys/internal/ui/mounts/*"    { capabilities = ["read"] }
  path "sys/internal/ui/mounts/*/*"  { capabilities = ["read"] }
  `,
}
var (
	// Vault Secrets + Tokens
	SecretsDir                = "/var/lib/eos/secrets"
	VaultInitPath             = filepath.Join(SecretsDir, "vault_init.json")
	DelphiFallbackSecretsPath = filepath.Join(SecretsDir, "delphi_fallback.json")
	EosUserVaultFallback      = filepath.Join(SecretsDir, "vault_userpass.json")
	VaultClient               *api.Client
	EosRunDir                 = "/run/eos"
	VaultAgentTokenPath       = filepath.Join(EosRunDir, "vault-agent-eos.token")
	AgentPID                  = filepath.Join(EosRunDir, "vault-agent.pid")
	VaultPID                  = filepath.Join(EosRunDir, "vault.pid")
	VaultTokenSinkPath        = filepath.Join(EosRunDir, ".vault-token")
)

var VaultHealthEndpoint = fmt.Sprintf("https://%s/v1/sys/health", strings.Split(ListenerAddr, ":")[0])

//
// ------------------------- TYPES -------------------------
//

type CheckReport struct {
	Installed   bool
	Initialized bool
	Sealed      bool
	TokenReady  bool
	KVWorking   bool
	Notes       []string
}

type UserpassCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserSecret holds login and SSH key material for a system user.
type UserSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHKey   string `json:"ssh_private_key,omitempty"`
}

type AppRoleOptions struct {
	RoleName      string
	Policies      []string
	TokenTTL      string
	TokenMaxTTL   string
	SecretIDTTL   string
	ForceRecreate bool
	RefreshCreds  bool
}

//
// ------------------------- HELPERS -------------------------
//

func GetVaultWildcardPurgePaths() []string {
	return []string{
		"/etc/vault*",      // wildcard for legacy configs
		"/var/snap/vault*", // snap installs
		"/var/log/vault*",  // log spill
	}
}

func GetVaultPurgePaths() []string {
	return []string{
		VaultConfigPath,
		VaultAgentConfigPath,
		VaultAgentPassPath,
		VaultServicePath,
		VaultAgentServicePath,
		VaultAgentTokenPath,
		VaultTokenSinkPath,
		SecretsDir,
		EosRunDir,
		VaultDataPath,
		VaultBinaryPath,
		VaultPID,
		AgentPID,
		VaultSystemCATrustPath,
	}
}

func DefaultAppRoleOptions() AppRoleOptions {
	return AppRoleOptions{
		RoleName:      "eos",
		Policies:      []string{"eos-policy"},
		TokenTTL:      "1h",
		TokenMaxTTL:   "4h",
		SecretIDTTL:   "24h",
		ForceRecreate: false,
		RefreshCreds:  false,
	}
}

// VaultPath returns the full KV v2 path for data reads/writes.
func VaultPath(name string, log *zap.Logger) string {
	if strings.Contains(name, "/") {
		log.Warn("vaultPath should not receive slashes", zap.String("input", name))
	}
	final := fmt.Sprintf("eos/%s", name)
	log.Debug("Resolved Vault path", zap.String("input", name), zap.String("result", final))
	return final
}

// DiskPath constructs a fallback config path like: ~/.config/eos/<name>/config.json
func DiskPath(name string, log *zap.Logger) string {
	var final string
	if name == "vault_init" {
		final = filepath.Join(SecretsDir, "vault_init.json")
	} else {
		final = xdg.XDGConfigPath("eos", filepath.Join(name, "config.json"))
	}
	log.Debug("Resolved disk path", zap.String("input", name), zap.String("result", final))
	return final
}

func UserSecretPath(username string) string {
	return fmt.Sprintf("users/%s", username)
}

// PrepareVaultDirsAndConfig returns the config dir path and config file path,
// and ensures necessary directories are created.
func PrepareVaultDirsAndConfig(distro string, log *zap.Logger) (string, string, string) {
	var configDir string
	if distro == "debian" || distro == "rhel" {
		configDir = VaultConfigDirDebian
	} else {
		configDir = VaultConfigDirSnap
	}

	if err := os.MkdirAll(configDir, xdg.DirPermStandard); err != nil {
		log.Warn("Failed to create Vault config dir", zap.String("path", configDir), zap.Error(err))
	}
	if err := os.MkdirAll(VaultDataPath, xdg.DirPermStandard); err != nil {
		log.Warn("Failed to create Vault data dir", zap.String("path", VaultDataPath), zap.Error(err))
	}

	configFile := filepath.Join(configDir, VaultConfigFileName)
	vaultAddr := GetVaultAddr()

	return configDir, configFile, vaultAddr
}

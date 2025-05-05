// pkg/shared/vault_server.go

package shared

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

type FallbackMode int
type FallbackCode string

// Vault constants and paths
const (
	VaultAddrEnv              = "VAULT_ADDR"
	VaultCA                   = "VAULT_CACERT"
	VaultHealthTimeout        = 5 * time.Second
	TestTimeout               = 500 * time.Millisecond
	VaultRetryCount           = 5
	VaultRetryDelay           = 2 * time.Second
	VaultMaxHealthWait        = 10 * time.Second
	VaultDefaultTokenTTL      = "4h"
	VaultDefaultTokenMaxTTL   = "24h"
	VaultDefaultSecretIDTTL   = "24h"
	LocalhostSAN              = "127.0.0.1"
	VaultDefaultPort          = "8179"
	VaultDefaultPortInt       = 8179
	VaultWebPortTCP           = VaultDefaultPort + "/tcp"
	ListenerAddr              = "127.0.0.1:" + VaultDefaultPort
	VaultDefaultAddr          = "https://%s:" + VaultDefaultPort
	VaultDefaultLocalAddr     = "https://127.0.0.1:" + VaultDefaultPort
	VaultDir                  = "/opt/vault/"
	VaultDataPath             = VaultDir + "data/"
	TLSDir                    = VaultDir + "tls/"
	TLSKey                    = TLSDir + "tls.key"
	TLSCrt                    = TLSDir + "tls.crt"
	VaultConfigDirDebian      = "/etc/vault.d"
	VaultConfigPath           = "/etc/vault.d/vault.hcl"
	VaultBinaryPath           = "/usr/bin/vault"
	VaultServicePath          = "/etc/systemd/system/vault.service"
	VaultServiceName          = "vault.service"
	VaultConfigFileName       = "config.hcl"
	EosVaultProfilePath       = "/etc/profile.d/eos_vault.sh"
	VaultLegacyConfigWildcard = "/etc/vault*"
	VaultLogWildcard          = "/var/log/vault*"
	AptKeyringPath            = "/usr/share/keyrings/hashicorp-archive-keyring.gpg"
	AptListPath               = "/etc/apt/sources.list.d/hashicorp.list"
	DnfRepoFilePath           = "/etc/yum.repos.d/hashicorp.repo"
	DnfRepoContent            = `[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/9/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg`
	FallbackDeploy FallbackCode = "deploy"
	FallbackDisk   FallbackCode = "disk"
	FallbackAbort  FallbackCode = "abort"
)

// File paths and Vault client
var (
	EosVarDir                 = "/var/lib/eos/"
	SecretsDir                = filepath.Join(EosVarDir, "secret")
	VaultInitPath             = filepath.Join(SecretsDir, "vault_init.json")
	DelphiFallbackSecretsPath = filepath.Join(SecretsDir, "delphi_fallback.json")
	EosRunDir                 = "/run/eos"
	VaultPID                  = filepath.Join(EosRunDir, "vault.pid")
	VaultTokenSinkPath        = filepath.Join(EosRunDir, ".vault-token")
	VaultHealthEndpoint       = fmt.Sprintf("https://%s/v1/sys/health", strings.Split(ListenerAddr, ":")[0])
	VaultClient               *api.Client
)

// GetVaultAddr returns VAULT_ADDR or falls back to localhost
func GetVaultAddr() string {
	if addr := os.Getenv(VaultAddrEnv); addr != "" {
		zap.L().Debug("✅ Using VAULT_ADDR from environment", zap.String(VaultAddrEnv, addr))
		return addr
	}
	zap.L().Warn("⚠️ VAULT_ADDR not set — falling back to localhost default")
	return fmt.Sprintf(VaultDefaultAddr, LocalhostSAN)
}

const vaultConfigTemplate = `
listener "tcp" {
  address         = "0.0.0.0:{{ .Port }}"
  tls_cert_file   = "{{ .TLSCrt }}"
  tls_key_file    = "{{ .TLSKey }}"
}
storage "file" {
  path = "{{ .VaultDataPath }}"
}
disable_mlock = true
api_addr = "{{ .APIAddr }}"
ui = true
log_level = "{{ .LogLevel }}"
log_format = "{{ .LogFormat }}"
`

type VaultConfigParams struct {
	Port          string
	TLSCrt        string
	TLSKey        string
	VaultDataPath string
	APIAddr       string
	LogLevel      string
	LogFormat     string
}

func RenderVaultConfig(addr string, logLevel string, logFormat string) (string, error) {
	if addr == "" {
		zap.L().Warn("⚠️ Blank address provided — using localhost fallback")
		addr = VaultDefaultLocalAddr
	}
	if _, err := os.Stat(TLSKey); err != nil {
		zap.L().Warn("⚠️ TLS key missing", zap.String("TLSKey", TLSKey), zap.Error(err))
	}
	if _, err := os.Stat(TLSCrt); err != nil {
		zap.L().Warn("⚠️ TLS cert missing", zap.String("TLSCrt", TLSCrt), zap.Error(err))
	}

	params := VaultConfigParams{
		Port:          VaultDefaultPort,
		TLSCrt:        TLSCrt,
		TLSKey:        TLSKey,
		VaultDataPath: VaultDataPath,
		APIAddr:       addr,
		LogLevel:      logLevel,
		LogFormat:     logFormat,
	}

	tmpl, err := template.New("vaultConfig").Parse(vaultConfigTemplate)
	if err != nil {
		return "", err
	}

	var rendered bytes.Buffer
	err = tmpl.Execute(&rendered, params)
	if err != nil {
		return "", err
	}

	zap.L().Info("📜 Rendering Vault config", zap.String("api_addr", addr))
	return rendered.String(), nil
}

// Vault systemd unit template
const ServerSystemDUnit = `
[Unit]
Description=Vault Server (Eos)
After=network.target

[Service]
User=eos
Group=eos
ExecStart=/usr/bin/vault server -config=/etc/vault.d/vault.hcl
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

// Health check report
type CheckReport struct {
	Installed       bool
	Initialized     bool
	Sealed          bool
	TokenReady      bool
	KVWorking       bool
	Notes           []string
	SecretsVerified bool
}

// Init response format
type VaultInitResponse struct {
	KeysB64   []string `json:"unseal_keys_b64"`
	RootToken string   `json:"root_token"`
}

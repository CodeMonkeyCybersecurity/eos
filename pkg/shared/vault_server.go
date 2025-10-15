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

	// === SINGLE SOURCE OF TRUTH: Base Directories ===
	VaultDir                  = "/opt/vault/"           // Vault data and logs
	VaultConfigDirDebian      = "/etc/vault.d"          // Vault config directory (all config files derive from this)
	VaultBinaryPath           = "/usr/bin/vault"        // Vault binary
	VaultServiceName          = "vault.service"         // Systemd service name
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

// Computed Vault port constants - ALL derived from ports.go
var (
	VaultDefaultPort        = fmt.Sprintf("%d", PortVault)
	VaultDefaultPortInt     = PortVault
	VaultClusterPort        = fmt.Sprintf("%d", PortVaultCluster)
	VaultClusterPortInt     = PortVaultCluster
	VaultWebPortTCP         = VaultDefaultPort + "/tcp"
	ListenerAddr            = "127.0.0.1:" + VaultDefaultPort
	VaultDefaultAddr        = "https://%s:" + VaultDefaultPort
	VaultDefaultLocalAddr   = "https://127.0.0.1:" + VaultDefaultPort
	VaultDefaultClusterAddr = "https://127.0.0.1:" + VaultClusterPort
	ConsulDefaultAddr       = fmt.Sprintf("127.0.0.1:%d", PortConsul) // Consul HTTP API on custom port 8161
)

// Computed Vault directory paths - ALL derived from base directories
var (
	// Vault data directories (derived from VaultDir)
	VaultDataPath   = VaultDir + "data/"
	VaultLogsPath   = VaultDir + "logs/"
	VaultAuditLogPath = VaultLogsPath + "vault_audit.log"

	// Vault config paths (derived from VaultConfigDirDebian)
	VaultConfigPath = filepath.Join(VaultConfigDirDebian, "vault.hcl")
	TLSDir          = filepath.Join(VaultConfigDirDebian, "tls")
	TLSCrt          = filepath.Join(TLSDir, "vault.crt")
	TLSKey          = filepath.Join(TLSDir, "vault.key")
	VaultServicePath = "/etc/systemd/system/" + VaultServiceName

	// Eos directories and files
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
		return addr
	}
	return fmt.Sprintf(VaultDefaultAddr, LocalhostSAN)
}

// DEPRECATED: File storage template - use Raft templates instead
// File storage is NOT SUPPORTED in Vault Enterprise 1.12.0+
const vaultConfigTemplateFileLegacy = `
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

// Consul Storage - Single Node (Development/Production)
// Recommended for: Production deployments with external Consul cluster
// Provides HA without Raft complexity
const vaultConfigTemplateConsulSingleNode = `
# Vault Configuration - Consul Storage Backend
# Storage: Consul KV Store
# Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/consul

storage "consul" {
  address = "{{ .ConsulAddress }}"
  path    = "{{ .ConsulPath }}"
  {{- if .ConsulToken }}
  token   = "{{ .ConsulToken }}"
  {{- end }}
  {{- if .ConsulScheme }}
  scheme  = "{{ .ConsulScheme }}"
  {{- end }}
}

listener "tcp" {
  address         = "0.0.0.0:{{ .Port }}"
  cluster_address = "0.0.0.0:{{ .ClusterPort }}"
  tls_cert_file   = "{{ .TLSCrt }}"
  tls_key_file    = "{{ .TLSKey }}"
  tls_min_version = "tls12"
}

cluster_addr = "{{ .ClusterAddr }}"
api_addr     = "{{ .APIAddr }}"
disable_mlock = true
ui = true
log_level = "{{ .LogLevel }}"
log_format = "{{ .LogFormat }}"

# Service registration with Consul
service_registration "consul" {
  address = "{{ .ConsulAddress }}"
  {{- if .ConsulToken }}
  token   = "{{ .ConsulToken }}"
  {{- end }}
}
`

// Consul Storage - Multi-Node (Production with Auto-Unseal)
// Recommended for: Production HA deployments with Consul backend
const vaultConfigTemplateConsulMultiNode = `
# Vault Configuration - Multi-Node Consul Storage (Production)
# Storage: Consul KV Store
# Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/consul

storage "consul" {
  address = "{{ .ConsulAddress }}"
  path    = "{{ .ConsulPath }}"
  {{- if .ConsulToken }}
  token   = "{{ .ConsulToken }}"
  {{- end }}
  {{- if .ConsulScheme }}
  scheme  = "{{ .ConsulScheme }}"
  {{- end }}

  # High availability settings
  max_parallel    = "128"
  consistency_mode = "default"
}

listener "tcp" {
  address         = "0.0.0.0:{{ .Port }}"
  cluster_address = "0.0.0.0:{{ .ClusterPort }}"
  tls_cert_file   = "{{ .TLSCrt }}"
  tls_key_file    = "{{ .TLSKey }}"
  tls_min_version = "tls12"
}

# This node's addresses (MUST be unique per node)
cluster_addr = "{{ .ClusterAddr }}"
api_addr     = "{{ .APIAddr }}"

# Production hardening
disable_mlock = true
ui = true
log_level = "{{ .LogLevel }}"
log_format = "{{ .LogFormat }}"

# Service registration with Consul
service_registration "consul" {
  address = "{{ .ConsulAddress }}"
  {{- if .ConsulToken }}
  token   = "{{ .ConsulToken }}"
  {{- end }}
}

# Telemetry for monitoring
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}

{{- if .AutoUnseal }}
# Auto-unseal configuration
{{ .AutoUnsealConfig }}
{{- end }}
`

// DEPRECATED: Raft Integrated Storage - Single Node (Development)
// Recommended for: Development, testing, POC
// As per vault-complete-specification-v1.0-raft-integrated.md
// NOTE: Raft backend is being replaced with Consul backend
const vaultConfigTemplateRaftSingleNode = `
# Vault Configuration - Single Node Raft (Development)
# Storage: Integrated Storage (Raft)
# Reference: vault-complete-specification-v1.0-raft-integrated.md
# DEPRECATED: Use Consul storage backend instead

storage "raft" {
  path    = "{{ .VaultDataPath }}"
  node_id = "{{ .NodeID }}"
}

listener "tcp" {
  address         = "0.0.0.0:{{ .Port }}"
  cluster_address = "0.0.0.0:{{ .ClusterPort }}"
  tls_cert_file   = "{{ .TLSCrt }}"
  tls_key_file    = "{{ .TLSKey }}"
  tls_min_version = "tls12"
}

cluster_addr = "{{ .ClusterAddr }}"
api_addr     = "{{ .APIAddr }}"
disable_mlock = true
ui = true
log_level = "{{ .LogLevel }}"
log_format = "{{ .LogFormat }}"
`

// Raft Integrated Storage - Multi-Node (Production)
// Recommended for: Production deployments with HA
// Requires: 3-5 nodes across multiple availability zones
const vaultConfigTemplateRaftMultiNode = `
# Vault Configuration - Multi-Node Raft (Production)
# Storage: Integrated Storage (Raft)
# Reference: vault-complete-specification-v1.0-raft-integrated.md

storage "raft" {
  path    = "{{ .VaultDataPath }}"
  node_id = "{{ .NodeID }}"
  
  # Production performance setting
  performance_multiplier = 1
  
  {{- if .RetryJoinNodes }}
  # Auto-join configuration
  {{- range .RetryJoinNodes }}
  retry_join {
    leader_api_addr         = "{{ .APIAddr }}"
    leader_client_cert_file = "{{ $.TLSCrt }}"
    leader_client_key_file  = "{{ $.TLSKey }}"
    leader_ca_cert_file     = "{{ $.TLSCrt }}"
    leader_tls_servername   = "{{ .Hostname }}"
  }
  {{- end }}
  {{- end }}
}

listener "tcp" {
  address         = "0.0.0.0:{{ .Port }}"
  cluster_address = "0.0.0.0:{{ .ClusterPort }}"
  tls_cert_file   = "{{ .TLSCrt }}"
  tls_key_file    = "{{ .TLSKey }}"
  tls_min_version = "tls12"
}

# This node's addresses (MUST be unique per node)
cluster_addr = "{{ .ClusterAddr }}"
api_addr     = "{{ .APIAddr }}"

# Production hardening
disable_mlock = true  # Required for Raft
ui = true
log_level = "{{ .LogLevel }}"
log_format = "{{ .LogFormat }}"

# Telemetry for monitoring
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}

{{- if .AutoUnseal }}
# Auto-unseal configuration
{{ .AutoUnsealConfig }}
{{- end }}
`

type VaultConfigParams struct {
	Port          string
	ClusterPort   string // Raft cluster communication port (default: 8180)
	TLSCrt        string
	TLSKey        string
	VaultDataPath string
	APIAddr       string
	ClusterAddr   string // This node's cluster address
	NodeID        string // Unique node identifier for Raft
	LogLevel      string
	LogFormat     string

	// Multi-node Raft configuration (DEPRECATED - use Consul instead)
	RetryJoinNodes []RetryJoinNode

	// Consul storage backend configuration
	ConsulAddress string // Consul agent address (default: 127.0.0.1:8161)
	ConsulPath    string // Path in Consul KV store (default: "vault/")
	ConsulToken   string // Consul ACL token (optional)
	ConsulScheme  string // http or https (default: http)

	// Auto-unseal configuration
	AutoUnseal       bool
	AutoUnsealConfig string // HCL block for seal configuration
}

// RetryJoinNode represents a node to join in a Raft cluster
type RetryJoinNode struct {
	APIAddr  string
	Hostname string
}

// DEPRECATED: RenderVaultConfig renders Vault configuration
// This function is deprecated and now defaults to Consul storage backend.
// Use RenderVaultConfigConsul for new deployments.
// File storage is NOT SUPPORTED in Vault Enterprise 1.12.0+
func RenderVaultConfig(addr string, logLevel string, logFormat string) (string, error) {
	if addr == "" {
		addr = VaultDefaultLocalAddr
	}

	// Use Consul backend (recommended) instead of deprecated file storage
	params := VaultConfigParams{
		Port:          VaultDefaultPort,
		ClusterPort:   VaultClusterPort,
		TLSCrt:        TLSCrt,
		TLSKey:        TLSKey,
		APIAddr:       addr,
		ClusterAddr:   VaultDefaultClusterAddr,
		LogLevel:      logLevel,
		LogFormat:     logFormat,
		ConsulAddress: ConsulDefaultAddr,
		ConsulPath:    "vault/",
		ConsulScheme:  "http",
	}

	// Delegate to Consul renderer
	return RenderVaultConfigConsul(params)
}

// RenderVaultConfigConsul renders Vault configuration with Consul storage backend
// This is the RECOMMENDED configuration for all deployments (dev and production)
// Reference: https://developer.hashicorp.com/vault/docs/configuration/storage/consul
func RenderVaultConfigConsul(params VaultConfigParams) (string, error) {
	// Set defaults
	if params.Port == "" {
		params.Port = VaultDefaultPort
	}
	if params.ClusterPort == "" {
		params.ClusterPort = "8180"
	}
	if params.TLSCrt == "" {
		params.TLSCrt = TLSCrt
	}
	if params.TLSKey == "" {
		params.TLSKey = TLSKey
	}
	if params.ConsulAddress == "" {
		params.ConsulAddress = ConsulDefaultAddr
	}
	if params.ConsulPath == "" {
		params.ConsulPath = "vault/"
	}
	if params.ConsulScheme == "" {
		params.ConsulScheme = "http"
	}
	if params.LogLevel == "" {
		params.LogLevel = "info"
	}
	if params.LogFormat == "" {
		params.LogFormat = "json"
	}

	// Choose template based on deployment type
	var templateStr string
	if params.AutoUnseal {
		// Multi-node production cluster with auto-unseal
		templateStr = vaultConfigTemplateConsulMultiNode
	} else {
		// Single-node or basic multi-node
		templateStr = vaultConfigTemplateConsulSingleNode
	}

	tmpl, err := template.New("vaultConfigConsul").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var rendered bytes.Buffer
	err = tmpl.Execute(&rendered, params)
	if err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return rendered.String(), nil
}

// DEPRECATED: RenderVaultConfigRaft renders Vault configuration with Raft Integrated Storage
// This function is deprecated. Use RenderVaultConfigConsul instead.
// Reference: vault-complete-specification-v1.0-raft-integrated.md
func RenderVaultConfigRaft(params VaultConfigParams) (string, error) {
	// Set defaults
	if params.Port == "" {
		params.Port = VaultDefaultPort
	}
	if params.ClusterPort == "" {
		params.ClusterPort = "8180"
	}
	if params.TLSCrt == "" {
		params.TLSCrt = TLSCrt
	}
	if params.TLSKey == "" {
		params.TLSKey = TLSKey
	}
	if params.VaultDataPath == "" {
		params.VaultDataPath = VaultDataPath
	}
	if params.NodeID == "" {
		params.NodeID = "eos-vault-node1"
	}
	if params.LogLevel == "" {
		params.LogLevel = "info"
	}
	if params.LogFormat == "" {
		params.LogFormat = "json"
	}
	
	// Choose template based on deployment type
	var templateStr string
	if len(params.RetryJoinNodes) > 0 {
		// Multi-node production cluster
		templateStr = vaultConfigTemplateRaftMultiNode
	} else {
		// Single-node development
		templateStr = vaultConfigTemplateRaftSingleNode
	}
	
	tmpl, err := template.New("vaultConfigRaft").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	
	var rendered bytes.Buffer
	err = tmpl.Execute(&rendered, params)
	if err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	
	return rendered.String(), nil
}

// Vault systemd unit template
const ServerSystemDUnit = `
[Unit]
Description=Vault Server (Eos)
After=network.target

[Service]
User=vault
Group=vault
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

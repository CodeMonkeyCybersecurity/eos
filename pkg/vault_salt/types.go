package vault_salt

import (
	"time"
)

// Config holds the configuration for Vault deployment via Salt
type Config struct {
	// Installation configuration
	Version           string
	InstallPath       string
	ConfigPath        string
	DataPath          string
	LogPath           string
	TLSPath           string
	
	// Network configuration
	ListenAddress     string
	ClusterAddress    string
	APIAddr           string
	ClusterAPIAddr    string
	Port              int
	ClusterPort       int
	
	// TLS configuration
	TLSDisable        bool
	TLSCertFile       string
	TLSKeyFile        string
	TLSMinVersion     string
	
	// Storage configuration
	StorageType       string
	StoragePath       string
	
	// UI configuration
	UIEnabled         bool
	
	// Performance configuration
	MaxLeaseTTL       time.Duration
	DefaultLeaseTTL   time.Duration
	
	// Salt-specific configuration
	SaltMasterless    bool
	SaltFileRoot      string
	SaltPillarRoot    string
	SaltStateFile     string
	SaltTimeout       time.Duration
	
	// Initialization configuration
	KeyShares         int
	KeyThreshold      int
	AutoUnseal        bool
	
	// Enable phase configuration
	EnableUserpass    bool
	EnableAppRole     bool
	EnableMFA         bool
	EnableAudit       bool
	EnablePolicies    bool
	
	// Hardening configuration
	HardenSystem      bool
	HardenNetwork     bool
	HardenVault       bool
	HardenBackup      bool
	
	// Backup configuration
	BackupEnabled     bool
	BackupPath        string
	BackupSchedule    string
	
	// Monitoring configuration
	TelemetryEnabled  bool
	MetricsPath       string
	
	// Integration configuration
	HecateIntegration bool
	DelphiIntegration bool
}

// DefaultConfig returns a default configuration for Vault
func DefaultConfig() *Config {
	return &Config{
		Version:           "latest",
		InstallPath:       "/opt/vault",
		ConfigPath:        "/etc/vault.d",
		DataPath:          "/opt/vault/data",
		LogPath:           "/var/log/vault",
		TLSPath:           "/opt/vault/tls",
		
		ListenAddress:     "0.0.0.0",
		ClusterAddress:    "0.0.0.0",
		Port:              8179, // Eos-specific port
		ClusterPort:       8180,
		
		TLSDisable:        false,
		TLSMinVersion:     "tls12",
		
		StorageType:       "raft",
		StoragePath:       "/opt/vault/data",
		
		UIEnabled:         true,
		
		MaxLeaseTTL:       87600 * time.Hour, // 10 years
		DefaultLeaseTTL:   768 * time.Hour,   // 32 days
		
		SaltMasterless:    true,
		SaltFileRoot:      "/opt/eos/salt/states",
		SaltPillarRoot:    "/opt/eos/salt/pillar",
		SaltStateFile:     "hashicorp.vault.complete_lifecycle",
		SaltTimeout:       10 * time.Minute,
		
		KeyShares:         5,
		KeyThreshold:      3,
		AutoUnseal:        false,
		
		EnableUserpass:    true,
		EnableAppRole:     true,
		EnableMFA:         true,
		EnableAudit:       true,
		EnablePolicies:    true,
		
		HardenSystem:      true,
		HardenNetwork:     true,
		HardenVault:       true,
		HardenBackup:      true,
		
		BackupEnabled:     true,
		BackupPath:        "/opt/vault/backup",
		BackupSchedule:    "0 2 * * *", // 2 AM daily
		
		TelemetryEnabled:  true,
		MetricsPath:       "/metrics",
		
		HecateIntegration: true,
		DelphiIntegration: true,
	}
}

// VaultInitResponse represents the response from vault operator init
type VaultInitResponse struct {
	UnsealKeysB64     []string `json:"unseal_keys_b64"`
	UnsealKeysHex     []string `json:"unseal_keys_hex"`
	UnsealShares      int      `json:"unseal_shares"`
	UnsealThreshold   int      `json:"unseal_threshold"`
	RecoveryKeysB64   []string `json:"recovery_keys_b64"`
	RecoveryKeysHex   []string `json:"recovery_keys_hex"`
	RecoveryShares    int      `json:"recovery_keys_shares"`
	RecoveryThreshold int      `json:"recovery_keys_threshold"`
	RootToken         string   `json:"root_token"`
}

// VaultStatus represents the status of a Vault instance
type VaultStatus struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Version     string `json:"version"`
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name"`
}

// SaltState represents a Salt state execution result
type SaltState struct {
	Name     string
	Result   bool
	Changes  map[string]interface{}
	Comment  string
	Duration float64
}

// Constants for Vault deployment
const (
	// Service names
	VaultServiceName       = "vault"
	VaultAgentServiceName  = "vault-agent"
	
	// File paths
	VaultBinaryPath        = "/usr/local/bin/vault"
	VaultConfigFile        = "vault.hcl"
	VaultAgentConfigFile   = "vault-agent.hcl"
	VaultInitDataFile      = "/var/lib/eos/secret/vault_init.json"
	
	// Salt state names
	SaltStateVaultInstall  = "hashicorp.vault.install"
	SaltStateVaultConfigure = "hashicorp.vault.configure"
	SaltStateVaultEnable    = "hashicorp.vault.enable"
	SaltStateVaultHarden    = "hashicorp.vault.harden"
	SaltStateVaultComplete  = "hashicorp.vault.complete_lifecycle"
	
	// Environment variables
	VaultAddrEnvVar        = "VAULT_ADDR"
	VaultTokenEnvVar       = "VAULT_TOKEN"
	VaultSkipVerifyEnvVar  = "VAULT_SKIP_VERIFY"
	
	// Default policies
	DefaultPolicyName      = "default"
	AdminPolicyName        = "admin"
	ReadOnlyPolicyName     = "readonly"
	
	// Audit log paths
	AuditLogFilePath       = "/var/log/vault/vault-audit.log"
	AuditLogSyslogPath     = "vault-audit"
)

// Error messages
var (
	ErrVaultNotInstalled   = "vault is not installed"
	ErrVaultNotInitialized = "vault is not initialized"
	ErrVaultSealed         = "vault is sealed"
	ErrSaltNotAvailable    = "salt is not available"
	ErrSaltStateFailed     = "salt state execution failed"
)
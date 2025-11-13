package vault

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

var (
	EnableOpts EnableOptions

	// Common errors
	ErrVaultSealed         = errors.New("vault is sealed")
	ErrSecretNotFound      = errors.New("secret not found")
	ErrVaultNotInstalled   = errors.New("vault is not installed")
	ErrVaultNotInitialized = errors.New("vault is not initialized")
)

// Interfaces

// SecretStore interface for vault secret operations
type SecretStore interface {
	Get(ctx context.Context, key string) (*Secret, error)
	Set(ctx context.Context, key string, secret *Secret) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// ConfigRepository interface for vault configuration operations
type ConfigRepository interface {
	GetConfig(ctx context.Context, key string) (string, error)
	SetConfig(ctx context.Context, key, value string) error
	GetAllConfig(ctx context.Context) (map[string]string, error)
	DeleteConfig(ctx context.Context, key string) error
}

// AuditRepository interface for vault audit operations
type AuditRepository interface {
	LogAccess(ctx context.Context, entry *AuditEvent) error
	GetAccessLogs(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error)
}

// EnableOptions controls which parts of the Vault enable sequence to run.
type EnableOptions struct {
	EnableAgent    bool
	EnableAPI      bool
	EnableAppRole  bool
	EnableUserpass bool // ← this must exist
	Password       string
	NonInteractive bool
	AppRoleOptions shared.AppRoleOptions
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

func diskFallbackPath() string {
	return filepath.Join(shared.SecretsDir, shared.TestDataFilename)
}

type Audit struct {
	Type        string            `json:"type" mapstructure:"type"`
	Description string            `json:"description" mapstructure:"description"`
	Options     map[string]string `json:"options" mapstructure:"options"`
	Local       bool              `json:"local" mapstructure:"local"`
	Path        string            `json:"path" mapstructure:"path"`
}

// Enhanced types from domain layer for comprehensive vault functionality

// Secret represents a secret with metadata and lifecycle management
type Secret struct {
	Key       string                 `json:"key"`
	Value     string                 `json:"-"` // Never serialize the actual value
	Metadata  map[string]string      `json:"metadata,omitempty"`
	Version   int                    `json:"version,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	Path      string                 `json:"path"`
	Data      map[string]interface{} `json:"-"` // Don't serialize raw data
}

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	Success      bool              `json:"success"`
	Token        string            `json:"-"` // Never serialize
	TokenTTL     time.Duration     `json:"token_ttl,omitempty"`
	Renewable    bool              `json:"renewable"`
	Policies     []string          `json:"policies,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	Method       string            `json:"method"`
	ErrorMessage string            `json:"error_message,omitempty"`
}

// AuthStatus represents current authentication status
type AuthStatus struct {
	Authenticated bool              `json:"authenticated"`
	UserID        string            `json:"user_id,omitempty"`
	Policies      []string          `json:"policies,omitempty"`
	TokenExpiry   *time.Time        `json:"token_expiry,omitempty"`
	LastAuth      *time.Time        `json:"last_auth,omitempty"`
	Method        string            `json:"method,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// InitConfig represents vault initialization configuration
type InitConfig struct {
	SecretShares      int      `json:"secret_shares"`
	SecretThreshold   int      `json:"secret_threshold"`
	RecoveryShares    int      `json:"recovery_shares,omitempty"`
	RecoveryThreshold int      `json:"recovery_threshold,omitempty"`
	PGPKeys           []string `json:"pgp_keys,omitempty"`
	RecoveryPGPKeys   []string `json:"recovery_pgp_keys,omitempty"`
	RootTokenPGPKey   string   `json:"root_token_pgp_key,omitempty"`
	StoredShares      int      `json:"stored_shares,omitempty"`
}

// InitResult represents the result of vault initialization
type InitResult struct {
	Keys               []string  `json:"-"` // Never serialize keys
	KeysBase64         []string  `json:"-"` // Never serialize keys
	RecoveryKeys       []string  `json:"-"` // Never serialize keys
	RecoveryKeysBase64 []string  `json:"-"` // Never serialize keys
	RootToken          string    `json:"-"` // Never serialize token
	Initialized        bool      `json:"initialized"`
	InitTime           time.Time `json:"init_time"`
	Timestamp          time.Time `json:"timestamp"`
	KeyThreshold       int       `json:"key_threshold"`
	KeyShares          int       `json:"key_shares"`
}

// VaultStatus represents the current status of the vault
type VaultStatus struct {
	Initialized  bool      `json:"initialized"`
	Sealed       bool      `json:"sealed"`
	Timestamp    time.Time `json:"timestamp"`
	Progress     int       `json:"progress"`
	Threshold    int       `json:"threshold"`
	Shares       int       `json:"shares"`
	Version      string    `json:"version"`
	ClusterName  string    `json:"cluster_name"`
	ClusterID    string    `json:"cluster_id"`
	HealthStatus string    `json:"health_status"`
	Nonce        string    `json:"nonce,omitempty"`
	Standby      bool      `json:"standby"`
}

// Comprehensive Audit System Types

// AuditEvent represents a vault audit log entry
type AuditEvent struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Time      time.Time      `json:"time"`
	Timestamp time.Time      `json:"timestamp"`
	Auth      *AuditAuth     `json:"auth,omitempty"`
	Request   *AuditRequest  `json:"request,omitempty"`
	Response  *AuditResponse `json:"response,omitempty"`
	Error     string         `json:"error,omitempty"`
	WrapInfo  *AuditWrapInfo `json:"wrap_info,omitempty"`
}

// AuditAuth represents authentication information in audit logs
type AuditAuth struct {
	ClientToken       string            `json:"-"` // Never log tokens
	Accessor          string            `json:"accessor,omitempty"`
	DisplayName       string            `json:"display_name,omitempty"`
	Policies          []string          `json:"policies,omitempty"`
	TokenPolicies     []string          `json:"token_policies,omitempty"`
	IdentityPolicies  []string          `json:"identity_policies,omitempty"`
	ExternalNamespace string            `json:"external_namespace,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	EntityID          string            `json:"entity_id,omitempty"`
	TokenType         string            `json:"token_type,omitempty"`
	TokenTTL          int64             `json:"token_ttl,omitempty"`
}

// AuditRequest represents request information in audit logs
type AuditRequest struct {
	ID                  string                 `json:"id,omitempty"`
	Operation           string                 `json:"operation"`
	ClientToken         string                 `json:"-"` // Never log tokens
	ClientTokenAccessor string                 `json:"client_token_accessor,omitempty"`
	Path                string                 `json:"path"`
	Data                map[string]interface{} `json:"-"` // Don't log sensitive data
	PolicyOverride      bool                   `json:"policy_override,omitempty"`
	RemoteAddr          string                 `json:"remote_addr,omitempty"`
	RemoteAddress       string                 `json:"remote_address,omitempty"` // Alias for compatibility
	WrapTTL             int                    `json:"wrap_ttl,omitempty"`
	Headers             map[string][]string    `json:"headers,omitempty"`
}

// AuditResponse represents response information in audit logs
type AuditResponse struct {
	Data     map[string]interface{} `json:"-"` // Don't log sensitive response data
	Secret   *AuditSecret           `json:"secret,omitempty"`
	Auth     *AuditAuth             `json:"auth,omitempty"`
	Headers  map[string][]string    `json:"headers,omitempty"`
	WrapInfo *AuditWrapInfo         `json:"wrap_info,omitempty"`
}

// AuditSecret represents secret information in audit logs (sanitized)
type AuditSecret struct {
	LeaseID       string `json:"lease_id,omitempty"`
	LeaseDuration int    `json:"lease_duration,omitempty"`
	Renewable     bool   `json:"renewable,omitempty"`
}

// AuditWrapInfo represents token wrapping information in audit logs
type AuditWrapInfo struct {
	Token           string    `json:"-"` // Never log wrap tokens
	Accessor        string    `json:"accessor,omitempty"`
	TTL             int       `json:"ttl,omitempty"`
	CreationTime    time.Time `json:"creation_time,omitempty"`
	CreationPath    string    `json:"creation_path,omitempty"`
	WrappedAccessor string    `json:"wrapped_accessor,omitempty"`
}

// AuditFilter represents query parameters for searching audit logs
type AuditFilter struct {
	StartTime  *time.Time `json:"start_time,omitempty"`
	EndTime    *time.Time `json:"end_time,omitempty"`
	Operation  string     `json:"operation,omitempty"`
	Path       string     `json:"path,omitempty"`
	UserID     string     `json:"user_id,omitempty"`
	EntityID   string     `json:"entity_id,omitempty"`
	ClientAddr string     `json:"client_address,omitempty"`
	RemoteAddr string     `json:"remote_address,omitempty"`
	Limit      int        `json:"limit,omitempty"`
	Offset     int        `json:"offset,omitempty"`
}

// AuditStats represents audit statistics and metrics
type AuditStats struct {
	TotalEvents  int64            `json:"total_events"`
	EventsByType map[string]int64 `json:"events_by_type"`
	EventsByPath map[string]int64 `json:"events_by_path"`
	UniqueUsers  int64            `json:"unique_users"`
	TimeRange    AuditTimeRange   `json:"time_range"`
	TopPaths     []AuditPathStat  `json:"top_paths"`
	TopUsers     []AuditUserStat  `json:"top_users"`
	LastEvent    *time.Time       `json:"last_event,omitempty"`
}

// AuditTimeRange represents a time range for audit statistics
type AuditTimeRange struct {
	Start    time.Time  `json:"start"`
	End      time.Time  `json:"end"`
	Earliest *time.Time `json:"earliest,omitempty"`
	Latest   *time.Time `json:"latest,omitempty"`
}

// AuditPathStat represents usage statistics for a specific path
type AuditPathStat struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// AuditUserStat represents usage statistics for a specific user
type AuditUserStat struct {
	UserID string `json:"user_id"`
	Count  int64  `json:"count"`
}

// Authentication Credential Types

// UserpassCredentials represents username/password authentication
type UserpassCredentials struct {
	Username string `json:"username"`
	Password string `json:"-"` // Never serialize password
}

// AppRoleCredentials represents AppRole authentication
type AppRoleCredentials struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"-"` // Never serialize secret
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

// ============================================================================
// Path and Network Configuration Types
// ============================================================================

// VaultPaths provides structured access to all Vault-related filesystem paths.
// Use this instead of hardcoding paths throughout the codebase.
type VaultPaths struct {
	// Binary locations
	Binary       string   // Primary vault binary location
	BinaryLegacy []string // Legacy locations to check/cleanup

	// Configuration
	ConfigDir   string // Base config directory
	ConfigFile  string // Main server config file
	AgentConfig string // Agent config file

	// TLS/Certificates
	TLSDir  string // TLS directory
	TLSCert string // Server certificate
	TLSKey  string // Server private key
	TLSCA   string // CA certificate

	// Data storage
	DataDir  string // Vault data directory
	LogsDir  string // Log directory
	AuditLog string // Audit log file

	// Systemd services
	ServiceFile      string // Server service file
	AgentServiceFile string // Agent service file

	// Helper scripts
	BackupScript      string // Backup script path
	HealthCheckScript string // Agent health check script
	SnapshotScript    string // Snapshot script path

	// Secrets/initialization
	InitDataFile string // Vault initialization data
}

// DefaultVaultPaths returns the standard Vault paths using constants from constants.go
func DefaultVaultPaths() *VaultPaths {
	return &VaultPaths{
		Binary: VaultBinaryPath,
		BinaryLegacy: []string{
			VaultBinaryPathLegacy, // /usr/bin/vault
			VaultBinaryPathOpt,    // /opt/vault/bin/vault
			VaultBinaryPathSnap,   // /snap/bin/vault
		},
		ConfigDir:         VaultConfigDir,
		ConfigFile:        VaultConfigPath,
		AgentConfig:       filepath.Join(VaultConfigDir, VaultAgentConfigFile),
		TLSDir:            VaultTLSDir,
		TLSCert:           VaultTLSCert,
		TLSKey:            VaultTLSKey,
		TLSCA:             VaultTLSCA,
		DataDir:           VaultDataDir,
		LogsDir:           VaultLogsDir,
		AuditLog:          VaultAuditLogPath,
		ServiceFile:       VaultServicePath,
		AgentServiceFile:  VaultAgentServicePath,
		BackupScript:      VaultBackupScriptPath,
		HealthCheckScript: VaultAgentHealthCheckPath,
		SnapshotScript:    VaultSnapshotScriptPath,
		InitDataFile:      VaultInitDataFile,
	}
}

// AllPaths returns all paths as a flat list (useful for cleanup/deletion)
func (vp *VaultPaths) AllPaths() []string {
	paths := []string{
		vp.Binary,
		vp.ConfigDir,
		vp.ConfigFile,
		vp.AgentConfig,
		vp.TLSDir,
		vp.TLSCert,
		vp.TLSKey,
		vp.TLSCA,
		vp.DataDir,
		vp.LogsDir,
		vp.AuditLog,
		vp.ServiceFile,
		vp.AgentServiceFile,
		vp.BackupScript,
		vp.HealthCheckScript,
		vp.SnapshotScript,
		vp.InitDataFile,
	}
	// Add legacy binary paths
	paths = append(paths, vp.BinaryLegacy...)
	return paths
}

// VaultNetworkConfig defines network addresses and ports for Vault
type VaultNetworkConfig struct {
	// Listen addresses
	ListenAddr        string // Address to bind to (0.0.0.0 for all interfaces)
	ClusterListenAddr string // Cluster communication address

	// Client connection addresses
	ClientAddr string // Address clients use to connect (shared.GetInternalHostname or hostname)

	// Ports
	APIPort     int // Vault API port (default: 8179)
	ClusterPort int // Raft cluster port (default: 8180)

	// Computed addresses
	APIAddress     string // Full API address (e.g., https://hostname:8179)
	ClusterAddress string // Full cluster address (e.g., https://hostname:8180)
}

// DefaultVaultNetwork returns standard network configuration
func DefaultVaultNetwork(hostname string) *VaultNetworkConfig {
	if hostname == "" {
		hostname = shared.GetInternalHostname()
	}

	return &VaultNetworkConfig{
		ListenAddr:        VaultListenAddr,  // 0.0.0.0
		ClusterListenAddr: VaultListenAddr,  // 0.0.0.0
		ClientAddr:        hostname,         // Hostname via intelligent resolution
		APIPort:           VaultDefaultPort, // 8179
		ClusterPort:       VaultClusterPort, // 8180
		APIAddress:        fmt.Sprintf("https://%s:%d", hostname, VaultDefaultPort),
		ClusterAddress:    fmt.Sprintf("https://%s:%d", hostname, VaultClusterPort),
	}
}

// APIListenAddress returns the full listen address for the API (e.g., "0.0.0.0:8179")
func (vnc *VaultNetworkConfig) APIListenAddress() string {
	return fmt.Sprintf("%s:%d", vnc.ListenAddr, vnc.APIPort)
}

// ClusterListenAddress returns the full listen address for cluster comm (e.g., "0.0.0.0:8180")
func (vnc *VaultNetworkConfig) ClusterListenAddress() string {
	return fmt.Sprintf("%s:%d", vnc.ClusterListenAddr, vnc.ClusterPort)
}

// LocalAPIAddress returns the client connection address using intelligent hostname resolution
// Priority: hostname → Tailscale IP → primary interface IP → localhost
func (vnc *VaultNetworkConfig) LocalAPIAddress() string {
	return fmt.Sprintf("https://%s:%d", shared.GetInternalHostname(), vnc.APIPort)
}

// VaultServiceConfig defines systemd service parameters
type VaultServiceConfig struct {
	ServiceName string // Service name (e.g., "vault.service")
	User        string // Run as user
	Group       string // Run as group
	BinaryPath  string // Path to vault binary
	ConfigPath  string // Path to config file
}

// DefaultVaultService returns standard service configuration
func DefaultVaultService() *VaultServiceConfig {
	return &VaultServiceConfig{
		ServiceName: VaultServiceName,
		User:        VaultServiceUser,
		Group:       VaultServiceGroup,
		BinaryPath:  VaultBinaryPath,
		ConfigPath:  VaultConfigPath,
	}
}

// ExecStartCommand returns the systemd ExecStart command line
func (vsc *VaultServiceConfig) ExecStartCommand() string {
	return fmt.Sprintf("%s server -config=%s", vsc.BinaryPath, vsc.ConfigPath)
}

// VaultInstallConfig aggregates all configuration for Vault installation
type VaultInstallConfig struct {
	Paths   *VaultPaths
	Network *VaultNetworkConfig
	Service *VaultServiceConfig

	// Additional options
	LogLevel  string
	LogFormat string
}

// DefaultInstallConfig returns a complete default configuration
func DefaultInstallConfig(hostname string) *VaultInstallConfig {
	return &VaultInstallConfig{
		Paths:     DefaultVaultPaths(),
		Network:   DefaultVaultNetwork(hostname),
		Service:   DefaultVaultService(),
		LogLevel:  "info",
		LogFormat: "json",
	}
}

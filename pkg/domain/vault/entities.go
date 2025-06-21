// Package vault defines domain entities for secret management
package vault

import (
	"time"
)

// Secret represents a secret with metadata
type Secret struct {
	Key       string            `json:"key"`
	Value     string            `json:"-"` // Never serialize the actual value
	Metadata  map[string]string `json:"metadata,omitempty"`
	Version   int               `json:"version,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
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
	StoredShares      int      `json:"stored_shares,omitempty"`
	PGPKeys           []string `json:"pgp_keys,omitempty"`
	RootTokenPGPKey   string   `json:"root_token_pgp_key,omitempty"`
}

// InitResult represents the result of vault initialization
type InitResult struct {
	Keys         []string  `json:"-"` // Never serialize
	KeysBase64   []string  `json:"-"` // Never serialize
	RootToken    string    `json:"-"` // Never serialize
	Initialized  bool      `json:"initialized"`
	Timestamp    time.Time `json:"timestamp"`
	KeyThreshold int       `json:"key_threshold"`
	KeyShares    int       `json:"key_shares"`
}

// VaultStatus represents vault health and status
type VaultStatus struct {
	Initialized     bool      `json:"initialized"`
	Sealed          bool      `json:"sealed"`
	Standby         bool      `json:"standby"`
	ReplicationMode string    `json:"replication_mode,omitempty"`
	Version         string    `json:"version,omitempty"`
	ClusterName     string    `json:"cluster_name,omitempty"`
	ClusterID       string    `json:"cluster_id,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	Progress        int       `json:"progress,omitempty"`
	Threshold       int       `json:"threshold,omitempty"`
	Nonce           string    `json:"nonce,omitempty"`
}

// AuditEvent represents an audit log entry
type AuditEvent struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Type      string         `json:"type"`
	Auth      *AuditAuth     `json:"auth,omitempty"`
	Request   *AuditRequest  `json:"request,omitempty"`
	Response  *AuditResponse `json:"response,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// AuditAuth represents authentication information in audit logs
type AuditAuth struct {
	ClientToken string            `json:"-"` // Never serialize
	Accessor    string            `json:"accessor,omitempty"`
	DisplayName string            `json:"display_name,omitempty"`
	Policies    []string          `json:"policies,omitempty"`
	TokenTTL    int64             `json:"token_ttl,omitempty"`
	TokenType   string            `json:"token_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AuditRequest represents request information in audit logs
type AuditRequest struct {
	ID                      string                 `json:"id"`
	Operation               string                 `json:"operation"`
	Path                    string                 `json:"path"`
	Data                    map[string]interface{} `json:"data,omitempty"`
	RemoteAddress           string                 `json:"remote_address,omitempty"`
	WrapTTL                 int64                  `json:"wrap_ttl,omitempty"`
	Headers                 map[string][]string    `json:"headers,omitempty"`
	ClientCertificateSerial string                 `json:"client_certificate_serial,omitempty"`
}

// AuditResponse represents response information in audit logs
type AuditResponse struct {
	MountType  string                 `json:"mount_type,omitempty"`
	MountPoint string                 `json:"mount_point,omitempty"`
	Auth       *AuditAuth             `json:"auth,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	WrapInfo   *AuditWrapInfo         `json:"wrap_info,omitempty"`
	Warnings   []string               `json:"warnings,omitempty"`
}

// AuditWrapInfo represents wrap information in audit logs
type AuditWrapInfo struct {
	Token           string    `json:"-"` // Never serialize
	Accessor        string    `json:"accessor,omitempty"`
	TTL             int64     `json:"ttl,omitempty"`
	CreationTime    time.Time `json:"creation_time,omitempty"`
	CreationPath    string    `json:"creation_path,omitempty"`
	WrappedAccessor string    `json:"wrapped_accessor,omitempty"`
}

// AuditFilter represents audit query parameters
type AuditFilter struct {
	StartTime  *time.Time `json:"start_time,omitempty"`
	EndTime    *time.Time `json:"end_time,omitempty"`
	Operation  string     `json:"operation,omitempty"`
	Path       string     `json:"path,omitempty"`
	UserID     string     `json:"user_id,omitempty"`
	RemoteAddr string     `json:"remote_addr,omitempty"`
	Limit      int        `json:"limit,omitempty"`
	Offset     int        `json:"offset,omitempty"`
}

// AuditStats represents audit statistics
type AuditStats struct {
	TotalEvents  int64            `json:"total_events"`
	EventsByType map[string]int64 `json:"events_by_type"`
	EventsByPath map[string]int64 `json:"events_by_path"`
	LastEvent    *time.Time       `json:"last_event,omitempty"`
	TimeRange    *AuditTimeRange  `json:"time_range,omitempty"`
}

// AuditTimeRange represents time range for audit stats
type AuditTimeRange struct {
	Earliest *time.Time `json:"earliest,omitempty"`
	Latest   *time.Time `json:"latest,omitempty"`
}

// UserpassCredentials represents userpass authentication credentials
type UserpassCredentials struct {
	Username string `json:"username"`
	Password string `json:"-"` // Never serialize
}

// AppRoleCredentials represents approle authentication credentials
type AppRoleCredentials struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"-"` // Never serialize
}

// EnableOptions controls which parts of the Vault enable sequence to run
// This maintains compatibility with existing vault package
type EnableOptions struct {
	EnableAgent    bool           `json:"enable_agent"`
	EnableAPI      bool           `json:"enable_api"`
	EnableAppRole  bool           `json:"enable_approle"`
	EnableUserpass bool           `json:"enable_userpass"`
	Password       string         `json:"-"` // Never serialize
	NonInteractive bool           `json:"non_interactive"`
	AppRoleOptions AppRoleOptions `json:"approle_options,omitempty"`
}

// AppRoleOptions represents AppRole configuration options
type AppRoleOptions struct {
	RoleName      string   `json:"role_name"`
	Policies      []string `json:"policies,omitempty"`
	TokenTTL      string   `json:"token_ttl,omitempty"`
	TokenMaxTTL   string   `json:"token_max_ttl,omitempty"`
	SecretIDTTL   string   `json:"secret_id_ttl,omitempty"`
	ForceRecreate bool     `json:"force_recreate"`
	RefreshCreds  bool     `json:"refresh_creds"`
}

// VaultAudit represents audit device configuration
type VaultAudit struct {
	Type        string            `json:"type"`
	Description string            `json:"description,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
	Local       bool              `json:"local"`
	Path        string            `json:"path"`
}

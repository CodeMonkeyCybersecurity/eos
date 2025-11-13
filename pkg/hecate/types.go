// pkg/hecate/types.go

package hecate

import (
	"net/url"
	"time"
)

// Route represents a reverse proxy route configuration
type Route struct {
	ID          string            `json:"id" yaml:"id"`
	Domain      string            `json:"domain" yaml:"domain"`
	Upstream    *Upstream         `json:"upstream" yaml:"upstream"`
	AuthPolicy  *AuthPolicy       `json:"auth_policy,omitempty" yaml:"auth_policy,omitempty"`
	RequireAuth bool              `json:"require_auth" yaml:"require_auth"` // Enable Authentik forward_auth
	Headers     map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	HealthCheck *HealthCheck      `json:"health_check,omitempty" yaml:"health_check,omitempty"`
	RateLimit   *RateLimit        `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	TLS         *TLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at"`
	Status      RouteStatus       `json:"status" yaml:"status"`
}

// Upstream represents the backend service configuration
type Upstream struct {
	URL               string        `json:"url" yaml:"url"`
	TLSSkipVerify     bool          `json:"tls_skip_verify,omitempty" yaml:"tls_skip_verify,omitempty"`
	LoadBalancePolicy string        `json:"lb_policy,omitempty" yaml:"lb_policy,omitempty"`
	HealthCheckPath   string        `json:"health_check_path,omitempty" yaml:"health_check_path,omitempty"`
	Timeout           time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	MaxIdleConns      int           `json:"max_idle_conns,omitempty" yaml:"max_idle_conns,omitempty"`
	MaxConnsPerHost   int           `json:"max_conns_per_host,omitempty" yaml:"max_conns_per_host,omitempty"`
	KeepAlive         time.Duration `json:"keep_alive,omitempty" yaml:"keep_alive,omitempty"`
}

// AuthPolicy represents authentication and authorization configuration
type AuthPolicy struct {
	Name        string            `json:"name" yaml:"name"`
	Provider    string            `json:"provider" yaml:"provider"` // authentik, etc
	Flow        string            `json:"flow,omitempty" yaml:"flow,omitempty"`
	Groups      []string          `json:"groups,omitempty" yaml:"groups,omitempty"`
	RequireMFA  bool              `json:"require_mfa" yaml:"require_mfa"`
	SessionTTL  time.Duration     `json:"session_ttl,omitempty" yaml:"session_ttl,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Permissions []Permission      `json:"permissions,omitempty" yaml:"permissions,omitempty"`
}

// Permission represents a specific permission requirement
type Permission struct {
	Resource string   `json:"resource" yaml:"resource"`
	Actions  []string `json:"actions" yaml:"actions"`
	Scopes   []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
}

// HealthCheck represents health check configuration
type HealthCheck struct {
	Path             string            `json:"path" yaml:"path"`
	Interval         time.Duration     `json:"interval" yaml:"interval"`
	Timeout          time.Duration     `json:"timeout" yaml:"timeout"`
	UnhealthyStatus  []int             `json:"unhealthy_status,omitempty" yaml:"unhealthy_status,omitempty"`
	HealthyStatus    []int             `json:"healthy_status,omitempty" yaml:"healthy_status,omitempty"`
	ExpectedStatus   []int             `json:"expected_status,omitempty" yaml:"expected_status,omitempty"`
	FailureThreshold int               `json:"failure_threshold" yaml:"failure_threshold"`
	SuccessThreshold int               `json:"success_threshold" yaml:"success_threshold"`
	Headers          map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Method           string            `json:"method,omitempty" yaml:"method,omitempty"`
	Body             string            `json:"body,omitempty" yaml:"body,omitempty"`
	Enabled          bool              `json:"enabled" yaml:"enabled"`
}

// RateLimit represents rate limiting configuration
type RateLimit struct {
	RequestsPerSecond int           `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize         int           `json:"burst_size" yaml:"burst_size"`
	WindowSize        time.Duration `json:"window_size" yaml:"window_size"`
	KeyBy             string        `json:"key_by" yaml:"key_by"` // ip, header, etc
	Enabled           bool          `json:"enabled" yaml:"enabled"`
}

// TLSConfig represents TLS/SSL configuration
type TLSConfig struct {
	Enabled            bool     `json:"enabled" yaml:"enabled"`
	MinVersion         string   `json:"min_version,omitempty" yaml:"min_version,omitempty"`
	MaxVersion         string   `json:"max_version,omitempty" yaml:"max_version,omitempty"`
	CipherSuites       []string `json:"cipher_suites,omitempty" yaml:"cipher_suites,omitempty"`
	CertFile           string   `json:"cert_file,omitempty" yaml:"cert_file,omitempty"`
	KeyFile            string   `json:"key_file,omitempty" yaml:"key_file,omitempty"`
	CAFile             string   `json:"ca_file,omitempty" yaml:"ca_file,omitempty"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitempty" yaml:"insecure_skip_verify,omitempty"`
	HSTS               *HSTS    `json:"hsts,omitempty" yaml:"hsts,omitempty"`
}

// HSTS represents HTTP Strict Transport Security configuration
type HSTS struct {
	MaxAge            int  `json:"max_age" yaml:"max_age"`
	IncludeSubdomains bool `json:"include_subdomains" yaml:"include_subdomains"`
	Preload           bool `json:"preload" yaml:"preload"`
}

// RouteStatus represents the current status of a route
type RouteStatus struct {
	State       string    `json:"state" yaml:"state"`   // active, inactive, error, pending
	Health      string    `json:"health" yaml:"health"` // healthy, unhealthy, unknown
	LastChecked time.Time `json:"last_checked" yaml:"last_checked"`
	ErrorCount  int       `json:"error_count" yaml:"error_count"`
	Message     string    `json:"message,omitempty" yaml:"message,omitempty"`
}

// RouteMetrics represents performance metrics for a route
type RouteMetrics struct {
	RequestCount     int64         `json:"request_count" yaml:"request_count"`
	ErrorCount       int64         `json:"error_count" yaml:"error_count"`
	AverageLatency   time.Duration `json:"average_latency" yaml:"average_latency"`
	P95Latency       time.Duration `json:"p95_latency" yaml:"p95_latency"`
	P99Latency       time.Duration `json:"p99_latency" yaml:"p99_latency"`
	BytesTransferred int64         `json:"bytes_transferred" yaml:"bytes_transferred"`
	LastRequest      time.Time     `json:"last_request" yaml:"last_request"`
	Uptime           time.Duration `json:"uptime" yaml:"uptime"`
}

// ConnectionTestResult represents the result of testing a route connection
type ConnectionTestResult struct {
	Success      bool              `json:"success" yaml:"success"`
	StatusCode   int               `json:"status_code" yaml:"status_code"`
	ResponseTime time.Duration     `json:"response_time" yaml:"response_time"`
	Error        string            `json:"error,omitempty" yaml:"error,omitempty"`
	Headers      map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body         string            `json:"body,omitempty" yaml:"body,omitempty"`
	SSL          *SSLInfo          `json:"ssl,omitempty" yaml:"ssl,omitempty"`
}

// SSLInfo represents SSL certificate information
type SSLInfo struct {
	Valid        bool      `json:"valid" yaml:"valid"`
	Issuer       string    `json:"issuer" yaml:"issuer"`
	Subject      string    `json:"subject" yaml:"subject"`
	NotBefore    time.Time `json:"not_before" yaml:"not_before"`
	NotAfter     time.Time `json:"not_after" yaml:"not_after"`
	DNSNames     []string  `json:"dns_names" yaml:"dns_names"`
	SerialNumber string    `json:"serial_number" yaml:"serial_number"`
}

// HecateConfig represents the main configuration for Hecate
type HecateConfig struct {
	CaddyAPIEndpoint     string            `json:"caddy_api_endpoint" yaml:"caddy_api_endpoint"`
	AuthentikAPIEndpoint string            `json:"authentik_api_endpoint" yaml:"authentik_api_endpoint"`
	HetznerAPIToken      string            `json:"hetzner_api_token,omitempty" yaml:"hetzner_api_token,omitempty"`
	CloudflareAPIToken   string            `json:"cloudflare_api_token,omitempty" yaml:"cloudflare_api_token,omitempty"`
	StateBackend         string            `json:"state_backend" yaml:"state_backend"` // consul, file, etcd, etc
	StateBackendConfig   map[string]string `json:"state_backend_config,omitempty" yaml:"state_backend_config,omitempty"`
	Environment          string            `json:"environment" yaml:"environment"`
	DefaultDomain        string            `json:"default_domain,omitempty" yaml:"default_domain,omitempty"`
	EnableMetrics        bool              `json:"enable_metrics" yaml:"enable_metrics"`
	MetricsInterval      time.Duration     `json:"metrics_interval" yaml:"metrics_interval"`
	LogLevel             string            `json:"log_level" yaml:"log_level"`
	Backup               *BackupConfig     `json:"backup,omitempty" yaml:"backup,omitempty"`
}

// BackupConfig represents backup configuration for routes
type BackupConfig struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	Directory       string        `json:"directory" yaml:"directory"`
	Retention       time.Duration `json:"retention" yaml:"retention"`
	Compression     bool          `json:"compression" yaml:"compression"`
	IncludeState    bool          `json:"include_state" yaml:"include_state"`
	ScheduleEnabled bool          `json:"schedule_enabled" yaml:"schedule_enabled"`
	Schedule        string        `json:"schedule,omitempty" yaml:"schedule,omitempty"` // cron format
}

// DeleteOptions represents options for route deletion
type DeleteOptions struct {
	Force          bool `json:"force" yaml:"force"`
	Backup         bool `json:"backup" yaml:"backup"`
	RemoveDNS      bool `json:"remove_dns" yaml:"remove_dns"`
	RemoveSSL      bool `json:"remove_ssl" yaml:"remove_ssl"`
	CleanupOrphans bool `json:"cleanup_orphans" yaml:"cleanup_orphans"`
	DryRun         bool `json:"dry_run" yaml:"dry_run"`
}

// ReconcileResult represents the result of a state reconciliation
type ReconcileResult struct {
	Added    []string         `json:"added" yaml:"added"`
	Updated  []string         `json:"updated" yaml:"updated"`
	Removed  []string         `json:"removed" yaml:"removed"`
	Errors   []ReconcileError `json:"errors,omitempty" yaml:"errors,omitempty"`
	Duration time.Duration    `json:"duration" yaml:"duration"`
	Summary  map[string]int   `json:"summary" yaml:"summary"`
	DryRun   bool             `json:"dry_run" yaml:"dry_run"`
}

// ReconcileError represents an error during reconciliation
type ReconcileError struct {
	Type     string `json:"type" yaml:"type"`
	Resource string `json:"resource" yaml:"resource"`
	Message  string `json:"message" yaml:"message"`
	Fatal    bool   `json:"fatal" yaml:"fatal"`
}

// AuthProvider represents an authentication provider configuration
type AuthProvider struct {
	Name         string            `json:"name" yaml:"name"`
	Type         string            `json:"type" yaml:"type"` // authentik, oauth2, saml
	Endpoint     string            `json:"endpoint" yaml:"endpoint"`
	ClientID     string            `json:"client_id" yaml:"client_id"`
	ClientSecret string            `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`
	Scopes       []string          `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	RedirectURI  string            `json:"redirect_uri,omitempty" yaml:"redirect_uri,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Enabled      bool              `json:"enabled" yaml:"enabled"`
	Default      bool              `json:"default" yaml:"default"`
}

// DNSProvider represents DNS provider configuration
type DNSProvider struct {
	Name     string            `json:"name" yaml:"name"`
	Type     string            `json:"type" yaml:"type"` // hetzner, cloudflare, route53, etc
	APIToken string            `json:"api_token,omitempty" yaml:"api_token,omitempty"`
	Config   map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
	Zones    []string          `json:"zones,omitempty" yaml:"zones,omitempty"`
	Default  bool              `json:"default" yaml:"default"`
}

// BackendType represents the type of reverse proxy backend
type BackendType string

const (
	BackendTypeCaddy   BackendType = "caddy"
	BackendTypeNginx   BackendType = "nginx"
	BackendTypeHAProxy BackendType = "haproxy"
	BackendTypeTraefik BackendType = "traefik"
)

// StateBackendType represents the type of state storage backend
type StateBackendType string

const (
	StateBackendFile   StateBackendType = "file"
	StateBackendConsul StateBackendType = "consul"
	StateBackendEtcd   StateBackendType = "etcd"
	StateBackendVault  StateBackendType = "vault"
)

// RouteState represents the state values for routes
const (
	RouteStateActive   = "active"
	RouteStateInactive = "inactive"
	RouteStateError    = "error"
	RouteStatePending  = "pending"
)

// RouteHealth represents the health status values for routes
const (
	RouteHealthHealthy   = "healthy"
	RouteHealthUnhealthy = "unhealthy"
	RouteHealthUnknown   = "unknown"
	RouteHealthDegraded  = "degraded"
)

// LogLevel represents log level values
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// ValidationResult represents the result of route validation
type ValidationResult struct {
	Valid    bool              `json:"valid" yaml:"valid"`
	Errors   []ValidationError `json:"errors,omitempty" yaml:"errors,omitempty"`
	Warnings []ValidationError `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// ValidationError represents a validation error or warning
type ValidationError struct {
	Field   string `json:"field" yaml:"field"`
	Message string `json:"message" yaml:"message"`
	Code    string `json:"code,omitempty" yaml:"code,omitempty"`
}

// ParseURL is a helper function to safely parse URLs
func (u *Upstream) ParsedURL() (*url.URL, error) {
	return url.Parse(u.URL)
}

// IsHealthy returns true if the route is currently healthy
func (r *Route) IsHealthy() bool {
	return r.Status.Health == RouteHealthHealthy
}

// IsActive returns true if the route is currently active
func (r *Route) IsActive() bool {
	return r.Status.State == RouteStateActive
}

// HasAuth returns true if the route has authentication configured
func (r *Route) HasAuth() bool {
	return r.AuthPolicy != nil && r.AuthPolicy.Provider != ""
}

// RequiresMFA returns true if the route requires MFA
func (r *Route) RequiresMFA() bool {
	return r.HasAuth() && r.AuthPolicy.RequireMFA
}

// GetEffectiveTimeout returns the effective timeout for the route
func (r *Route) GetEffectiveTimeout() time.Duration {
	if r.Upstream.Timeout > 0 {
		return r.Upstream.Timeout
	}
	return 30 * time.Second // Default timeout
}

// GetEffectiveHealthCheckInterval returns the effective health check interval
func (r *Route) GetEffectiveHealthCheckInterval() time.Duration {
	if r.HealthCheck != nil && r.HealthCheck.Interval > 0 {
		return r.HealthCheck.Interval
	}
	return 30 * time.Second // Default interval
}

// State represents the complete state of all Hecate resources
type State struct {
	Routes        map[string]*Route        `json:"routes" yaml:"routes"`
	Upstreams     map[string]*Upstream     `json:"upstreams" yaml:"upstreams"`
	AuthPolicies  map[string]*AuthPolicy   `json:"auth_policies" yaml:"auth_policies"`
	AuthProviders map[string]*AuthProvider `json:"auth_providers" yaml:"auth_providers"`
	DNSProviders  map[string]*DNSProvider  `json:"dns_providers" yaml:"dns_providers"`
	Version       string                   `json:"version" yaml:"version"`
	LastUpdated   time.Time                `json:"last_updated" yaml:"last_updated"`
	Fingerprint   string                   `json:"fingerprint" yaml:"fingerprint"`
}

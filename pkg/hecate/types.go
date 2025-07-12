// pkg/hecate/types.go
package hecate

import (
	"time"
)

// Load balancer strategies
const (
	LoadBalancerRoundRobin = "round_robin"
	LoadBalancerLeastConn  = "least_conn"
	LoadBalancerIPHash     = "ip_hash"
)

// Auth providers
const (
	AuthProviderAuthentik = "authentik"
	AuthProviderOAuth2    = "oauth2"
	AuthProviderSAML      = "saml"
	AuthProviderLDAP      = "ldap"
	AuthProviderBasic     = "basic"
)

// Secret rotation strategies
const (
	StrategyDualSecret = "dual-secret"
	StrategyImmediate  = "immediate"
)

// Reconciliation components
const (
	ComponentAll       = "all"
	ComponentRoutes    = "routes"
	ComponentAuth      = "auth"
	ComponentUpstreams = "upstreams"
)

// TLS minimum versions
const (
	TLSVersion12 = "1.2"
	TLSVersion13 = "1.3"
)

// Route represents a reverse proxy route configuration
type Route struct {
	Domain      string            `json:"domain" yaml:"domain"`
	Upstream    string            `json:"upstream" yaml:"upstream"`
	AuthPolicy  string            `json:"auth_policy,omitempty" yaml:"auth_policy,omitempty"`
	Middleware  []string          `json:"middleware,omitempty" yaml:"middleware,omitempty"`
	Headers     map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	TLS         *TLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
	HealthCheck *HealthCheck      `json:"health_check,omitempty" yaml:"health_check,omitempty"`
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at"`
}

// RouteStatus represents the health status of a route
type RouteStatus struct {
	Domain       string        `json:"domain"`
	Healthy      bool          `json:"healthy"`
	LastCheck    time.Time     `json:"last_check"`
	ResponseTime time.Duration `json:"response_time"`
	ErrorMessage string        `json:"error_message,omitempty"`
}

// Upstream represents an upstream server configuration
type Upstream struct {
	Name         string        `json:"name" yaml:"name"`
	Servers      []string      `json:"servers" yaml:"servers"`
	LoadBalancer string        `json:"load_balancer" yaml:"load_balancer"`
	HealthCheck  *HealthCheck  `json:"health_check,omitempty" yaml:"health_check,omitempty"`
	Timeout      time.Duration `json:"timeout" yaml:"timeout"`
	CreatedAt    time.Time     `json:"created_at" yaml:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at" yaml:"updated_at"`
}

// TLSConfig represents TLS/SSL configuration
type TLSConfig struct {
	CertFile     string        `json:"cert_file,omitempty" yaml:"cert_file,omitempty"`
	KeyFile      string        `json:"key_file,omitempty" yaml:"key_file,omitempty"`
	AutoHTTPS    bool          `json:"auto_https" yaml:"auto_https"`
	ForceHTTPS   bool          `json:"force_https" yaml:"force_https"`
	SNI          []string      `json:"sni,omitempty" yaml:"sni,omitempty"`
	MinVersion   string        `json:"min_version,omitempty" yaml:"min_version,omitempty"`
	Ciphers      []string      `json:"ciphers,omitempty" yaml:"ciphers,omitempty"`
	DNSChallenge *DNSChallenge `json:"dns_challenge,omitempty" yaml:"dns_challenge,omitempty"`
}

// DNSChallenge represents DNS challenge configuration for ACME
type DNSChallenge struct {
	Provider string            `json:"provider" yaml:"provider"`
	Config   map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
}

// HealthCheck represents health check configuration
type HealthCheck struct {
	Path               string        `json:"path" yaml:"path"`
	Interval           time.Duration `json:"interval" yaml:"interval"`
	Timeout            time.Duration `json:"timeout" yaml:"timeout"`
	UnhealthyThreshold int           `json:"unhealthy_threshold" yaml:"unhealthy_threshold"`
	HealthyThreshold   int           `json:"healthy_threshold" yaml:"healthy_threshold"`
	ExpectedStatus     []int         `json:"expected_status,omitempty" yaml:"expected_status,omitempty"`
	ExpectedBody       string        `json:"expected_body,omitempty" yaml:"expected_body,omitempty"`
}

// AuthPolicy represents an authentication policy
type AuthPolicy struct {
	Name       string            `json:"name" yaml:"name"`
	Provider   string            `json:"provider" yaml:"provider"`
	Flow       string            `json:"flow" yaml:"flow"`
	Groups     []string          `json:"groups,omitempty" yaml:"groups,omitempty"`
	RequireMFA bool              `json:"require_mfa" yaml:"require_mfa"`
	Metadata   map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	CreatedAt  time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at" yaml:"updated_at"`
}

// State represents the complete Hecate configuration state
type State struct {
	Routes       map[string]*Route      `json:"routes" yaml:"routes"`
	Upstreams    map[string]*Upstream   `json:"upstreams" yaml:"upstreams"`
	AuthPolicies map[string]*AuthPolicy `json:"auth_policies" yaml:"auth_policies"`
	Version      string                 `json:"version" yaml:"version"`
	LastUpdated  time.Time              `json:"last_updated" yaml:"last_updated"`
}

// HecateConfig represents the main Hecate configuration
type HecateConfig struct {
	// General settings
	Name        string `json:"name" yaml:"name"`
	Environment string `json:"environment" yaml:"environment"`
	Datacenter  string `json:"datacenter" yaml:"datacenter"`
	Domain      string `json:"domain" yaml:"domain"`

	// Caddy configuration
	Caddy CaddyConfig `json:"caddy" yaml:"caddy"`

	// Authentik configuration
	Authentik AuthentikConfig `json:"authentik" yaml:"authentik"`

	// Hetzner DNS configuration
	HetznerDNS HetznerDNSConfig `json:"hetzner_dns" yaml:"hetzner_dns"`

	// Temporal configuration
	Temporal TemporalConfig `json:"temporal" yaml:"temporal"`

	// Monitoring configuration
	Monitoring MonitoringConfig `json:"monitoring" yaml:"monitoring"`

	// API configuration
	API APIConfig `json:"api" yaml:"api"`
}

// CaddyConfig represents Caddy-specific configuration
type CaddyConfig struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	AdminAPI      string `json:"admin_api" yaml:"admin_api"`
	ConfigPath    string `json:"config_path" yaml:"config_path"`
	LogLevel      string `json:"log_level" yaml:"log_level"`
	HTTPPort      int    `json:"http_port" yaml:"http_port"`
	HTTPSPort     int    `json:"https_port" yaml:"https_port"`
	EnableMetrics bool   `json:"enable_metrics" yaml:"enable_metrics"`
	MetricsPort   int    `json:"metrics_port" yaml:"metrics_port"`
}

// AuthentikConfig represents Authentik integration configuration
type AuthentikConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	URL      string `json:"url" yaml:"url"`
	Token    string `json:"token" yaml:"token"`
	Provider string `json:"provider" yaml:"provider"`
	Flow     string `json:"flow" yaml:"flow"`
}

// HetznerDNSConfig represents Hetzner DNS configuration
type HetznerDNSConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	APIKey  string `json:"api_key" yaml:"api_key"`
	Zone    string `json:"zone" yaml:"zone"`
	TTL     int    `json:"ttl" yaml:"ttl"`
}

// TemporalConfig represents Temporal workflow engine configuration
type TemporalConfig struct {
	Enabled       bool   `json:"enabled" yaml:"enabled"`
	HostPort      string `json:"host_port" yaml:"host_port"`
	Namespace     string `json:"namespace" yaml:"namespace"`
	TaskQueue     string `json:"task_queue" yaml:"task_queue"`
	WorkerCount   int    `json:"worker_count" yaml:"worker_count"`
	RetentionDays int    `json:"retention_days" yaml:"retention_days"`
}

// MonitoringConfig represents monitoring and alerting configuration
type MonitoringConfig struct {
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	PrometheusURL   string `json:"prometheus_url" yaml:"prometheus_url"`
	GrafanaURL      string `json:"grafana_url" yaml:"grafana_url"`
	AlertmanagerURL string `json:"alertmanager_url" yaml:"alertmanager_url"`
	EnableTracing   bool   `json:"enable_tracing" yaml:"enable_tracing"`
	JaegerURL       string `json:"jaeger_url" yaml:"jaeger_url"`
}

// APIConfig represents Hecate API server configuration
type APIConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	Port         int    `json:"port" yaml:"port"`
	TLSCertFile  string `json:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile   string `json:"tls_key_file" yaml:"tls_key_file"`
	AuthEnabled  bool   `json:"auth_enabled" yaml:"auth_enabled"`
	APIKeyHeader string `json:"api_key_header" yaml:"api_key_header"`
}

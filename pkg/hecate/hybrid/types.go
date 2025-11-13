// pkg/hecate/hybrid/types.go

package hybrid

import (
	"fmt"
	"time"
)

// HybridLink represents a secure connection between frontend and backend DCs
type HybridLink struct {
	ID             string           `json:"id" yaml:"id"`
	FrontendDC     string           `json:"frontend_dc" yaml:"frontend_dc"`
	BackendDC      string           `json:"backend_dc" yaml:"backend_dc"`
	ConnectionType string           `json:"connection_type" yaml:"connection_type"` // mesh-gateway, wireguard, cloudflare
	Status         ConnectionStatus `json:"status" yaml:"status"`
	Security       SecurityConfig   `json:"security" yaml:"security"`
	MeshGateway    *MeshGatewayDef  `json:"mesh_gateway,omitempty" yaml:"mesh_gateway,omitempty"`
	WireGuard      *WireGuardDef    `json:"wireguard,omitempty" yaml:"wireguard,omitempty"`
	CloudflareLink *CloudflareDef   `json:"cloudflare,omitempty" yaml:"cloudflare,omitempty"`
	Created        time.Time        `json:"created" yaml:"created"`
	Updated        time.Time        `json:"updated" yaml:"updated"`
}

// Backend represents a locally-hosted backend service
type Backend struct {
	ID             string           `json:"id" yaml:"id"`
	Name           string           `json:"name" yaml:"name"`
	LocalAddress   string           `json:"local_address" yaml:"local_address"` // Internal IP:port
	PublicDomain   string           `json:"public_domain" yaml:"public_domain"` // External domain
	ConsulService  ConsulServiceDef `json:"consul_service" yaml:"consul_service"`
	HealthCheck    HealthCheckDef   `json:"health_check" yaml:"health_check"`
	Tunnel         *TunnelConfig    `json:"tunnel,omitempty" yaml:"tunnel,omitempty"`
	Authentication *AuthConfig      `json:"auth,omitempty" yaml:"auth,omitempty"`
	DNSName        string           `json:"dns_name,omitempty" yaml:"dns_name,omitempty"`
	Port           int              `json:"port" yaml:"port"`
	FrontendDC     string           `json:"frontend_dc" yaml:"frontend_dc"`
	BackendDC      string           `json:"backend_dc" yaml:"backend_dc"`
	RequiredPorts  []int            `json:"required_ports,omitempty" yaml:"required_ports,omitempty"`
	Created        time.Time        `json:"created" yaml:"created"`
	Updated        time.Time        `json:"updated" yaml:"updated"`
}

// TunnelConfig defines the tunnel configuration for hybrid connections
type TunnelConfig struct {
	Type             string          `json:"type" yaml:"type"` // consul-connect, wireguard, cloudflare
	MeshGateway      *MeshGatewayDef `json:"mesh_gateway,omitempty" yaml:"mesh_gateway,omitempty"`
	WireGuard        *WireGuardDef   `json:"wireguard,omitempty" yaml:"wireguard,omitempty"`
	CloudflareTunnel *CloudflareDef  `json:"cloudflare,omitempty" yaml:"cloudflare,omitempty"`
	Status           TunnelStatus    `json:"status" yaml:"status"`
	Created          time.Time       `json:"created" yaml:"created"`
	Updated          time.Time       `json:"updated" yaml:"updated"`
}

// ConnectionStatus tracks the health and status of hybrid connections
type ConnectionStatus struct {
	Connected    bool             `json:"connected" yaml:"connected"`
	LastSeen     time.Time        `json:"last_seen" yaml:"last_seen"`
	Latency      time.Duration    `json:"latency" yaml:"latency"`
	HealthChecks map[string]bool  `json:"health_checks" yaml:"health_checks"`
	Errors       []string         `json:"errors" yaml:"errors"`
	Bandwidth    BandwidthMetrics `json:"bandwidth" yaml:"bandwidth"`
	LastError    string           `json:"last_error,omitempty" yaml:"last_error,omitempty"`
	ErrorCount   int              `json:"error_count" yaml:"error_count"`
}

// SecurityConfig defines security settings for hybrid connections
type SecurityConfig struct {
	MTLS            bool              `json:"mtls" yaml:"mtls"`
	Encryption      string            `json:"encryption" yaml:"encryption"`
	CertificateCA   string            `json:"certificate_ca,omitempty" yaml:"certificate_ca,omitempty"`
	CertificatePath string            `json:"certificate_path,omitempty" yaml:"certificate_path,omitempty"`
	KeyPath         string            `json:"key_path,omitempty" yaml:"key_path,omitempty"`
	RotationPeriod  time.Duration     `json:"rotation_period" yaml:"rotation_period"`
	Intentions      []ConsulIntention `json:"intentions,omitempty" yaml:"intentions,omitempty"`
}

// MeshGatewayDef defines Consul mesh gateway configuration
type MeshGatewayDef struct {
	Mode              string `json:"mode" yaml:"mode"` // local, remote, none
	Port              int    `json:"port" yaml:"port"`
	FrontendAddress   string `json:"frontend_address" yaml:"frontend_address"` // Public IP:port
	BackendMode       string `json:"backend_mode" yaml:"backend_mode"`
	WANFederation     bool   `json:"wan_federation" yaml:"wan_federation"`
	PrimaryDatacenter string `json:"primary_datacenter" yaml:"primary_datacenter"`
}

// WireGuardDef defines WireGuard VPN configuration
type WireGuardDef struct {
	InterfaceName       string          `json:"interface_name" yaml:"interface_name"`
	ListenPort          int             `json:"listen_port" yaml:"listen_port"`
	PrivateKey          string          `json:"private_key" yaml:"private_key"`
	PublicKey           string          `json:"public_key" yaml:"public_key"`
	AllowedIPs          []string        `json:"allowed_ips" yaml:"allowed_ips"`
	Endpoint            string          `json:"endpoint" yaml:"endpoint"`
	PersistentKeepalive int             `json:"persistent_keepalive" yaml:"persistent_keepalive"`
	Peers               []WireGuardPeer `json:"peers" yaml:"peers"`
	DNS                 []string        `json:"dns,omitempty" yaml:"dns,omitempty"`
}

// WireGuardPeer represents a WireGuard peer configuration
type WireGuardPeer struct {
	PublicKey           string   `json:"public_key" yaml:"public_key"`
	AllowedIPs          []string `json:"allowed_ips" yaml:"allowed_ips"`
	Endpoint            string   `json:"endpoint" yaml:"endpoint"`
	PersistentKeepalive int      `json:"persistent_keepalive" yaml:"persistent_keepalive"`
}

// CloudflareDef defines Cloudflare Tunnel configuration
type CloudflareDef struct {
	TunnelID     string                `json:"tunnel_id" yaml:"tunnel_id"`
	TunnelName   string                `json:"tunnel_name" yaml:"tunnel_name"`
	TunnelSecret string                `json:"tunnel_secret" yaml:"tunnel_secret"`
	AccountID    string                `json:"account_id" yaml:"account_id"`
	Ingresses    []CloudflareIngress   `json:"ingresses" yaml:"ingresses"`
	Credentials  CloudflareCredentials `json:"credentials" yaml:"credentials"`
}

// CloudflareIngress defines ingress rules for Cloudflare Tunnel
type CloudflareIngress struct {
	Hostname string `json:"hostname" yaml:"hostname"`
	Service  string `json:"service" yaml:"service"`
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
}

// CloudflareCredentials stores Cloudflare API credentials
type CloudflareCredentials struct {
	APIKey   string `json:"api_key" yaml:"api_key"`
	Email    string `json:"email" yaml:"email"`
	ZoneID   string `json:"zone_id" yaml:"zone_id"`
	APIToken string `json:"api_token" yaml:"api_token"`
}

// ConsulServiceDef defines Consul service registration
type ConsulServiceDef struct {
	Name        string            `json:"name" yaml:"name"`
	Port        int               `json:"port" yaml:"port"`
	Tags        []string          `json:"tags" yaml:"tags"`
	Meta        map[string]string `json:"meta" yaml:"meta"`
	Connect     bool              `json:"connect" yaml:"connect"`
	MeshGateway bool              `json:"mesh_gateway" yaml:"mesh_gateway"`
}

// HealthCheckDef defines health check configuration
type HealthCheckDef struct {
	HTTP                   string        `json:"http,omitempty" yaml:"http,omitempty"`
	TCP                    string        `json:"tcp,omitempty" yaml:"tcp,omitempty"`
	Script                 string        `json:"script,omitempty" yaml:"script,omitempty"`
	Interval               time.Duration `json:"interval" yaml:"interval"`
	Timeout                time.Duration `json:"timeout" yaml:"timeout"`
	DeregisterAfter        time.Duration `json:"deregister_after" yaml:"deregister_after"`
	FailuresBeforeCritical int           `json:"failures_before_critical" yaml:"failures_before_critical"`
}

// AuthConfig defines authentication configuration
type AuthConfig struct {
	Policy     *AuthPolicy `json:"policy,omitempty" yaml:"policy,omitempty"`
	RequireSSL bool        `json:"require_ssl" yaml:"require_ssl"`
	JWTSecret  string      `json:"jwt_secret,omitempty" yaml:"jwt_secret,omitempty"`
}

// AuthPolicy represents authentication policy
type AuthPolicy struct {
	Name       string   `json:"name" yaml:"name"`
	Provider   string   `json:"provider" yaml:"provider"`
	Groups     []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	RequireMFA bool     `json:"require_mfa" yaml:"require_mfa"`
}

// ConsulIntention defines Consul service intentions
type ConsulIntention struct {
	SourceName      string            `json:"source_name" yaml:"source_name"`
	DestinationName string            `json:"destination_name" yaml:"destination_name"`
	Action          string            `json:"action" yaml:"action"` // allow, deny
	Meta            map[string]string `json:"meta,omitempty" yaml:"meta,omitempty"`
}

// TunnelStatus represents tunnel connection status
type TunnelStatus struct {
	State       string    `json:"state" yaml:"state"` // connected, connecting, disconnected, error
	LastChecked time.Time `json:"last_checked" yaml:"last_checked"`
	BytesIn     int64     `json:"bytes_in" yaml:"bytes_in"`
	BytesOut    int64     `json:"bytes_out" yaml:"bytes_out"`
	PacketsIn   int64     `json:"packets_in" yaml:"packets_in"`
	PacketsOut  int64     `json:"packets_out" yaml:"packets_out"`
	Errors      []string  `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// BandwidthMetrics tracks bandwidth usage
type BandwidthMetrics struct {
	BytesPerSecond   int64 `json:"bytes_per_second" yaml:"bytes_per_second"`
	PacketsPerSecond int64 `json:"packets_per_second" yaml:"packets_per_second"`
	PeakBandwidth    int64 `json:"peak_bandwidth" yaml:"peak_bandwidth"`
	AverageBandwidth int64 `json:"average_bandwidth" yaml:"average_bandwidth"`
}

// DiagnosticReport provides comprehensive connection diagnostics
type DiagnosticReport struct {
	Timestamp time.Time              `json:"timestamp" yaml:"timestamp"`
	Backend   string                 `json:"backend" yaml:"backend"`
	Checks    map[string]CheckResult `json:"checks" yaml:"checks"`
	Summary   DiagnosticSummary      `json:"summary" yaml:"summary"`
}

// CheckResult represents the result of a diagnostic check
type CheckResult struct {
	Status   string        `json:"status" yaml:"status"` // pass, fail, warning
	Message  string        `json:"message" yaml:"message"`
	Duration time.Duration `json:"duration" yaml:"duration"`
	Details  interface{}   `json:"details,omitempty" yaml:"details,omitempty"`
	Error    string        `json:"error,omitempty" yaml:"error,omitempty"`
}

// DiagnosticSummary provides an overview of diagnostic results
type DiagnosticSummary struct {
	TotalChecks   int    `json:"total_checks" yaml:"total_checks"`
	PassedChecks  int    `json:"passed_checks" yaml:"passed_checks"`
	FailedChecks  int    `json:"failed_checks" yaml:"failed_checks"`
	Warnings      int    `json:"warnings" yaml:"warnings"`
	OverallStatus string `json:"overall_status" yaml:"overall_status"`
}

// CacheConfig defines caching configuration for optimization
type CacheConfig struct {
	TTL                  time.Duration `json:"ttl" yaml:"ttl"`
	MaxSize              int64         `json:"max_size" yaml:"max_size"`
	StaleWhileRevalidate time.Duration `json:"stale_while_revalidate" yaml:"stale_while_revalidate"`
}

// Constants for various types
const (
	// Connection types
	ConnectionTypeConsulConnect = "consul-connect"
	ConnectionTypeWireGuard     = "wireguard"
	ConnectionTypeCloudflare    = "cloudflare"
	ConnectionTypeAuto          = "auto"

	// Tunnel states
	TunnelStateConnected    = "connected"
	TunnelStateConnecting   = "connecting"
	TunnelStateDisconnected = "disconnected"
	TunnelStateError        = "error"

	// Check statuses
	CheckStatusPass    = "pass"
	CheckStatusFail    = "fail"
	CheckStatusWarning = "warning"

	// Mesh gateway modes
	MeshGatewayModeLocal  = "local"
	MeshGatewayModeRemote = "remote"
	MeshGatewayModeNone   = "none"

	// Intention actions
	IntentionActionAllow = "allow"
	IntentionActionDeny  = "deny"
)

// Helper functions

// GenerateBackendID generates a unique ID for a backend service
func GenerateBackendID(name string) string {
	return fmt.Sprintf("backend-%s-%d", name, time.Now().Unix())
}

// GenerateHybridLinkID generates a unique ID for a hybrid link
func GenerateHybridLinkID(frontendDC, backendDC string) string {
	return fmt.Sprintf("hybrid-link-%s-%s-%d", frontendDC, backendDC, time.Now().Unix())
}

// IsHealthy returns true if the connection is healthy
func (cs *ConnectionStatus) IsHealthy() bool {
	return cs.Connected && len(cs.Errors) == 0
}

// GetOverallHealthStatus returns the overall health status
func (cs *ConnectionStatus) GetOverallHealthStatus() string {
	if cs.IsHealthy() {
		return "healthy"
	}
	if cs.Connected {
		return "degraded"
	}
	return "unhealthy"
}

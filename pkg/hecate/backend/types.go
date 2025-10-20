// pkg/hecate/backend/types.go

package backend

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/hybrid"
)

// BackendSummary provides a summary view of a backend for list operations
type BackendSummary struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	PublicDomain string    `json:"public_domain"`
	LocalAddress string    `json:"local_address"`
	Status       string    `json:"status"`
	Datacenter   string    `json:"datacenter"`
	Created      time.Time `json:"created"`
	LastSeen     time.Time `json:"last_seen"`
}

// BackendDetails provides detailed information about a backend
type BackendDetails struct {
	ID             string                  `json:"id"`
	Name           string                  `json:"name"`
	PublicDomain   string                  `json:"public_domain"`
	LocalAddress   string                  `json:"local_address"`
	FrontendDC     string                  `json:"frontend_dc"`
	BackendDC      string                  `json:"backend_dc"`
	ConnectionType string                  `json:"connection_type"`
	Status         string                  `json:"status"`
	Tunnel         *hybrid.TunnelConfig    `json:"tunnel,omitempty"`
	Security       *hybrid.SecurityConfig  `json:"security,omitempty"`
	HealthCheck    *hybrid.HealthCheckDef  `json:"health_check,omitempty"`
	Metrics        *BackendMetrics         `json:"metrics,omitempty"`
	Created        time.Time               `json:"created"`
	Updated        time.Time               `json:"updated"`
}

// BackendMetrics contains performance metrics for a backend
type BackendMetrics struct {
	Latency       time.Duration `json:"latency"`
	Throughput    int64         `json:"throughput"`
	ErrorRate     float64       `json:"error_rate"`
	UptimePercent float64       `json:"uptime_percent"`
	LastHealthy   time.Time     `json:"last_healthy"`
}

// BackendDiagnostics contains comprehensive diagnostic information
type BackendDiagnostics struct {
	BackendID       string            `json:"backend_id"`
	Connectivity    *ConnectivityTest `json:"connectivity"`
	DNSResolution   *DNSTest          `json:"dns_resolution"`
	Certificates    *CertificateTest  `json:"certificates"`
	TunnelStatus    *TunnelTest       `json:"tunnel_status"`
	HealthChecks    *HealthTest       `json:"health_checks"`
	Performance     *PerformanceTest  `json:"performance"`
	Recommendations []string          `json:"recommendations"`
	Timestamp       time.Time         `json:"timestamp"`
}

// ConnectivityTest contains connectivity test results
type ConnectivityTest struct {
	LocalReachable    bool          `json:"local_reachable"`
	FrontendReachable bool          `json:"frontend_reachable"`
	TunnelActive      bool          `json:"tunnel_active"`
	Latency           time.Duration `json:"latency"`
	Error             string        `json:"error,omitempty"`
}

// DNSTest contains DNS resolution test results
type DNSTest struct {
	PublicDomainResolved bool          `json:"public_domain_resolved"`
	LocalDNSWorking      bool          `json:"local_dns_working"`
	ResolutionTime       time.Duration `json:"resolution_time"`
	Error                string        `json:"error,omitempty"`
}

// CertificateTest contains certificate validation test results
type CertificateTest struct {
	CertificateValid bool      `json:"certificate_valid"`
	CAValid          bool      `json:"ca_valid"`
	ExpiresAt        time.Time `json:"expires_at"`
	DaysUntilExpiry  int       `json:"days_until_expiry"`
	Error            string    `json:"error,omitempty"`
}

// TunnelTest contains tunnel status test results
type TunnelTest struct {
	TunnelType   string `json:"tunnel_type"`
	TunnelActive bool   `json:"tunnel_active"`
	PeerCount    int    `json:"peer_count"`
	DataTransfer int64  `json:"data_transfer"`
	Error        string `json:"error,omitempty"`
}

// HealthTest contains health check test results
type HealthTest struct {
	HealthEndpointReachable bool          `json:"health_endpoint_reachable"`
	HealthCheckPassing      bool          `json:"health_check_passing"`
	ResponseTime            time.Duration `json:"response_time"`
	StatusCode              int           `json:"status_code"`
	Error                   string        `json:"error,omitempty"`
}

// PerformanceTest contains performance test results
type PerformanceTest struct {
	AverageLatency  time.Duration `json:"average_latency"`
	P95Latency      time.Duration `json:"p95_latency"`
	Throughput      int64         `json:"throughput"`
	ErrorRate       float64       `json:"error_rate"`
	Recommendations []string      `json:"recommendations"`
}
